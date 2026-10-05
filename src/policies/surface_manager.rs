use crate::policies::policy_definitions::FileSystemPolicyDefinitionStore;
use crate::policies::{CircuitBreaker, CompiledMcpToolGating, OpaEngine, RateLimiter};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Surface-level policy manager: handles surface OPA, rate limiting, and circuit breakers per surface.
pub struct SurfacePolicyManager {
    /// Pre-compiled OPA engine templates per surface (keyed by config_id).
    /// Uses std::sync::RwLock because reads are sub-microsecond (clone the template)
    /// and writes only happen during surface config updates.
    opa_engines: std::sync::RwLock<HashMap<String, OpaEngine>>,

    /// Rate limiters per surface (keyed by config_id)
    rate_limiters: Arc<RwLock<HashMap<String, Arc<RateLimiter>>>>,

    /// Circuit breakers per surface (keyed by config_id)
    circuit_breakers: Arc<RwLock<HashMap<String, Arc<CircuitBreaker>>>>,

    /// Compiled MCP Tool Gating per surface. Keyed by `config_id` for the base
    /// surface and `variant:{config_id}:{alias}` for each variant that
    /// overrides gating. Built during surface config updates; cloned-Arc read
    /// per request so runtime pays only one OPA eval per gate.
    mcp_tool_gating: std::sync::RwLock<HashMap<String, Arc<CompiledMcpToolGating>>>,

    /// Policy definition store for resolving policy text from `opa_policy_definition_id`
    policy_definition_store: std::sync::RwLock<Option<Arc<FileSystemPolicyDefinitionStore>>>,
}

impl SurfacePolicyManager {
    pub fn new() -> Self {
        Self {
            opa_engines: std::sync::RwLock::new(HashMap::new()),
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            mcp_tool_gating: std::sync::RwLock::new(HashMap::new()),
            policy_definition_store: std::sync::RwLock::new(None),
        }
    }

    /// Set (or replace) the policy definition store used to resolve policies at compile time
    pub fn set_policy_definition_store(
        &self,
        store: Arc<FileSystemPolicyDefinitionStore>,
    ) {
        *self
            .policy_definition_store
            .write()
            .expect("policy_definition_store lock poisoned") = Some(store);
    }

    /// Snapshot of the policy definition store, if any. Used by inbound
    /// MCP tool-policy evaluation to resolve `policy_definition_id`s to
    /// Rego text at request time.
    pub fn policy_definition_store(&self) -> Option<Arc<FileSystemPolicyDefinitionStore>> {
        self.policy_definition_store
            .read()
            .expect("policy_definition_store lock poisoned")
            .clone()
    }

    /// Name, enforced version and content hash for a surface policy decision,
    /// from one store lookup. The name is the definition's operator-assigned
    /// name, its id when the definition is unknown, or the Rego package
    /// (`surface.policy`) when none is attached; version and hash are `None`
    /// unless the definition is known, so a decision backed by the built-in
    /// allow-all default carries no revision evidence.
    pub async fn resolve_policy_decision_evidence(
        &self,
        def_id: Option<&str>,
    ) -> (String, Option<u32>, Option<String>) {
        let Some(id) = def_id else {
            return (super::SURFACE_POLICY_PACKAGE.to_string(), None, None);
        };
        let attestation = self
            .resolve_policy_attestation(Some(id))
            .await;
        (
            attestation
                .name
                .unwrap_or_else(|| id.to_string()),
            attestation.version,
            attestation.content_hash,
        )
    }

    /// Name, enforced version and content hash of a stored policy definition,
    /// for attesting a decision it made. Empty when the definition is unknown.
    pub async fn resolve_policy_attestation(
        &self,
        def_id: Option<&str>,
    ) -> super::PolicyAttestation {
        if let Some(id) = def_id
            && let Some(store) = self.policy_definition_store()
            && let Some(def) = store.get(id).await
        {
            return super::PolicyAttestation::of(&def);
        }
        super::PolicyAttestation::default()
    }

    /// Returns true when a compiled OPA engine exists for the given surface
    pub fn has_policy(
        &self,
        channel_id: &str,
    ) -> bool {
        self.opa_engines
            .read()
            .expect("opa_engines lock poisoned")
            .contains_key(channel_id)
    }

    /// Returns true when a compiled OPA engine exists for the given
    /// surface/variant pair. Prefers the variant-scoped engine; falls back
    /// to the surface-scoped engine when the variant has no override.
    pub fn has_policy_for_variant(
        &self,
        channel_id: &str,
        variant_alias: Option<&str>,
    ) -> bool {
        let engines = self
            .opa_engines
            .read()
            .expect("opa_engines lock poisoned");
        if let Some(alias) = variant_alias
            && engines.contains_key(&format!("variant:{}:{}", channel_id, alias))
        {
            return true;
        }
        engines.contains_key(channel_id)
    }

    /// Initialize or update policy for a surface
    pub async fn update_channel_policy(
        &self,
        surface: &crate::config::agent_surface::AgentSurface,
    ) -> Result<(), String> {
        let _access_change = crate::mcp::subscriptions::AccessChange::begin();
        let config_id = surface
            .config_id()
            .map(|s| s.to_string())
            .ok_or_else(|| "Channel missing config_id".to_string())?;

        // Fail closed on any error from the update — a failed recompile *or* a
        // failed policy-definition resolve. `evaluate_policy_decision_for_variant`
        // prefers a surface's variant/inbound/transit engine key over its base
        // key, so any sibling engine left installed could still serve a prior,
        // more-permissive policy. Evict the whole key set for this surface on error
        // so it denies until a clean recompile lands. This deliberately denies on a
        // dangling/unresolvable definition too, rather than serving a stale engine.
        let result = self
            .update_channel_policy_inner(surface, &config_id)
            .await;
        if result.is_err() {
            self.evict_all_opa_engines_for_config(&config_id);
        }
        result
    }

    /// Evict every OPA engine keyed to this surface's `config_id` — the base
    /// key plus all `outbound:`, `inbound:`, `inbound:variant:`, `variant:`,
    /// `transit:` and `response:transit:` keys. Shared `response:{def_id}`
    /// engines are intentionally left in place (they can be shared across
    /// surfaces). Used to fail closed when a (re)compile fails.
    fn evict_all_opa_engines_for_config(
        &self,
        config_id: &str,
    ) {
        let mut engines = self
            .opa_engines
            .write()
            .expect("opa_engines lock poisoned");
        engines.remove(config_id);
        engines.remove(&format!("outbound:{}", config_id));
        engines.remove(&format!("inbound:{}", config_id));
        let inbound_variant_prefix = format!("inbound:variant:{}:", config_id);
        let variant_prefix = format!("variant:{}:", config_id);
        let transit_prefix = format!("transit:{}:", config_id);
        let transit_resp_prefix = format!("response:transit:{}:", config_id);
        engines.retain(|k, _| {
            !k.starts_with(&inbound_variant_prefix)
                && !k.starts_with(&variant_prefix)
                && !k.starts_with(&transit_prefix)
                && !k.starts_with(&transit_resp_prefix)
        });
    }

    async fn update_channel_policy_inner(
        &self,
        surface: &crate::config::agent_surface::AgentSurface,
        config_id: &str,
    ) -> Result<(), String> {
        let config_id = config_id.to_string();
        let config_id = &config_id;

        // Resolve the effective surface so that variant-level overrides
        // (opa_policy_definition_id, rate_limit, circuit_breaker) are visible here.
        let effective = surface
            .resolve_variant(None)
            .unwrap_or_else(|_| surface.clone());

        // Handle OPA policy — resolve text from the definition store, compile synchronously
        if effective.opa_enabled() {
            if let Some(def_id) = effective.opa_policy_definition_id() {
                // Resolve the policy text from the definition store
                // Clone the Arc so we release the std::sync lock before awaiting
                let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                    .policy_definition_store
                    .read()
                    .expect("policy_definition_store lock poisoned")
                    .clone();
                let policy_text = if let Some(ref store) = maybe_store {
                    store.get(def_id).await
                } else {
                    warn!(channel_id = %config_id, def_id = %def_id, "Policy definition store not available; skipping policy compile");
                    None
                };

                match policy_text {
                    Some(def) if !def.policy.is_empty() => {
                        info!(channel_id = %config_id, def_id = %def_id, "Compiling OPA policy for channel");
                        let engine = OpaEngine::new();
                        engine.load_policy(config_id, &def.policy)?;
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.insert(config_id.clone(), engine);
                        info!(channel_id = %config_id, "OPA policy compiled and cached");
                    }
                    Some(_) => {
                        warn!(channel_id = %config_id, def_id = %def_id, "Policy definition has empty Rego body; removing engine");
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.remove(config_id);
                    }
                    None => {
                        warn!(channel_id = %config_id, def_id = %def_id, "Policy definition not found; removing engine");
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.remove(config_id);
                    }
                }
            } else {
                // opa_enabled but no definition_id — remove any stale engine
                let mut engines = self
                    .opa_engines
                    .write()
                    .expect("opa_engines lock poisoned");
                if engines
                    .remove(config_id)
                    .is_some()
                {
                    info!(channel_id = %config_id, "Removed OPA policy for channel (no definition_id)");
                }
            }
        } else {
            let mut engines = self
                .opa_engines
                .write()
                .expect("opa_engines lock poisoned");
            if engines
                .remove(config_id)
                .is_some()
            {
                info!(channel_id = %config_id, "Removed OPA policy for channel");
            }
        }

        // Handle access-point inbound OPA policy. Compiled engines live under
        // `inbound:{config_id}` for the base/default variant and
        // `inbound:variant:{config_id}:{alias}` for each non-default variant
        // that overrides `access_point.inbound_policy`. This mirrors the
        // target-policy variant scheme so the handler can evaluate the
        // active-variant inbound policy with a single key lookup.
        {
            let inbound_base_key = format!("inbound:{}", config_id);
            {
                let mut engines = self
                    .opa_engines
                    .write()
                    .expect("opa_engines lock poisoned");
                let prefix = format!("inbound:variant:{}:", config_id);
                engines.retain(|k, _| !k.starts_with(&prefix));
                engines.remove(&inbound_base_key);
            }

            if let Some(def_id) = effective.inbound_opa_policy_definition_id() {
                let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                    .policy_definition_store
                    .read()
                    .expect("policy_definition_store lock poisoned")
                    .clone();
                let policy_text = if let Some(ref store) = maybe_store {
                    store.get(def_id).await
                } else {
                    warn!(channel_id = %config_id, def_id = %def_id, "Policy definition store not available; skipping inbound policy compile");
                    None
                };
                match policy_text {
                    Some(def) if !def.policy.is_empty() => {
                        info!(channel_id = %config_id, def_id = %def_id, key = %inbound_base_key, "Compiling inbound OPA policy for channel");
                        let engine = OpaEngine::new();
                        engine.load_policy(&inbound_base_key, &def.policy)?;
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.insert(inbound_base_key, engine);
                    }
                    Some(_) => {
                        warn!(channel_id = %config_id, def_id = %def_id, "Inbound policy definition has empty Rego body; not installing engine");
                    }
                    None => {
                        warn!(channel_id = %config_id, def_id = %def_id, "Inbound policy definition not found; not installing engine");
                    }
                }
            }

            for variant in surface.variants.iter() {
                if !variant.enabled {
                    continue;
                }
                if surface
                    .default_variant_id
                    .as_deref()
                    == Some(variant.id.as_str())
                {
                    continue;
                }
                let alias = variant.alias.as_str();
                let resolved = match surface.resolve_variant(Some(alias)) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let Some(def_id) = resolved.inbound_opa_policy_definition_id() else {
                    continue;
                };
                let variant_key = format!("inbound:variant:{}:{}", config_id, alias);
                let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                    .policy_definition_store
                    .read()
                    .expect("policy_definition_store lock poisoned")
                    .clone();
                let policy_text = if let Some(ref store) = maybe_store {
                    store.get(def_id).await
                } else {
                    warn!(channel_id = %config_id, variant_alias = %alias, def_id = %def_id, "Policy definition store not available; skipping variant inbound policy compile");
                    None
                };
                match policy_text {
                    Some(def) if !def.policy.is_empty() => {
                        info!(channel_id = %config_id, variant_alias = %alias, def_id = %def_id, key = %variant_key, "Compiling variant inbound OPA policy");
                        let engine = OpaEngine::new();
                        engine.load_policy(&variant_key, &def.policy)?;
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.insert(variant_key, engine);
                    }
                    Some(_) => {
                        warn!(channel_id = %config_id, variant_alias = %alias, def_id = %def_id, "Variant inbound policy definition has empty Rego body; not installing engine");
                    }
                    None => {
                        warn!(channel_id = %config_id, variant_alias = %alias, def_id = %def_id, "Variant inbound policy definition not found; not installing engine");
                    }
                }
            }
        }

        // Handle outbound OPA policy — uses a separate engine key ("outbound:{config_id}")
        // so inbound and outbound policies can coexist without overwriting each other.
        let outbound_key = format!("outbound:{}", config_id);
        let outbound_def_id = surface
            .transit
            .as_ref()
            .filter(|t| !t.points.is_empty())
            .and_then(|t| {
                t.shared
                    .opa_policy_definition_id
                    .as_ref()
            });
        if let Some(def_id) = outbound_def_id {
            let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                .policy_definition_store
                .read()
                .expect("policy_definition_store lock poisoned")
                .clone();
            let Some(ref store) = maybe_store else {
                return Err(format!(
                    "Channel '{}': outbound opa_policy_definition_id '{}' is set but policy definition store is not available",
                    config_id, def_id
                ));
            };

            match store.get(def_id).await {
                Some(def) if !def.policy.is_empty() => {
                    info!(channel_id = %config_id, def_id = %def_id, "Compiling outbound OPA policy for channel");
                    let engine = OpaEngine::new();
                    engine.load_policy(&outbound_key, &def.policy)?;
                    let mut engines = self
                        .opa_engines
                        .write()
                        .expect("opa_engines lock poisoned");
                    engines.insert(outbound_key.clone(), engine);
                    info!(channel_id = %config_id, "Outbound OPA policy compiled and cached (key={})", outbound_key);
                }
                Some(_) => {
                    return Err(format!(
                        "Channel '{}': outbound policy definition '{}' has empty Rego body",
                        config_id, def_id
                    ));
                }
                None => {
                    return Err(format!("Channel '{}': outbound policy definition '{}' not found", config_id, def_id));
                }
            }
        } else {
            // Outbound not enabled or no policy definition — remove any stale outbound engine
            let mut engines = self
                .opa_engines
                .write()
                .expect("opa_engines lock poisoned");
            if engines
                .remove(&outbound_key)
                .is_some()
            {
                info!(channel_id = %config_id, "Removed outbound OPA policy for channel (key={})", outbound_key);
            }
        }

        // Handle response OPA policy — uses key "response:{definition_id}" so response policies
        // can coexist with inbound and outbound policies.
        let response_def_id = surface.response_policy_definition_id();
        let response_key = format!("response:{}", response_def_id.unwrap_or(""));
        if let Some(def_id) = response_def_id {
            let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                .policy_definition_store
                .read()
                .expect("policy_definition_store lock poisoned")
                .clone();
            let policy_text = if let Some(ref store) = maybe_store {
                store.get(def_id).await
            } else {
                warn!(channel_id = %config_id, def_id = %def_id, "Policy definition store not available; skipping response policy compile");
                None
            };

            match policy_text {
                Some(def) if !def.policy.is_empty() => {
                    info!(channel_id = %config_id, def_id = %def_id, "Compiling response OPA policy for channel");
                    let engine = OpaEngine::new();
                    engine.load_policy(&response_key, &def.policy)?;
                    let mut engines = self
                        .opa_engines
                        .write()
                        .expect("opa_engines lock poisoned");
                    engines.insert(response_key.clone(), engine);
                    info!(channel_id = %config_id, "Response OPA policy compiled and cached (key={})", response_key);
                }
                Some(_) => {
                    warn!(channel_id = %config_id, def_id = %def_id, "Response policy definition has empty Rego body; removing engine");
                    let mut engines = self
                        .opa_engines
                        .write()
                        .expect("opa_engines lock poisoned");
                    engines.remove(&response_key);
                }
                None => {
                    warn!(channel_id = %config_id, def_id = %def_id, "Response policy definition not found; removing engine");
                    let mut engines = self
                        .opa_engines
                        .write()
                        .expect("opa_engines lock poisoned");
                    engines.remove(&response_key);
                }
            }
        } else {
            // No response policy — remove any stale engine
            let mut engines = self
                .opa_engines
                .write()
                .expect("opa_engines lock poisoned");
            engines.remove(&response_key);
        }

        // Per-variant target OPA policies — each uses key
        // "variant:{config_id}:{alias}". Compiled when a variant's effective
        // (merged) `target.policy` is set; lookup at request time prefers the
        // variant key and falls back to the surface key. Always clear
        // previously-installed entries for this surface first so removed or
        // renamed variants don't leave stale engines behind.
        {
            let mut engines = self
                .opa_engines
                .write()
                .expect("opa_engines lock poisoned");
            let prefix = format!("variant:{}:", config_id);
            engines.retain(|k, _| !k.starts_with(&prefix));
        }
        for variant in &surface.variants {
            let resolved = match surface.resolve_variant(Some(&variant.alias)) {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        channel_id = %config_id,
                        variant_alias = %variant.alias,
                        error = %e,
                        "Failed to resolve variant; skipping per-variant policy compile"
                    );
                    continue;
                }
            };
            // Request-side policy
            let request_def_id = resolved
                .opa_policy_definition_id()
                .map(|s| s.to_string());
            if let Some(def_id) = request_def_id {
                let v_key = format!("variant:{}:{}", config_id, variant.alias);
                let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                    .policy_definition_store
                    .read()
                    .expect("policy_definition_store lock poisoned")
                    .clone();
                let policy_text = if let Some(ref store) = maybe_store {
                    store.get(&def_id).await
                } else {
                    None
                };
                match policy_text {
                    Some(def) if !def.policy.is_empty() => {
                        info!(channel_id = %config_id, variant_alias = %variant.alias, def_id = %def_id, "Compiling per-variant target OPA policy");
                        let engine = OpaEngine::new();
                        engine.load_policy(&v_key, &def.policy)?;
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.insert(v_key, engine);
                    }
                    Some(_) => {
                        warn!(channel_id = %config_id, variant_alias = %variant.alias, def_id = %def_id, "Per-variant target policy definition has empty Rego body; skipping engine");
                    }
                    None => {
                        warn!(channel_id = %config_id, variant_alias = %variant.alias, def_id = %def_id, "Per-variant target policy definition not found; skipping engine");
                    }
                }
            }
            // Response-side policy — engines are keyed by `response:{def_id}`
            // (matching the base compile path) so multiple variants pointing
            // at the same definition share one engine. The handler-side
            // lookup uses `state.surface.response_policy_definition_id()`,
            // which is already variant-aware (state.surface is the resolved
            // variant surface), so installing under the def-id key is
            // sufficient.
            let response_def_id = resolved
                .response_policy_definition_id()
                .map(|s| s.to_string());
            if let Some(def_id) = response_def_id {
                let v_resp_key = format!("response:{}", def_id);
                let already_installed = self
                    .opa_engines
                    .read()
                    .expect("opa_engines lock poisoned")
                    .contains_key(&v_resp_key);
                if !already_installed {
                    let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                        .policy_definition_store
                        .read()
                        .expect("policy_definition_store lock poisoned")
                        .clone();
                    let policy_text = if let Some(ref store) = maybe_store {
                        store.get(&def_id).await
                    } else {
                        None
                    };
                    match policy_text {
                        Some(def) if !def.policy.is_empty() => {
                            info!(channel_id = %config_id, variant_alias = %variant.alias, def_id = %def_id, "Compiling per-variant response OPA policy");
                            let engine = OpaEngine::new();
                            engine.load_policy(&v_resp_key, &def.policy)?;
                            let mut engines = self
                                .opa_engines
                                .write()
                                .expect("opa_engines lock poisoned");
                            engines.insert(v_resp_key, engine);
                        }
                        Some(_) => {
                            warn!(channel_id = %config_id, variant_alias = %variant.alias, def_id = %def_id, "Per-variant response policy definition has empty Rego body; skipping engine");
                        }
                        None => {
                            warn!(channel_id = %config_id, variant_alias = %variant.alias, def_id = %def_id, "Per-variant response policy definition not found; skipping engine");
                        }
                    }
                }
            }
        }

        // Handle per-transit-point OPA policies — each uses key "transit:{config_id}:{alias}"
        for tp in surface.transit_points() {
            let tp_key = format!("transit:{}:{}", config_id, tp.alias);
            if let Some(ref def_id) = tp
                .policy
                .as_ref()
                .map(|p| p.policy_definition_id.clone())
            {
                let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                    .policy_definition_store
                    .read()
                    .expect("policy_definition_store lock poisoned")
                    .clone();
                let policy_text = if let Some(ref store) = maybe_store {
                    store.get(def_id).await
                } else {
                    None
                };

                match policy_text {
                    Some(def) if !def.policy.is_empty() => {
                        info!(channel_id = %config_id, alias = %tp.alias, def_id = %def_id, "Compiling per-transit-point OPA policy");
                        let engine = OpaEngine::new();
                        engine.load_policy(&tp_key, &def.policy)?;
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.insert(tp_key.clone(), engine);
                    }
                    _ => {
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.remove(&tp_key);
                    }
                }
            } else {
                let mut engines = self
                    .opa_engines
                    .write()
                    .expect("opa_engines lock poisoned");
                engines.remove(&tp_key);
            }
        }

        // Handle per-transit-point response OPA policies — each uses key
        // "response:transit:{config_id}:{alias}". Independent of the per-TP
        // request policy above so each TP flow can carry its own response gate.
        for tp in surface.transit_points() {
            let tp_resp_key = format!("response:transit:{}:{}", config_id, tp.alias);
            if let Some(ref def_id) = tp
                .response_policy
                .as_ref()
                .map(|p| p.policy_definition_id.clone())
            {
                let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
                    .policy_definition_store
                    .read()
                    .expect("policy_definition_store lock poisoned")
                    .clone();
                let policy_text = if let Some(ref store) = maybe_store {
                    store.get(def_id).await
                } else {
                    None
                };

                match policy_text {
                    Some(def) if !def.policy.is_empty() => {
                        info!(channel_id = %config_id, alias = %tp.alias, def_id = %def_id, "Compiling per-transit-point response OPA policy");
                        let engine = OpaEngine::new();
                        engine.load_policy(&tp_resp_key, &def.policy)?;
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.insert(tp_resp_key.clone(), engine);
                    }
                    _ => {
                        let mut engines = self
                            .opa_engines
                            .write()
                            .expect("opa_engines lock poisoned");
                        engines.remove(&tp_resp_key);
                    }
                }
            } else {
                let mut engines = self
                    .opa_engines
                    .write()
                    .expect("opa_engines lock poisoned");
                engines.remove(&tp_resp_key);
            }
        }

        // Handle rate limiting
        if let Some(rate_limit_config) = &effective
            .access_point
            .rate_limit
        {
            info!(
                surface_id = %config_id,
                requests = rate_limit_config.requests,
                window_secs = rate_limit_config.window_secs,
                "Configuring rate limiter for channel"
            );

            let rl_config = crate::policies::RateLimitConfig {
                requests: rate_limit_config.requests,
                window_secs: rate_limit_config.window_secs,
                burst: rate_limit_config.burst,
            };

            let rate_limiter =
                RateLimiter::new(rl_config).map_err(|e| format!("Failed to create rate limiter: {}", e))?;

            let mut limiters = self
                .rate_limiters
                .write()
                .await;
            limiters.insert(config_id.clone(), Arc::new(rate_limiter));

            info!(channel_id = %config_id, "Rate limiter configured successfully");
        } else {
            // Remove rate limiter if none configured
            let mut limiters = self
                .rate_limiters
                .write()
                .await;
            if limiters
                .remove(config_id)
                .is_some()
            {
                info!(channel_id = %config_id, "Removed rate limiter for channel");
            }
        }

        // Per-VC outbound rate limiters. Each outbound virtual channel
        // (transit point in the agent-surface model) can declare its own
        // `rate_limit`; install a separate limiter keyed by
        // `vc:{config_id}:{alias}` so per-TP enforcement composes with
        // (and runs after) the channel-wide limit. Always clear any
        // previously-installed per-VC limiters for this channel first
        // so removed/renamed VCs don't leave stale entries behind.
        {
            let mut limiters = self
                .rate_limiters
                .write()
                .await;
            let prefix = format!("vc:{}:", config_id);
            limiters.retain(|k, _| !k.starts_with(&prefix));
            for tp in surface.transit_points() {
                let Some(rl) = tp.rate_limit.as_ref() else {
                    continue;
                };
                let rl_config = crate::policies::RateLimitConfig {
                    requests: rl.requests,
                    window_secs: rl.window_secs,
                    burst: rl.burst,
                };
                match RateLimiter::new(rl_config) {
                    Ok(rate_limiter) => {
                        let key = format!("{}{}", prefix, tp.alias);
                        info!(
                            surface_id = %config_id,
                            vc_alias = %tp.alias,
                            requests = rl.requests,
                            window_secs = rl.window_secs,
                            "Configuring per-VC outbound rate limiter"
                        );
                        limiters.insert(key, Arc::new(rate_limiter));
                    }
                    Err(e) => {
                        warn!(
                            surface_id = %config_id,
                            vc_alias = %tp.alias,
                            error = %e,
                            "Failed to create per-VC rate limiter"
                        );
                    }
                }
            }
        }

        // Handle circuit breaker
        if let Some(cb_config) = effective.circuit_breaker() {
            info!(
                surface_id = %config_id,
                failure_threshold = cb_config.failure_threshold,
                timeout_secs = cb_config.timeout_secs,
                "Configuring circuit breaker for channel"
            );

            let circuit_breaker = CircuitBreaker::new(cb_config.clone());

            let mut breakers = self
                .circuit_breakers
                .write()
                .await;
            breakers.insert(config_id.clone(), Arc::new(circuit_breaker));

            info!(channel_id = %config_id, "Circuit breaker configured successfully");
        } else {
            // Remove circuit breaker if none configured
            let mut breakers = self
                .circuit_breakers
                .write()
                .await;
            if breakers
                .remove(config_id)
                .is_some()
            {
                info!(channel_id = %config_id, "Removed circuit breaker for channel");
            }
        }

        // Handle MCP Tool Gating — compile regex sets + condition OPA engines
        // once per surface, cached for per-request reuse. Base gating is keyed
        // by `config_id`; a variant whose effective gating differs from the base
        // gets its own `variant:{config_id}:{alias}` entry (an empty tombstone
        // when it clears the base gating, so it does not inherit at lookup).
        //
        // Build every new entry OFF the cache lock, then swap the whole set in
        // under a single write lock. Doing the clear + repopulate atomically
        // avoids a TOCTOU window where a concurrent request would observe the
        // gating as absent (fail-open) between the clear and the recompile.
        {
            let base_cfg = effective
                .target
                .mcp_tool_gating
                .clone();

            let mut new_entries: Vec<(String, Arc<CompiledMcpToolGating>)> = Vec::new();

            if let Some(cfg) = base_cfg
                .as_ref()
                .filter(|c| !c.is_empty())
            {
                let compiled = self
                    .compile_mcp_tool_gating(cfg)
                    .await;
                new_entries.push((config_id.clone(), Arc::new(compiled)));
                info!(channel_id = %config_id, gate_count = cfg.gates.len(), "Compiled MCP tool gating for channel");
            }

            for variant in &surface.variants {
                let resolved = match surface.resolve_variant(Some(&variant.alias)) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let v_cfg = resolved
                    .target
                    .mcp_tool_gating
                    .clone();
                if v_cfg == base_cfg {
                    continue;
                }
                let v_key = format!("variant:{}:{}", config_id, variant.alias);
                match v_cfg
                    .as_ref()
                    .filter(|c| !c.is_empty())
                {
                    Some(cfg) => {
                        let compiled = self
                            .compile_mcp_tool_gating(cfg)
                            .await;
                        new_entries.push((v_key, Arc::new(compiled)));
                    }
                    None => {
                        // Variant differs and has no effective gating: only shadow
                        // the base when the base actually installed gating.
                        if base_cfg
                            .as_ref()
                            .map(|c| !c.is_empty())
                            .unwrap_or(false)
                        {
                            new_entries.push((v_key, Arc::new(CompiledMcpToolGating::empty())));
                        }
                    }
                }
            }

            // Per-Transit-Point MCP tool gating — each TP carries its own
            // firewall over its outbound MCP tool surface, keyed
            // `transit:{config_id}:{alias}`. Independent of the surface-wide
            // base/variant gating above; a TP without gating installs no entry
            // (the outbound path then applies no gating for that TP).
            for tp in surface.transit_points() {
                if let Some(cfg) = tp
                    .mcp_tool_gating
                    .as_ref()
                    .filter(|c| !c.is_empty())
                {
                    let compiled = self
                        .compile_mcp_tool_gating(cfg)
                        .await;
                    new_entries.push((format!("transit:{}:{}", config_id, tp.alias), Arc::new(compiled)));
                    info!(channel_id = %config_id, alias = %tp.alias, gate_count = cfg.gates.len(), "Compiled per-transit-point MCP tool gating");
                }
            }

            // Atomic swap: replace the base + all variant/transit entries for
            // this surface in one lock hold so no request ever sees a gap.
            let variant_prefix = format!("variant:{}:", config_id);
            let transit_prefix = format!("transit:{}:", config_id);
            let mut gating = self
                .mcp_tool_gating
                .write()
                .expect("mcp_tool_gating lock poisoned");
            gating.remove(config_id);
            gating.retain(|k, _| !k.starts_with(&variant_prefix) && !k.starts_with(&transit_prefix));
            for (key, compiled) in new_entries {
                gating.insert(key, compiled);
            }
        }

        Ok(())
    }

    /// Resolve every distinct condition policy id in `cfg` to its Rego text and
    /// compile the gating. A missing/empty/disabled condition definition is
    /// left unresolved, which makes that gate fail closed (always active).
    async fn compile_mcp_tool_gating(
        &self,
        cfg: &crate::config::agent_surface::McpToolGatingConfig,
    ) -> CompiledMcpToolGating {
        let mut texts: HashMap<String, String> = HashMap::new();
        let maybe_store: Option<Arc<FileSystemPolicyDefinitionStore>> = self
            .policy_definition_store
            .read()
            .expect("policy_definition_store lock poisoned")
            .clone();
        if let Some(store) = maybe_store {
            for gate in &cfg.gates {
                let Some(policy_id) = gate
                    .condition_policy_definition_id
                    .as_deref()
                else {
                    continue;
                };
                if texts.contains_key(policy_id) {
                    continue;
                }
                if let Some(def) = store.get(policy_id).await
                    && def.enabled
                    && !def.policy.is_empty()
                {
                    texts.insert(policy_id.to_string(), def.policy);
                }
            }
        }
        CompiledMcpToolGating::build(cfg, |id| texts.get(id).cloned())
    }

    /// Resolve the compiled gating for a surface/variant, preferring the
    /// variant-scoped entry when present. One read-lock + `Arc` clone; the
    /// caller then queries the returned handle directly (single lookup for the
    /// whole request rather than one per `has_/filter_/is_` call).
    pub fn compiled_mcp_tool_gating(
        &self,
        config_id: &str,
        variant_alias: Option<&str>,
    ) -> Option<Arc<CompiledMcpToolGating>> {
        let gating = self
            .mcp_tool_gating
            .read()
            .expect("mcp_tool_gating lock poisoned");
        variant_alias
            .and_then(|alias| {
                gating
                    .get(&format!("variant:{}:{}", config_id, alias))
                    .cloned()
            })
            .or_else(|| gating.get(config_id).cloned())
    }

    /// True when the surface/variant has at least one MCP tool gate installed.
    /// Test-only convenience; production fetches the compiled handle once via
    /// [`Self::compiled_mcp_tool_gating`] and queries it directly.
    #[cfg(test)]
    pub fn has_mcp_tool_gating(
        &self,
        config_id: &str,
        variant_alias: Option<&str>,
    ) -> bool {
        self.compiled_mcp_tool_gating(config_id, variant_alias)
            .map(|c| !c.is_empty())
            .unwrap_or(false)
    }

    /// Resolve the compiled gating for a specific transit point
    /// (key `transit:{config_id}:{alias}`). Per-TP gating is independent of
    /// the surface-wide base/variant gating and is not variant-scoped.
    pub fn compiled_mcp_tool_gating_for_transit(
        &self,
        config_id: &str,
        transit_alias: &str,
    ) -> Option<Arc<CompiledMcpToolGating>> {
        self.mcp_tool_gating
            .read()
            .expect("mcp_tool_gating lock poisoned")
            .get(&format!("transit:{}:{}", config_id, transit_alias))
            .cloned()
    }

    /// True when the given transit point has at least one MCP tool gate
    /// installed. Test-only convenience (see [`Self::has_mcp_tool_gating`]).
    #[cfg(test)]
    pub fn has_transit_mcp_tool_gating(
        &self,
        config_id: &str,
        transit_alias: &str,
    ) -> bool {
        self.compiled_mcp_tool_gating_for_transit(config_id, transit_alias)
            .map(|c| !c.is_empty())
            .unwrap_or(false)
    }

    /// Apply a transit point's MCP tool gating to a `tools/list` name set,
    /// returning the retained names. Returns the input unchanged when the TP
    /// has no gating installed. Test-only convenience.
    #[cfg(test)]
    pub fn filter_transit_mcp_tools_with_gating(
        &self,
        config_id: &str,
        transit_alias: &str,
        tools: Vec<String>,
        input: &serde_json::Value,
    ) -> Vec<String> {
        match self.compiled_mcp_tool_gating_for_transit(config_id, transit_alias) {
            Some(compiled) => compiled.filter_tools(tools, input),
            None => tools,
        }
    }

    /// Decide whether a `tools/call` for `tool_name` toward the given transit
    /// point is permitted by that TP's MCP tool gating. Returns `true` when the
    /// TP has no gating installed. Test-only convenience.
    #[cfg(test)]
    pub fn is_transit_mcp_tool_call_allowed(
        &self,
        config_id: &str,
        transit_alias: &str,
        tool_name: &str,
        input: &serde_json::Value,
    ) -> bool {
        match self.compiled_mcp_tool_gating_for_transit(config_id, transit_alias) {
            Some(compiled) => compiled.is_tool_call_allowed(tool_name, input),
            None => true,
        }
    }

    /// Get the circuit breaker for a channel (if configured)
    pub async fn get_circuit_breaker(
        &self,
        channel_id: &str,
    ) -> Option<Arc<CircuitBreaker>> {
        let breakers = self
            .circuit_breakers
            .read()
            .await;
        breakers
            .get(channel_id)
            .cloned()
    }

    /// Check rate limit for a channel
    pub async fn check_rate_limit(
        &self,
        channel_id: &str,
    ) -> Result<(), crate::policies::RateLimitError> {
        let limiters = self
            .rate_limiters
            .read()
            .await;

        if let Some(limiter) = limiters.get(channel_id) {
            let _span = tracing::info_span!(
                "channel.rate_limit",
                otel.name = "Rate Limit Check",
                surface = %channel_id
            );
            let _guard = _span.enter();

            debug!(channel_id = %channel_id, "Checking rate limit");
            limiter.check()?;
        }

        Ok(())
    }

    /// Test-only boolean convenience over [`Self::evaluate_policy_decision`].
    /// Production code calls `evaluate_policy_decision` directly so it can also
    /// record the deny reason in the policy-decision audit event.
    #[cfg(test)]
    pub fn evaluate_policy(
        &self,
        channel_id: &str,
        input: serde_json::Value,
    ) -> Result<bool, String> {
        Ok(self
            .evaluate_policy_decision(channel_id, input)?
            .allow)
    }

    /// Evaluate policy for a channel, returning the full decision (allow flag
    /// plus deny reason). Unlike [`Self::evaluate_policy`], this performs no
    /// logging of its own — the caller is expected to record a single
    /// structured audit event so a denial is not logged twice.
    pub fn evaluate_policy_decision(
        &self,
        channel_id: &str,
        input: serde_json::Value,
    ) -> Result<crate::policies::PolicyDecision, String> {
        self.evaluate_policy_decision_for_variant(channel_id, None, input)
    }

    /// Evaluate policy for a surface/variant pair. Prefers the variant-scoped
    /// engine (key `variant:{channel_id}:{alias}`) when present, falling back
    /// to the surface-scoped engine. Same audit-logging contract as
    /// [`Self::evaluate_policy_decision`].
    pub fn evaluate_policy_decision_for_variant(
        &self,
        channel_id: &str,
        variant_alias: Option<&str>,
        input: serde_json::Value,
    ) -> Result<crate::policies::PolicyDecision, String> {
        let engines = self
            .opa_engines
            .read()
            .expect("opa_engines lock poisoned");

        let (lookup_key, engine) = if let Some(alias) = variant_alias {
            let v_key = format!("variant:{}:{}", channel_id, alias);
            if let Some(e) = engines.get(&v_key) {
                (v_key, Some(e))
            } else {
                (channel_id.to_string(), engines.get(channel_id))
            }
        } else {
            (channel_id.to_string(), engines.get(channel_id))
        };

        if let Some(engine) = engine {
            debug!(channel_id = %channel_id, lookup_key = %lookup_key, "Evaluating OPA policy");
            engine.evaluate(input)
        } else {
            debug!(channel_id = %channel_id, "Engine not found for channel, denying request");
            Ok(crate::policies::PolicyDecision {
                allow: false,
                reason: Some("No policy engine loaded for channel".to_string()),
            })
        }
    }

    /// Evaluate the access-point (inbound) OPA policy for the given surface
    /// and active variant. Prefers the variant-keyed engine
    /// (`inbound:variant:{cid}:{alias}`) and falls back to the base inbound
    /// engine (`inbound:{cid}`) when no variant override is installed.
    /// Returns the full decision so the caller can record a single audit
    /// event without double-logging.
    pub fn evaluate_inbound_policy_decision_for_variant(
        &self,
        channel_id: &str,
        active_variant_alias: Option<&str>,
        input: serde_json::Value,
    ) -> Result<crate::policies::PolicyDecision, String> {
        let engines = self
            .opa_engines
            .read()
            .expect("opa_engines lock poisoned");

        let engine = active_variant_alias
            .and_then(|alias| engines.get(&format!("inbound:variant:{}:{}", channel_id, alias)))
            .or_else(|| engines.get(&format!("inbound:{}", channel_id)));

        if let Some(engine) = engine {
            debug!(channel_id = %channel_id, variant_alias = ?active_variant_alias, "Evaluating inbound OPA policy");
            engine.evaluate(input)
        } else {
            debug!(channel_id = %channel_id, variant_alias = ?active_variant_alias, "No inbound OPA engine found for surface/variant, denying request");
            Ok(crate::policies::PolicyDecision {
                allow: false,
                reason: Some("No inbound policy engine loaded for surface".to_string()),
            })
        }
    }

    /// Filter MCP tools based on policy.
    /// Uses clone-per-eval — each tool evaluation is independent.
    ///
    /// `input_template` is the request-level `PolicyInput` built by the
    /// caller; the engine clones it and stamps `input.mcp` per-tool so the
    /// policy sees the same context for `tools/list` filtering as for the
    /// general channel OPA gate.
    #[allow(dead_code)]
    pub fn filter_mcp_tools(
        &self,
        channel_id: &str,
        tools: Vec<String>,
        input_template: &crate::surface_context::PolicyInput,
    ) -> Vec<String> {
        self.filter_mcp_tools_for_variant(channel_id, None, tools, input_template)
    }

    /// Variant-aware MCP tool filter. Prefers the variant-scoped engine
    /// (`variant:{channel_id}:{alias}`) when present, falling back to the
    /// surface-scoped engine.
    pub fn filter_mcp_tools_for_variant(
        &self,
        channel_id: &str,
        variant_alias: Option<&str>,
        tools: Vec<String>,
        input_template: &crate::surface_context::PolicyInput,
    ) -> Vec<String> {
        let engines = self
            .opa_engines
            .read()
            .expect("opa_engines lock poisoned");

        let engine = variant_alias
            .and_then(|alias| engines.get(&format!("variant:{}:{}", channel_id, alias)))
            .or_else(|| engines.get(channel_id));

        if let Some(engine) = engine {
            debug!(channel_id = %channel_id, tool_count = tools.len(), "Filtering MCP tools with policy");
            let filtered = engine.filter_mcp_tools(tools.clone(), input_template);

            if filtered.len() < tools.len() {
                info!(
                    surface_id = %channel_id,
                    original_count = tools.len(),
                    filtered_count = filtered.len(),
                    "Filtered {} tools by policy",
                    tools.len() - filtered.len()
                );
            }

            filtered
        } else {
            // No policy, return all tools
            tools
        }
    }

    /// Remove all policies and rate limiters for a channel
    #[allow(dead_code)]
    pub async fn remove_channel(
        &self,
        channel_id: &str,
    ) {
        let _access_change = crate::mcp::subscriptions::AccessChange::begin();
        {
            let mut engines = self
                .opa_engines
                .write()
                .expect("opa_engines lock poisoned");
            engines.remove(channel_id);
            // Also remove the outbound-specific engine key
            engines.remove(&format!("outbound:{}", channel_id));
            // Remove the access-point inbound base engine and any per-variant
            // inbound engines installed for this channel.
            engines.remove(&format!("inbound:{}", channel_id));
            let inbound_variant_prefix = format!("inbound:variant:{}:", channel_id);
            engines.retain(|k, _| !k.starts_with(&inbound_variant_prefix));
            // Drop any per-variant request engines installed for this channel.
            // Response-side engines are keyed by `response:{def_id}` and can
            // be shared across surfaces, so they are not cleared here.
            let v_prefix = format!("variant:{}:", channel_id);
            engines.retain(|k, _| !k.starts_with(&v_prefix));
        }
        {
            // Drop base + per-variant MCP tool gating for this channel.
            let mut gating = self
                .mcp_tool_gating
                .write()
                .expect("mcp_tool_gating lock poisoned");
            gating.remove(channel_id);
            let gating_variant_prefix = format!("variant:{}:", channel_id);
            gating.retain(|k, _| !k.starts_with(&gating_variant_prefix));
        }
        let mut limiters = self
            .rate_limiters
            .write()
            .await;

        limiters.remove(channel_id);
        // Drop any per-VC limiters installed for this channel.
        let prefix = format!("vc:{}:", channel_id);
        limiters.retain(|k, _| !k.starts_with(&prefix));

        info!(channel_id = %channel_id, "Removed all policies and rate limiters");
    }

    /// Load a policy engine directly from Rego text (test helper).
    #[cfg(test)]
    pub fn load_policy_text(
        &self,
        channel_id: &str,
        policy_text: &str,
    ) -> Result<(), String> {
        let engine = OpaEngine::new();
        engine.load_policy(channel_id, policy_text)?;
        let mut engines = self
            .opa_engines
            .write()
            .expect("opa_engines lock poisoned");
        engines.insert(channel_id.to_string(), engine);
        Ok(())
    }
}

impl Default for SurfacePolicyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_surface(config_id: &str) -> crate::config::agent_surface::AgentSurface {
        use crate::config::agent_surface::{AccessPoint, AgentSurface, SurfaceProtocol, SurfaceStatus, Target};
        AgentSurface {
            surface_id: config_id.to_string(),
            name: "test-channel".to_string(),
            description: "Test channel".to_string(),
            status: SurfaceStatus::Active,
            access_point: AccessPoint {
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/".to_string(),
                protocol: SurfaceProtocol::Mcp,
                ..Default::default()
            },
            target: Target {
                endpoint: "http://localhost:9000".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_rate_limit_config() {
        let manager = SurfacePolicyManager::new();
        let mut surface = create_test_surface("test-1");

        surface
            .access_point
            .rate_limit = Some(crate::config::RateLimitConfig {
            requests: 2,
            window_secs: 1,
            burst: None,
        });

        manager
            .update_channel_policy(&surface)
            .await
            .unwrap();

        // First two requests should succeed
        assert!(
            manager
                .check_rate_limit("test-1")
                .await
                .is_ok()
        );
        assert!(
            manager
                .check_rate_limit("test-1")
                .await
                .is_ok()
        );

        // Third should fail
        assert!(
            manager
                .check_rate_limit("test-1")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_opa_policy_allow() {
        let manager = SurfacePolicyManager::new();

        manager
            .load_policy_text(
                "test-2",
                r#"
package surface.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}
"#,
            )
            .unwrap();

        let input = serde_json::json!({
            "mcp": {
                "method": "tools/call",
                "tool_name": "echo"
            }
        });

        let allowed = manager
            .evaluate_policy("test-2", input)
            .unwrap();
        assert!(allowed);
    }

    #[tokio::test]
    async fn test_filter_tools() {
        let manager = SurfacePolicyManager::new();

        manager
            .load_policy_text(
                "test-3",
                r#"
package surface.policy

default allow = false

allow if {
    input.mcp.tool_name == "echo"
}

allow if {
    input.mcp.tool_name == "add"
}
"#,
            )
            .unwrap();

        let tools = vec!["echo".to_string(), "add".to_string(), "forbidden".to_string()];
        let filtered = manager.filter_mcp_tools("test-3", tools, &Default::default());

        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains(&"echo".to_string()));
        assert!(filtered.contains(&"add".to_string()));
        assert!(!filtered.contains(&"forbidden".to_string()));
    }

    #[tokio::test]
    async fn filter_mcp_tools_propagates_template_through_manager() {
        // Regression guard for audit P3 #17 at the manager layer: the
        // PolicyInput template carried by callers must survive the manager
        // hop and reach per-tool Rego evaluation.
        let manager = SurfacePolicyManager::new();
        manager
            .load_policy_text(
                "test-prop",
                r#"
package surface.policy

default allow = false

allow if {
    input.source_auth.method == "api_key"
    input.mcp.tool_name == "echo"
}
"#,
            )
            .unwrap();

        let template = crate::surface_context::PolicyInput {
            source_auth: Some(crate::surface_context::SourceAuthContext::ApiKey { key_name: "k".to_string() }),
            ..Default::default()
        };

        let with_template =
            manager.filter_mcp_tools("test-prop", vec!["echo".to_string(), "blocked".to_string()], &template);
        assert_eq!(with_template, vec!["echo".to_string()]);

        let without_template = manager.filter_mcp_tools("test-prop", vec!["echo".to_string()], &Default::default());
        assert!(without_template.is_empty(), "without source_auth in the template every tool must be filtered out");
    }

    #[tokio::test]
    async fn per_transit_point_mcp_tool_gating_is_independent_of_base() {
        // A TP carrying an unconditional deny gate installs per-TP gating
        // keyed `transit:{cid}:{alias}`, independent of the surface-wide
        // `target.mcp_tool_gating` (absent here).
        let manager = SurfacePolicyManager::new();
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "cfg-tp-gate",
            "name": "tp-gate",
            "description": "",
            "status": "active",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/",
                "protocol": "mcp"
            },
            "target": { "endpoint": "http://localhost:9000" },
            "transit": {
                "points": [{
                    "alias": "partner-mcp",
                    "target_endpoint": "https://partner.example.com/mcp",
                    "protocol": "mcp",
                    "mcp_tool_gating": {
                        "gates": [{
                            "id": "g1",
                            "name": "no admin",
                            "action": { "effect": "deny", "patterns": ["^admin_"] }
                        }]
                    }
                }]
            }
        }))
        .expect("surface json");

        manager
            .update_channel_policy(&surface)
            .await
            .unwrap();

        // Per-TP gating is installed; the surface-wide (base) gating is not.
        assert!(manager.has_transit_mcp_tool_gating("cfg-tp-gate", "partner-mcp"));
        assert!(!manager.has_mcp_tool_gating("cfg-tp-gate", None));

        // tools/list filter hides the denied tool for this TP.
        let filtered = manager.filter_transit_mcp_tools_with_gating(
            "cfg-tp-gate",
            "partner-mcp",
            vec!["admin_delete".to_string(), "echo".to_string()],
            &Default::default(),
        );
        assert_eq!(filtered, vec!["echo".to_string()]);

        // tools/call gate blocks the denied tool and allows others.
        assert!(!manager.is_transit_mcp_tool_call_allowed(
            "cfg-tp-gate",
            "partner-mcp",
            "admin_delete",
            &Default::default()
        ));
        assert!(manager.is_transit_mcp_tool_call_allowed("cfg-tp-gate", "partner-mcp", "echo", &Default::default()));

        // An unknown TP alias has no gating installed (allow-through).
        assert!(!manager.has_transit_mcp_tool_gating("cfg-tp-gate", "does-not-exist"));
        assert!(manager.is_transit_mcp_tool_call_allowed(
            "cfg-tp-gate",
            "does-not-exist",
            "admin_delete",
            &Default::default()
        ));
    }

    #[tokio::test]
    async fn surface_deny_by_default_with_no_gates_denies_all_tools() {
        // A surface-wide `target.mcp_tool_gating = { default_effect: "deny" }`
        // with no gates must install (it is NOT a no-op) and deny every tool.
        let manager = SurfacePolicyManager::new();
        let surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "cfg-deny-all",
            "name": "deny-all",
            "description": "",
            "status": "active",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/",
                "protocol": "mcp"
            },
            "target": {
                "endpoint": "http://localhost:9000",
                "mcp_tool_gating": { "default_effect": "deny" }
            }
        }))
        .expect("surface json");

        manager
            .update_channel_policy(&surface)
            .await
            .unwrap();

        let gating = manager
            .compiled_mcp_tool_gating("cfg-deny-all", None)
            .expect("deny-by-default gating must be installed even with no gates");
        assert!(!gating.is_empty());
        assert!(
            gating
                .filter_tools(vec!["read".to_string(), "write".to_string()], &serde_json::Value::Null)
                .is_empty()
        );
        assert!(!gating.is_tool_call_allowed("read", &serde_json::Value::Null));
    }

    #[tokio::test]
    async fn evict_all_opa_engines_denies_base_and_variant() {
        // F2/M-1: eviction must clear the base *and* every variant engine for
        // a surface. The evaluator prefers the variant key over the base, so a
        // surviving stale variant engine would defeat fail-closed enforcement.
        let manager = SurfacePolicyManager::new();
        let allow_all = "package surface.policy\ndefault allow = true";
        manager
            .load_policy_text("s-evict", allow_all)
            .unwrap();
        manager
            .load_policy_text("variant:s-evict:v1", allow_all)
            .unwrap();

        // Sanity: both keys currently allow (stale permissive state).
        assert!(
            manager
                .evaluate_policy_decision_for_variant("s-evict", None, serde_json::json!({}))
                .unwrap()
                .allow
        );
        assert!(
            manager
                .evaluate_policy_decision_for_variant("s-evict", Some("v1"), serde_json::json!({}))
                .unwrap()
                .allow
        );

        manager.evict_all_opa_engines_for_config("s-evict");

        // Both the base and the variant now fail closed (no engine → deny).
        assert!(
            !manager
                .evaluate_policy_decision_for_variant("s-evict", None, serde_json::json!({}))
                .unwrap()
                .allow
        );
        assert!(
            !manager
                .evaluate_policy_decision_for_variant("s-evict", Some("v1"), serde_json::json!({}))
                .unwrap()
                .allow
        );
    }

    #[tokio::test]
    async fn failed_recompile_evicts_stale_variant_engine_fail_closed() {
        // F2 end-to-end: when a surface's target policy fails to compile,
        // update_channel_policy must evict the whole key set — including a
        // stale, permissive variant engine left from a prior good compile — so
        // a request to that variant fails closed instead of hitting the old
        // engine.
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

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
                id: "broken-def".into(),
                name: "broken".into(),
                description: String::new(),
                policy_type: PolicyType::AgentSurface,
                policy: "this is not valid rego {{{".into(),
                enabled: true,
                created_at: "t".into(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
                tenant_id: None,
            })
            .await
            .unwrap();

        let manager = SurfacePolicyManager::new();
        manager.set_policy_definition_store(store);

        // Stale, permissive variant engine from a prior good compile.
        manager
            .load_policy_text("variant:s-wrap:v1", "package surface.policy\ndefault allow = true")
            .unwrap();
        assert!(
            manager
                .evaluate_policy_decision_for_variant("s-wrap", Some("v1"), serde_json::json!({}))
                .unwrap()
                .allow,
            "precondition: stale variant engine allows"
        );

        // Enable target OPA pointing at the broken definition.
        let mut surface = create_test_surface("s-wrap");
        surface.target.policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: "broken-def".to_string(),
            require_agent_context: false,
        });

        let result = manager
            .update_channel_policy(&surface)
            .await;
        assert!(result.is_err(), "a broken policy recompile must return Err");

        // The stale variant engine is gone → fail closed on base and variant.
        assert!(
            !manager
                .evaluate_policy_decision_for_variant("s-wrap", Some("v1"), serde_json::json!({}))
                .unwrap()
                .allow,
            "failed recompile must evict the stale variant engine"
        );
        assert!(
            !manager
                .evaluate_policy_decision_for_variant("s-wrap", None, serde_json::json!({}))
                .unwrap()
                .allow
        );
    }

    #[tokio::test]
    async fn resolve_policy_attestation_names_the_stored_revision() {
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

        let manager = SurfacePolicyManager::new();
        assert_eq!(
            manager
                .resolve_policy_attestation(Some("deny-def"))
                .await,
            crate::policies::PolicyAttestation::default(),
            "no store, no attestation"
        );

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
                id: "deny-def".into(),
                name: "Deny unknown callers".into(),
                description: String::new(),
                policy_type: PolicyType::AgentSurface,
                policy: "package surface.policy\ndefault allow = false".into(),
                enabled: true,
                created_at: "t".into(),
                updated_at: None,
                version: Some(4),
                content_hash: Some("sha256:abc".into()),
                sample_input: None,
                tenant_id: None,
            })
            .await
            .unwrap();
        let stored = store
            .get("deny-def")
            .await
            .unwrap();
        manager.set_policy_definition_store(store);

        let attestation = manager
            .resolve_policy_attestation(Some("deny-def"))
            .await;
        assert_eq!(attestation.name.as_deref(), Some("Deny unknown callers"));
        assert_eq!(attestation.version, stored.version);
        assert_eq!(attestation.content_hash, stored.content_hash);
        assert_eq!(
            manager
                .resolve_policy_decision_evidence(Some("deny-def"))
                .await,
            (
                "Deny unknown callers".to_string(),
                attestation.version,
                attestation
                    .content_hash
                    .clone()
            ),
            "decision evidence agrees with the attestation"
        );
        assert_eq!(
            manager
                .resolve_policy_decision_evidence(Some("missing"))
                .await,
            ("missing".to_string(), None, None),
            "an unknown definition is named by its id"
        );
        assert_eq!(
            manager
                .resolve_policy_decision_evidence(None)
                .await,
            (crate::policies::SURFACE_POLICY_PACKAGE.to_string(), None, None),
            "no definition falls back to the Rego package"
        );

        assert_eq!(
            manager
                .resolve_policy_attestation(Some("missing"))
                .await,
            crate::policies::PolicyAttestation::default()
        );
        assert_eq!(
            manager
                .resolve_policy_attestation(None)
                .await,
            crate::policies::PolicyAttestation::default()
        );
    }
}
