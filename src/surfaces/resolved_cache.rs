//! Phase C — in-memory cache of pre-resolved per-variant
//! [`AgentSurface`] snapshots.
//!
//! Keyed by `surface_id`. Each entry holds the default snapshot plus one
//! snapshot per declared variant alias. Disabled aliases are kept so the
//! pipeline can later answer them with HTTP 503 instead of 404 (Phase D).
//!
//! Resolution work (`AgentSurface::resolve_variant`) runs once at write
//! time; request-time lookups are pure `Arc` clones from a `DashMap`.
//!
//! Lifecycle:
//! - Populated at startup from `AgentSurfaceStore::list_all`.
//! - Kept in sync by [`crate::identity::handlers::surfaces::apply_surface_change`].
//! - Authoritative for the request pipeline: the inbound handler resolves
//!   `(surface_id, alias)` against this cache to get the active surface.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use dashmap::DashMap;

use crate::config::agent_surface::AgentSurface;
use crate::config::agent_surface_variants::{VariantResolveError, VariantValidationError};

/// Pre-resolved snapshots for one surface — what the runtime should see
/// when a request selects this surface (default or a named variant).
#[derive(Debug, Clone)]
pub struct SurfaceSnapshots {
    /// Snapshot used when no `$alias` is present in the request URL.
    /// Equal to the base surface when no variants are configured.
    pub default: Arc<AgentSurface>,
    /// Pre-resolved snapshots for each enabled variant alias.
    pub by_alias: HashMap<String, Arc<AgentSurface>>,
    /// Aliases of variants that exist on the surface but are
    /// `enabled: false`. Selecting one of these is **not** an unknown
    /// alias — the pipeline must distinguish so it can return HTTP 503
    /// (intentionally switched off) rather than 404 (no such variant).
    pub disabled_aliases: HashSet<String>,
}

/// Why a [`ResolvedSurfaceCache::resolve`] call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The surface is not registered with the cache (deleted, inactive
    /// at startup, or never persisted).
    UnknownSurface(String),
    /// The surface exists but has no variant with the requested alias.
    UnknownAlias(String),
    /// The surface has a variant with the requested alias but it is
    /// `enabled: false`.
    DisabledAlias(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::UnknownSurface(id) => write!(f, "no surface '{id}' in resolved-surface cache"),
            Self::UnknownAlias(a) => write!(f, "no variant with alias '{a}' on this surface"),
            Self::DisabledAlias(a) => write!(f, "variant '{a}' is disabled"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Why a [`ResolvedSurfaceCache::upsert`] call failed.
#[derive(Debug, Clone)]
pub enum CacheUpsertError {
    /// The surface's `variants[]` failed structural validation
    /// (duplicate alias/id, bad alias grammar, dangling `default_variant_id`).
    Validation(VariantValidationError),
    /// Resolving one of the surface's variants failed even though
    /// validation passed. This indicates an internal inconsistency
    /// (`resolve_variant` and `validate_variants` should agree); the
    /// surface is left out of the cache so the request path will fall
    /// back rather than serve a stale snapshot.
    Resolve(VariantResolveError),
}

impl std::fmt::Display for CacheUpsertError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Validation(e) => write!(f, "surface variant validation failed: {e}"),
            Self::Resolve(e) => write!(f, "surface variant resolution failed: {e}"),
        }
    }
}

impl std::error::Error for CacheUpsertError {}

impl From<VariantValidationError> for CacheUpsertError {
    fn from(value: VariantValidationError) -> Self {
        Self::Validation(value)
    }
}

impl From<VariantResolveError> for CacheUpsertError {
    fn from(value: VariantResolveError) -> Self {
        Self::Resolve(value)
    }
}

/// Process-global resolved-surface cache. Cheap to clone (it's a single
/// [`Arc`] wrapping a [`DashMap`]).
#[derive(Debug, Default)]
pub struct ResolvedSurfaceCache {
    inner: DashMap<String, Arc<SurfaceSnapshots>>,
}

impl ResolvedSurfaceCache {
    pub fn new() -> Self {
        Self { inner: DashMap::new() }
    }

    /// Validate `surface.variants`, pre-resolve every snapshot, then
    /// replace the cache entry atomically. On any error nothing is
    /// inserted — the previous entry (if any) is left intact so the
    /// runtime keeps serving the last known-good snapshots.
    pub fn upsert(
        &self,
        surface: &AgentSurface,
    ) -> Result<(), CacheUpsertError> {
        surface.validate_variants()?;
        let snapshots = build_snapshots(surface)?;
        self.inner
            .insert(surface.surface_id.clone(), Arc::new(snapshots));
        Ok(())
    }

    /// Drop the cache entry for `surface_id`. No-op if absent.
    pub fn remove(
        &self,
        surface_id: &str,
    ) {
        self.inner.remove(surface_id);
    }

    /// Look up a pre-resolved snapshot by surface and optional alias.
    /// `alias = None` returns the default-variant snapshot.
    pub fn resolve(
        &self,
        surface_id: &str,
        alias: Option<&str>,
    ) -> Result<Arc<AgentSurface>, ResolveError> {
        let entry = self
            .inner
            .get(surface_id)
            .ok_or_else(|| ResolveError::UnknownSurface(surface_id.to_string()))?;
        let snaps = entry.value().clone();
        drop(entry);
        match alias {
            None => Ok(snaps.default.clone()),
            Some(a) => {
                if let Some(s) = snaps.by_alias.get(a) {
                    Ok(s.clone())
                } else if snaps
                    .disabled_aliases
                    .contains(a)
                {
                    Err(ResolveError::DisabledAlias(a.to_string()))
                } else {
                    Err(ResolveError::UnknownAlias(a.to_string()))
                }
            }
        }
    }

    /// Return the full snapshot bundle for a surface, if any.
    #[allow(dead_code)]
    pub fn snapshots(
        &self,
        surface_id: &str,
    ) -> Option<Arc<SurfaceSnapshots>> {
        self.inner
            .get(surface_id)
            .map(|e| e.value().clone())
    }

    /// Number of surfaces currently cached. For observability/tests.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if the cache holds no surfaces.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

fn build_snapshots(surface: &AgentSurface) -> Result<SurfaceSnapshots, CacheUpsertError> {
    let default = Arc::new(surface.resolve_variant(None)?);
    let mut by_alias = HashMap::with_capacity(surface.variants.len());
    let mut disabled_aliases = HashSet::new();
    for v in &surface.variants {
        if !v.enabled {
            disabled_aliases.insert(v.alias.clone());
            continue;
        }
        let resolved = surface.resolve_variant(Some(&v.alias))?;
        by_alias.insert(v.alias.clone(), Arc::new(resolved));
    }
    Ok(SurfaceSnapshots {
        default,
        by_alias,
        disabled_aliases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::{
        AccessPoint, AgentSurface, CallerContext, IdentityInjectionConfig, SurfaceProtocol, SurfaceStatus, Target,
    };
    use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant};

    fn base_surface(id: &str) -> AgentSurface {
        AgentSurface {
            surface_id: id.to_string(),
            tenant_id: None,
            name: id.to_string(),
            description: String::new(),
            status: SurfaceStatus::Active,
            agent_did: None,
            issuer_id: None,
            tags: Vec::new(),
            access_point: AccessPoint {
                name: None,
                listen_address: "127.0.0.1:9000".to_string(),
                route: format!("/{id}"),
                protocol: SurfaceProtocol::A2a,
                caller_authentication: None,
                caller_context: CallerContext::default(),
                identity_resolution: None,
                inbound_policy: None,
                rate_limit: None,
                extension_validation: None,
                trust_check_list: Vec::new(),
                header_metadata_mapping: None,
                trust_recorder: None,
                publish_to_did_document: false,
                supported_extensions: vec![],
                primary_extension: None,
                agent_card_path: None,
                response_custom_metadata: None,
                didwebvh_identity: None,
                terminate_trace_id: false,
                a2a: None,
            },
            target: Target {
                endpoint: "http://upstream.example/".to_string(),
                auth: None,
                policy: None,
                response_policy: None,
                payment_policy: None,
                mcp_tool_policies: vec![],
                mcp_tool_policies_enabled: false,
                mcp_tool_gating: None,
                networking: None,
                identity_injection: IdentityInjectionConfig::default(),
                workload_binding: None,
                extension_rules: None,
                custom_metadata: None,
                response_custom_metadata: None,
                trust_check_list: Vec::new(),
                mcp_proxy_id: None,
                a2a_proxy_id: None,
                fabric_target_name: None,
                mpp_auto_pay: false,
                mpp_auto_pay_max_amount: None,
            },
            transit: None,
            canvas: None,
            variants: Vec::new(),
            default_variant_id: None,
            outbound_credentials: Vec::new(),
            identity_slots: Default::default(),
            mcp_legacy_metadata_output: None,
            _retired_protocol_mode: Default::default(),
            mcp_http: None,
        }
    }

    fn variant(
        id: &str,
        alias: &str,
        enabled: bool,
        endpoint_override: Option<&str>,
    ) -> SurfaceVariant {
        let target = endpoint_override.map(|ep| crate::config::agent_surface_variants::TargetOverrides {
            endpoint: Some(ep.to_string()),
            ..Default::default()
        });
        SurfaceVariant {
            id: id.to_string(),
            alias: alias.to_string(),
            name: alias.to_string(),
            description: String::new(),
            enabled,
            overrides: SurfaceOverrides {
                complete: false,
                access_point: None,
                target,
                transit: None,
                identity_slots: None,
                outbound_credentials: None,
                canvas: None,
            },
        }
    }

    #[test]
    fn resolve_default_when_no_variants_returns_base_snapshot() {
        let cache = ResolvedSurfaceCache::new();
        cache
            .upsert(&base_surface("s1"))
            .unwrap();
        let snap = cache
            .resolve("s1", None)
            .unwrap();
        assert_eq!(snap.surface_id, "s1");
        assert_eq!(snap.target.endpoint, "http://upstream.example/");
    }

    #[test]
    fn resolve_default_when_variants_present_uses_default_variant_id() {
        let mut s = base_surface("s2");
        s.variants
            .push(variant("v1", "alpha", true, Some("http://alpha/")));
        s.variants
            .push(variant("v2", "beta", true, Some("http://beta/")));
        s.default_variant_id = Some("v2".to_string());
        let cache = ResolvedSurfaceCache::new();
        cache.upsert(&s).unwrap();
        let snap = cache
            .resolve("s2", None)
            .unwrap();
        assert_eq!(snap.target.endpoint, "http://beta/");
    }

    #[test]
    fn resolve_named_alias_returns_per_variant_snapshot() {
        let mut s = base_surface("s3");
        s.variants
            .push(variant("v1", "alpha", true, Some("http://alpha/")));
        s.default_variant_id = Some("v1".to_string());
        let cache = ResolvedSurfaceCache::new();
        cache.upsert(&s).unwrap();
        let snap = cache
            .resolve("s3", Some("alpha"))
            .unwrap();
        assert_eq!(snap.target.endpoint, "http://alpha/");
    }

    #[test]
    fn resolve_disabled_alias_returns_disabled_error() {
        let mut s = base_surface("s4");
        s.variants
            .push(variant("v1", "alpha", false, Some("http://alpha/")));
        s.variants
            .push(variant("v2", "beta", true, None));
        s.default_variant_id = Some("v2".to_string());
        let cache = ResolvedSurfaceCache::new();
        cache.upsert(&s).unwrap();
        assert_eq!(
            cache
                .resolve("s4", Some("alpha"))
                .unwrap_err(),
            ResolveError::DisabledAlias("alpha".to_string())
        );
    }

    #[test]
    fn resolve_unknown_alias_returns_unknown_error() {
        let mut s = base_surface("s5");
        s.variants
            .push(variant("v1", "alpha", true, None));
        s.default_variant_id = Some("v1".to_string());
        let cache = ResolvedSurfaceCache::new();
        cache.upsert(&s).unwrap();
        assert_eq!(
            cache
                .resolve("s5", Some("gamma"))
                .unwrap_err(),
            ResolveError::UnknownAlias("gamma".to_string())
        );
    }

    #[test]
    fn resolve_unknown_surface_returns_unknown_error() {
        let cache = ResolvedSurfaceCache::new();
        assert_eq!(
            cache
                .resolve("missing", None)
                .unwrap_err(),
            ResolveError::UnknownSurface("missing".to_string())
        );
    }

    #[test]
    fn upsert_rejects_invalid_alias_grammar() {
        let mut s = base_surface("s6");
        s.variants
            .push(variant("v1", "BAD ALIAS!", true, None));
        s.default_variant_id = Some("v1".to_string());
        let cache = ResolvedSurfaceCache::new();
        let err = cache.upsert(&s).unwrap_err();
        matches!(err, CacheUpsertError::Validation(_));
        // Cache must remain empty so the runtime falls back rather than
        // serving a half-built snapshot.
        assert!(cache.is_empty());
    }

    #[test]
    fn upsert_failure_preserves_previous_entry() {
        let mut s = base_surface("s7");
        s.variants
            .push(variant("v1", "alpha", true, Some("http://alpha/")));
        s.default_variant_id = Some("v1".to_string());
        let cache = ResolvedSurfaceCache::new();
        cache.upsert(&s).unwrap();
        assert_eq!(cache.len(), 1);

        let mut bad = s.clone();
        bad.variants
            .push(variant("v2", "alpha", true, None)); // duplicate alias
        let err = cache
            .upsert(&bad)
            .unwrap_err();
        matches!(err, CacheUpsertError::Validation(_));

        // Previous good snapshot still resolvable.
        let snap = cache
            .resolve("s7", Some("alpha"))
            .unwrap();
        assert_eq!(snap.target.endpoint, "http://alpha/");
    }

    #[test]
    fn remove_drops_entry() {
        let cache = ResolvedSurfaceCache::new();
        cache
            .upsert(&base_surface("s8"))
            .unwrap();
        assert_eq!(cache.len(), 1);
        cache.remove("s8");
        assert_eq!(cache.len(), 0);
        assert!(matches!(cache.resolve("s8", None), Err(ResolveError::UnknownSurface(_))));
    }

    #[test]
    fn upsert_replaces_existing_entry_atomically() {
        let cache = ResolvedSurfaceCache::new();
        let mut s = base_surface("s9");
        s.target.endpoint = "http://v1/".to_string();
        cache.upsert(&s).unwrap();
        s.target.endpoint = "http://v2/".to_string();
        cache.upsert(&s).unwrap();
        let snap = cache
            .resolve("s9", None)
            .unwrap();
        assert_eq!(snap.target.endpoint, "http://v2/");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn snapshots_tracks_disabled_aliases_separately() {
        let mut s = base_surface("s10");
        s.variants
            .push(variant("v1", "alpha", true, None));
        s.variants
            .push(variant("v2", "beta", false, None));
        s.default_variant_id = Some("v1".to_string());
        let cache = ResolvedSurfaceCache::new();
        cache.upsert(&s).unwrap();
        let snaps = cache
            .snapshots("s10")
            .unwrap();
        assert!(
            snaps
                .by_alias
                .contains_key("alpha")
        );
        assert!(
            !snaps
                .by_alias
                .contains_key("beta")
        );
        assert!(
            snaps
                .disabled_aliases
                .contains("beta")
        );
    }
}
