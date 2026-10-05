//! Resource-limit configuration loader for `limits.json`.
//!
//! Constrains the number of each kind of entity the appliance will hold
//! (secrets, surfaces, policies, users, …) so that reaching a limit prevents
//! further entities of that dimension from being created. Limits are addressed
//! with dot-notation keys, each mapping to a definition (operator-facing name +
//! description + the integer cap), mirroring the shape of `rbac.json`.
//!
//! The configuration is loaded once at startup, held in a process-global, and
//! consulted at every entity-creation enforcement point. When the file is
//! missing — or a specific dimension is not listed — the limit defaults to
//! [`DEFAULT_LIMIT`] (one million), which is effectively unconstrained.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, RwLock};

/// Limit applied to any dimension that is not present in `limits.json` (or when
/// the file is absent). Large enough to be effectively unconstrained.
pub const DEFAULT_LIMIT: u64 = 1_000_000;

/// A single configured resource limit: operator-facing `name` and `description`
/// (surfaced in the dashboard's Limits view) plus the integer `limit` cap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitDefinition {
    /// Operator-facing display name (e.g. "Secrets").
    pub name: String,
    /// Operator-facing description of what the dimension counts.
    pub description: String,
    /// Maximum number of entities allowed for the dimension.
    pub limit: u64,
}

/// Parsed contents of `limits.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Dot-notation dimension key -> its definition (name, description, limit).
    #[serde(default)]
    pub limits: HashMap<String, LimitDefinition>,
}

/// Error returned when creating one more entity would breach a configured limit.
#[derive(Debug, Clone)]
pub struct LimitExceeded {
    /// The dot-notation dimension that was exceeded (e.g. `surfaces.agent`).
    pub dimension: String,
    /// The configured maximum for that dimension.
    pub limit: u64,
    /// The number of entities that already exist for that dimension.
    pub current: u64,
}

impl LimitExceeded {
    /// Operator-facing message suitable for returning in an API error body.
    pub fn message(&self) -> String {
        format!(
            "Appliance limit reached for '{}': {} of {} in use. Upgrade your appliance tier to add more.",
            self.dimension, self.current, self.limit
        )
    }
}

impl std::fmt::Display for LimitExceeded {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for LimitExceeded {}

impl LimitsConfig {
    /// Returns the configured limit for `key`, or [`DEFAULT_LIMIT`] when the
    /// dimension is not listed.
    pub fn limit(
        &self,
        key: &str,
    ) -> u64 {
        self.limits
            .get(key)
            .map(|d| d.limit)
            .unwrap_or(DEFAULT_LIMIT)
    }

    /// Checks whether one more entity may be added to `key` given the current
    /// count. Returns [`LimitExceeded`] when `current_count` has already
    /// reached (or somehow surpassed) the configured limit.
    pub fn check_can_add(
        &self,
        key: &str,
        current_count: usize,
    ) -> Result<(), LimitExceeded> {
        let limit = self.limit(key);
        if current_count as u64 >= limit {
            Err(LimitExceeded {
                dimension: key.to_string(),
                limit,
                current: current_count as u64,
            })
        } else {
            Ok(())
        }
    }
}

/// Load resource-limit configuration from `limits.json`.
///
/// A missing file yields an empty [`LimitsConfig`], so every dimension defaults
/// to [`DEFAULT_LIMIT`]. A malformed file is logged and likewise treated as
/// unconstrained rather than failing appliance startup.
pub fn load_limits_config<P: AsRef<Path>>(path: P) -> LimitsConfig {
    let path = path.as_ref();
    match std::fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<LimitsConfig>(&content) {
            Ok(config) => {
                tracing::info!("Loaded {} resource-limit dimension(s) from {}", config.limits.len(), path.display());
                config
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to parse limits config from {}: {} — treating all dimensions as unconstrained",
                    path.display(),
                    e
                );
                LimitsConfig::default()
            }
        },
        Err(_) => {
            tracing::info!(
                "Limits config not found at {} — all dimensions unconstrained (limit {})",
                path.display(),
                DEFAULT_LIMIT
            );
            LimitsConfig::default()
        }
    }
}

static GLOBAL_LIMITS: OnceLock<LimitsConfig> = OnceLock::new();

/// Install the process-global limits configuration. First writer wins; later
/// calls are ignored (startup-only, mirroring the RBAC/encryption globals).
pub fn init_global_limits(config: LimitsConfig) {
    let _ = GLOBAL_LIMITS.set(config);
}

/// Access the process-global limits configuration. Before initialisation this
/// returns an empty (unconstrained) configuration.
pub fn global_limits() -> &'static LimitsConfig {
    GLOBAL_LIMITS.get_or_init(LimitsConfig::default)
}

// ── Live count registry ─────────────────────────────────────────────────────
//
// Enforcement is count-based: to know whether one more entity may be added we
// must count the entities that already exist. Rather than thread every sibling
// store through every router, each store registers a small async counter for
// its leaf dimension at startup. An umbrella dimension's live total is then
// either a directly-registered counter (single-store groups such as `surfaces`
// and `policies`) or the sum of its registered children (multi-store groups
// such as `secrets`, `credentials`, `connections`, and `proxies`).

type CountFuture = Pin<Box<dyn Future<Output = usize> + Send>>;
type CountFn = Arc<dyn Fn() -> CountFuture + Send + Sync>;

static COUNTERS: OnceLock<RwLock<HashMap<String, CountFn>>> = OnceLock::new();

fn counters() -> &'static RwLock<HashMap<String, CountFn>> {
    COUNTERS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register a live counter for a leaf dimension (e.g. `secrets.apikeys`) or an
/// umbrella total (e.g. `surfaces`). The closure is invoked fresh on every
/// enforcement check so counts always reflect current storage. Last registration
/// for a given dimension wins.
pub fn register_counter<F, Fut>(
    dimension: &str,
    counter: F,
) where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = usize> + Send + 'static,
{
    let f: CountFn = Arc::new(move || Box::pin(counter()));
    counters()
        .write()
        .unwrap()
        .insert(dimension.to_string(), f);
}

/// Current count for a dimension that has a directly-registered counter.
async fn counted(dimension: &str) -> Option<usize> {
    let f = counters()
        .read()
        .unwrap()
        .get(dimension)
        .cloned();
    match f {
        Some(f) => Some(f().await),
        None => None,
    }
}

/// Live total for an umbrella dimension: a directly-registered counter when one
/// exists, otherwise the sum of all registered child dimensions (`parent.*`).
async fn umbrella_count(parent: &str) -> Option<usize> {
    if let Some(direct) = counted(parent).await {
        return Some(direct);
    }
    let prefix = format!("{parent}.");
    let children: Vec<CountFn> = {
        let guard = counters().read().unwrap();
        guard
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone())
            .collect()
    };
    if children.is_empty() {
        return None;
    }
    let mut total = 0;
    for c in children {
        total += c().await;
    }
    Some(total)
}

/// Current live count for a dimension: a leaf's own registered counter, or an
/// umbrella's summed children. Returns 0 when no counter is registered.
pub async fn current_count(dimension: &str) -> usize {
    umbrella_count(dimension)
        .await
        .unwrap_or(0)
}

/// Emit a single, structured error when a create is rejected by a configured
/// limit, so operators can see exactly which dimension blocked the request.
pub fn log_limit_reached(
    requested: &str,
    e: &LimitExceeded,
) {
    tracing::error!(
        target: "appliance_limits",
        requested_dimension = %requested,
        blocked_dimension = %e.dimension,
        limit = e.limit,
        current = e.current,
        "Appliance resource limit reached — rejecting create for '{}': dimension '{}' has {} of {} in use",
        requested,
        e.dimension,
        e.current,
        e.limit
    );
}

/// Enforce the configured limits for adding one entity to `leaf`.
///
/// Checks the leaf dimension's own limit and, when `leaf` is dotted, its
/// umbrella parent as well — so both "no more than N of this type" and "no more
/// than M in total" hold simultaneously. Dimensions with no registered counter
/// are skipped (fail-open), matching the unconstrained default for unconfigured
/// limits.
pub async fn enforce_add(leaf: &str) -> std::result::Result<(), LimitExceeded> {
    let result = enforce_add_with(global_limits(), leaf).await;
    if let Err(ref e) = result {
        log_limit_reached(leaf, e);
    }
    result
}

/// [`enforce_add`] against an explicit configuration (testable without touching
/// the process-global limits).
async fn enforce_add_with(
    limits: &LimitsConfig,
    leaf: &str,
) -> std::result::Result<(), LimitExceeded> {
    if let Some(count) = counted(leaf).await {
        limits.check_can_add(leaf, count)?;
    }
    if let Some((parent, _)) = leaf.rsplit_once('.')
        && let Some(total) = umbrella_count(parent).await
    {
        limits.check_can_add(parent, total)?;
    }
    Ok(())
}

/// Enforce only the leaf dimension's own limit, without the umbrella rollup.
///
/// Used on the type-change update path: re-typing an existing entity (e.g.
/// changing a policy definition's `policy_type`) does not change the umbrella
/// total, but it does add one to the destination type's count. The entity being
/// re-typed is not yet part of that destination count, so this behaves like a
/// create against the leaf alone.
pub async fn enforce_leaf(leaf: &str) -> std::result::Result<(), LimitExceeded> {
    let result = enforce_leaf_with(global_limits(), leaf).await;
    if let Err(ref e) = result {
        log_limit_reached(leaf, e);
    }
    result
}

async fn enforce_leaf_with(
    limits: &LimitsConfig,
    leaf: &str,
) -> std::result::Result<(), LimitExceeded> {
    if let Some(count) = counted(leaf).await {
        limits.check_can_add(leaf, count)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(limit: u64) -> LimitDefinition {
        LimitDefinition {
            name: String::new(),
            description: String::new(),
            limit,
        }
    }

    #[test]
    fn missing_key_defaults_to_one_million() {
        let cfg = LimitsConfig::default();
        assert_eq!(cfg.limit("surfaces"), DEFAULT_LIMIT);
        assert!(
            cfg.check_can_add("surfaces", 999)
                .is_ok()
        );
    }

    #[test]
    fn enforces_configured_limit() {
        let mut limits = HashMap::new();
        limits.insert("integrations".to_string(), def(3));
        let cfg = LimitsConfig { limits };
        assert!(
            cfg.check_can_add("integrations", 2)
                .is_ok()
        );
        let err = cfg
            .check_can_add("integrations", 3)
            .expect_err("at-limit must be rejected");
        assert_eq!(err.limit, 3);
        assert_eq!(err.current, 3);
        assert!(
            cfg.check_can_add("integrations", 5)
                .is_err()
        );
    }

    #[test]
    fn zero_limit_blocks_all_creates() {
        let mut limits = HashMap::new();
        limits.insert("integrations".to_string(), def(0));
        let cfg = LimitsConfig { limits };
        assert!(
            cfg.check_can_add("integrations", 0)
                .is_err()
        );
    }

    #[test]
    fn parses_object_form_json() {
        let json = r#"{ "limits": {
            "secrets": { "name": "Secrets", "description": "All secrets", "limit": 10 },
            "secrets.secret": { "name": "Vault Secrets", "description": "Vault", "limit": 5 },
            "surfaces.agent": { "name": "Agent Surfaces", "description": "Surfaces", "limit": 5 }
        } }"#;
        let cfg: LimitsConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.limit("secrets"), 10);
        assert_eq!(cfg.limit("secrets.secret"), 5);
        assert_eq!(cfg.limit("surfaces.agent"), 5);
        assert_eq!(cfg.limit("unlisted"), DEFAULT_LIMIT);
        let secrets = cfg
            .limits
            .get("secrets")
            .unwrap();
        assert_eq!(secrets.name, "Secrets");
        assert_eq!(secrets.description, "All secrets");
    }

    #[test]
    fn missing_file_is_unconstrained() {
        let cfg = load_limits_config("/nonexistent/path/limits.json");
        assert!(cfg.limits.is_empty());
        assert_eq!(cfg.limit("anything"), DEFAULT_LIMIT);
    }

    #[test]
    fn loads_limits_from_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tg_limits_test_{}.json", std::process::id()));
        std::fs::write(&path, r#"{ "limits": { "proxies": { "name": "Proxies", "description": "d", "limit": 2 }, "surfaces.agent": { "name": "Surfaces", "description": "d", "limit": 1 } } }"#).unwrap();
        let cfg = load_limits_config(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(cfg.limit("proxies"), 2);
        assert_eq!(cfg.limit("surfaces.agent"), 1);
        assert!(
            cfg.check_can_add("proxies", 2)
                .is_err()
        );
        assert_eq!(cfg.limit("missing"), DEFAULT_LIMIT);
    }

    #[test]
    fn malformed_file_is_unconstrained() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tg_limits_bad_{}.json", std::process::id()));
        std::fs::write(&path, "{ not valid json").unwrap();
        let cfg = load_limits_config(&path);
        std::fs::remove_file(&path).ok();
        assert!(cfg.limits.is_empty());
        assert_eq!(cfg.limit("proxies"), DEFAULT_LIMIT);
    }

    #[tokio::test]
    async fn enforce_add_checks_leaf_and_umbrella() {
        register_counter("t_creds.jwt", || async { 2 });
        register_counter("t_creds.providers", || async { 1 });
        let mut limits = HashMap::new();
        limits.insert("t_creds".to_string(), def(5));
        limits.insert("t_creds.jwt".to_string(), def(2));
        let cfg = LimitsConfig { limits };
        // jwt leaf at 2 has reached its own cap of 2 → rejected.
        assert!(
            enforce_add_with(&cfg, "t_creds.jwt")
                .await
                .is_err()
        );
        // providers leaf is unlimited and the umbrella total (3) is under 5 → allowed.
        assert!(
            enforce_add_with(&cfg, "t_creds.providers")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn enforce_add_blocks_when_umbrella_total_reached() {
        register_counter("t_conn.gw", || async { 1 });
        register_counter("t_conn.med", || async { 1 });
        register_counter("t_conn.cp", || async { 1 });
        let mut limits = HashMap::new();
        limits.insert("t_conn".to_string(), def(3));
        let cfg = LimitsConfig { limits };
        // The leaf has no per-type cap, but the cross-store umbrella total (3)
        // has reached the limit of 3, so no more may be added.
        let err = enforce_add_with(&cfg, "t_conn.gw")
            .await
            .expect_err("umbrella total must block");
        assert_eq!(err.dimension, "t_conn");
        assert_eq!(err.current, 3);
    }

    #[tokio::test]
    async fn enforce_add_counts_trust_registries_as_connections() {
        register_counter("t_conn_tr.gateways", || async { 1 });
        register_counter("t_conn_tr.mediators", || async { 1 });
        register_counter("t_conn_tr.connectionpoints", || async { 1 });
        register_counter("t_conn_tr.trustregistries", || async { 1 });
        let mut limits = HashMap::new();
        limits.insert("t_conn_tr".to_string(), def(4));
        limits.insert("t_conn_tr.trustregistries".to_string(), def(2));
        let cfg = LimitsConfig { limits };

        let err = enforce_add_with(&cfg, "t_conn_tr.trustregistries")
            .await
            .expect_err("trust registry must count toward the connections umbrella");
        assert_eq!(err.dimension, "t_conn_tr");
        assert_eq!(err.current, 4);

        let mut limits = HashMap::new();
        limits.insert("t_conn_tr".to_string(), def(5));
        limits.insert("t_conn_tr.trustregistries".to_string(), def(1));
        let cfg = LimitsConfig { limits };
        let err = enforce_add_with(&cfg, "t_conn_tr.trustregistries")
            .await
            .expect_err("trust registry leaf cap must still be enforced");
        assert_eq!(err.dimension, "t_conn_tr.trustregistries");
        assert_eq!(err.current, 1);
    }

    #[tokio::test]
    async fn direct_umbrella_counter_takes_precedence_over_children() {
        // A single-store umbrella registers its own total (all types), which
        // must win over summing only the sub-typed children.
        register_counter("t_surf", || async { 7 });
        register_counter("t_surf.agent", || async { 7 });
        let mut limits = HashMap::new();
        limits.insert("t_surf".to_string(), def(5));
        let cfg = LimitsConfig { limits };
        let err = enforce_add_with(&cfg, "t_surf.agent")
            .await
            .expect_err("direct umbrella total must block");
        assert_eq!(err.dimension, "t_surf");
        assert_eq!(err.current, 7);
    }

    #[tokio::test]
    async fn enforce_leaf_ignores_umbrella_total() {
        // Type-change path: the umbrella is already full but the destination
        // leaf still has room, so a re-type is allowed.
        register_counter("t_pol.fabric", || async { 5 });
        register_counter("t_pol.agent", || async { 0 });
        let mut limits = HashMap::new();
        limits.insert("t_pol".to_string(), def(5));
        limits.insert("t_pol.agent".to_string(), def(2));
        limits.insert("t_pol.fabric".to_string(), def(5));
        let cfg = LimitsConfig { limits };
        // Umbrella total (5) is at the cap of 5, but enforce_leaf only checks the
        // destination leaf (agent, 0 of 2) → allowed.
        assert!(
            enforce_leaf_with(&cfg, "t_pol.agent")
                .await
                .is_ok()
        );
        // The destination leaf itself is still enforced.
        let err = enforce_leaf_with(&cfg, "t_pol.fabric")
            .await
            .expect_err("leaf at cap must block");
        assert_eq!(err.dimension, "t_pol.fabric");
        assert_eq!(err.current, 5);
    }

    #[tokio::test]
    async fn current_count_reports_leaf_and_umbrella() {
        register_counter("t_cc.a", || async { 2 });
        register_counter("t_cc.b", || async { 3 });
        // Leaf uses its own registered counter.
        assert_eq!(current_count("t_cc.a").await, 2);
        // Umbrella with no direct counter sums its children.
        assert_eq!(current_count("t_cc").await, 5);
        // Unknown dimension with no counter reports 0.
        assert_eq!(current_count("t_cc.missing").await, 0);
    }
}
