//! Single-use guard for ID-JAG redemption.
//!
//! An ID-JAG is a short-lived, single-use authorization grant (RFC 8693 /
//! `draft-ietf-oauth-identity-assertion-authz-grant`). Once redeemed for an
//! access token it must not be redeemable again within its validity window.
//! [`ReplayGuard`] records each grant's `jti` until its `exp`, rejecting a
//! second presentation of the same `jti`.
//!
//! In-memory and process-local (like the rest of the runtime caches). Entries
//! self-expire logically — a `jti` only blocks while its recorded expiry is in
//! the future — and are pruned opportunistically so memory stays bounded.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum McpReplayConfig {
    Embedded { capacity: usize },
    Dynamodb { table: String },
}

impl Default for McpReplayConfig {
    fn default() -> Self {
        Self::Embedded { capacity: 100_000 }
    }
}

impl McpReplayConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn validate(&self) -> Result<(), crate::sts::errors::StsError> {
        let valid = match self {
            Self::Embedded { capacity } => (1..=100_000).contains(capacity),
            Self::Dynamodb { table } => {
                (3..=255).contains(&table.len())
                    && table
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            }
        };
        if valid {
            Ok(())
        } else {
            Err(crate::sts::errors::StsError::InvalidRequest("Invalid MCP replay storage configuration".into()))
        }
    }
}

pub enum McpReplay {
    Embedded { entries: std::sync::Mutex<HashMap<[u8; 32], u64>>, capacity: usize },
    Dynamodb { client: aws_sdk_dynamodb::Client, table: String },
}

impl std::fmt::Debug for McpReplay {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Embedded { .. } => "McpReplay::Embedded",
            Self::Dynamodb { .. } => "McpReplay::Dynamodb",
        })
    }
}

impl McpReplay {
    pub fn new(
        config: &McpReplayConfig,
        client: Option<aws_sdk_dynamodb::Client>,
    ) -> Result<Self, crate::sts::errors::StsError> {
        config.validate()?;
        Ok(match config {
            McpReplayConfig::Embedded { capacity } => Self::Embedded {
                entries: std::sync::Mutex::new(HashMap::new()),
                capacity: *capacity,
            },
            McpReplayConfig::Dynamodb { table } => Self::Dynamodb {
                client: client.ok_or_else(|| {
                    crate::sts::errors::StsError::ServerError("MCP replay database client unavailable".into())
                })?,
                table: table.clone(),
            },
        })
    }

    pub async fn record_unique(
        &self,
        profile_issuer: &str,
        grant_issuer: &str,
        jti: &str,
        expiry: u64,
        now: u64,
    ) -> Result<bool, crate::sts::errors::StsError> {
        use crate::sts::errors::StsError;

        if profile_issuer.is_empty()
            || profile_issuer.len() > 4096
            || grant_issuer.is_empty()
            || grant_issuer.len() > 4096
            || jti.is_empty()
            || jti.len() > 1024
            || expiry
                .checked_sub(now)
                .is_none_or(|ttl| ttl == 0 || ttl > 900)
        {
            return Err(StsError::InvalidGrant("MCP ID-JAG identity or lifetime is invalid".into()));
        }
        let binding = serde_json_canonicalizer::to_vec(&(profile_issuer, grant_issuer, jti))
            .map_err(|_| StsError::ServerError("MCP replay key failed".into()))?;
        let digest: [u8; 32] = Sha256::digest(binding).into();
        match self {
            Self::Embedded { entries, capacity } => {
                let mut entries = entries
                    .lock()
                    .map_err(|_| StsError::ServerError("MCP replay storage unavailable".into()))?;
                entries.retain(|_, expiry| *expiry > now);
                if entries.contains_key(&digest) {
                    return Ok(false);
                }
                if entries.len() >= *capacity {
                    return Err(StsError::ServerError("MCP replay storage capacity reached".into()));
                }
                entries.insert(digest, expiry);
                Ok(true)
            }
            Self::Dynamodb { client, table } => {
                use crate::storage::dynamodb_generic_repository::{PK, SK, object_key};
                use aws_sdk_dynamodb::types::AttributeValue;

                let (partition, sort) = object_key("StsMcpReplay", &hex::encode(digest));
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    client
                        .put_item()
                        .table_name(table)
                        .item(PK, AttributeValue::S(partition))
                        .item(SK, AttributeValue::S(sort))
                        .item("expires_at", AttributeValue::N(expiry.to_string()))
                        .condition_expression("attribute_not_exists(#pk) OR #expiry <= :now")
                        .expression_attribute_names("#pk", PK)
                        .expression_attribute_names("#expiry", "expires_at")
                        .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
                        .send(),
                )
                .await
                .map_err(|_| StsError::ServerError("MCP replay storage timed out".into()))?;
                match result {
                    Ok(_) => Ok(true),
                    Err(error)
                        if error
                            .as_service_error()
                            .is_some_and(|error| error.is_conditional_check_failed_exception()) =>
                    {
                        Ok(false)
                    }
                    Err(_) => Err(StsError::ServerError("MCP replay storage unavailable".into())),
                }
            }
        }
    }
}

/// Single-use enforcement for ID-JAG redemption. An implementation records each
/// grant's `jti` until its `exp` and rejects a second presentation of the same
/// `jti` within the validity window.
pub trait ReplayProtection: Send + Sync {
    /// Atomically record `jti` as used until `exp`. Returns `true` when newly
    /// recorded (first use, or a prior record that had already expired) and
    /// `false` when `jti` is already recorded and still valid — i.e. a replay.
    fn record_unique(
        &self,
        jti: &str,
        exp: u64,
        now: u64,
    ) -> bool;
}

/// The built-in replay-protection backend name.
pub const IN_PROCESS_BACKEND: &str = "in_process";

/// Factory that constructs a replay-protection backend on demand.
pub type ReplayBackendFactory = Arc<dyn Fn() -> Arc<dyn ReplayProtection> + Send + Sync>;

fn backend_registry() -> &'static RwLock<HashMap<String, ReplayBackendFactory>> {
    static REGISTRY: OnceLock<RwLock<HashMap<String, ReplayBackendFactory>>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Register a replay-protection backend under `name`, selectable via the
/// gateway configuration's backend name. A later registration for the same name
/// replaces the earlier one.
#[allow(dead_code)]
pub fn register_replay_backend(
    name: &str,
    factory: ReplayBackendFactory,
) {
    if let Ok(mut reg) = backend_registry().write() {
        reg.insert(name.to_string(), factory);
    }
}

/// Build the replay-protection backend for the configured `name`, falling back
/// to the in-process backend when no backend is registered for that name.
pub fn build_replay_backend(name: &str) -> Arc<dyn ReplayProtection> {
    if name != IN_PROCESS_BACKEND
        && let Some(factory) = backend_registry()
            .read()
            .ok()
            .and_then(|reg| reg.get(name).cloned())
    {
        return factory();
    }
    if name != IN_PROCESS_BACKEND {
        tracing::warn!(backend = name, "no replay-protection backend registered for name; using in-process");
    }
    Arc::new(ReplayGuard::new())
}

/// Soft cap on retained `jti` entries. When exceeded, expired entries are swept
/// on the next record. ID-JAG TTLs are short (seconds), so the live set is tiny
/// in practice; the cap only bounds pathological growth.
const PRUNE_THRESHOLD: usize = 100_000;

/// Records recently-seen single-use token ids to reject replays.
#[derive(Default)]
pub struct ReplayGuard {
    /// `jti` → expiry (unix seconds). An entry blocks replay while `exp > now`.
    seen: DashMap<String, u64>,
    inserts: AtomicUsize,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every entry whose recorded expiry is at or before `now`.
    pub fn prune(
        &self,
        now: u64,
    ) {
        self.seen
            .retain(|_, exp| *exp > now);
    }

    /// Number of currently recorded ids.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether no ids are currently recorded.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl ReplayProtection for ReplayGuard {
    /// Atomically record `jti` as used until `exp`. Returns `true` when the id
    /// was previously unseen (or its prior record had already expired) and is
    /// now recorded; returns `false` when `jti` is already recorded and still
    /// valid — i.e. a replay.
    fn record_unique(
        &self,
        jti: &str,
        exp: u64,
        now: u64,
    ) -> bool {
        let accepted = match self
            .seen
            .entry(jti.to_string())
        {
            // A still-valid prior record ⇒ replay. An expired record is refreshed.
            Entry::Occupied(mut occupied) => {
                if *occupied.get() > now {
                    false
                } else {
                    occupied.insert(exp);
                    true
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(exp);
                true
            }
        };

        if accepted
            && self
                .inserts
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
                .is_multiple_of(1024)
            && self.seen.len() > PRUNE_THRESHOLD
        {
            self.prune(now);
        }
        accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mcp_replay_is_bounded_issuer_scoped_and_atomic() {
        let replay = Arc::new(McpReplay::new(&McpReplayConfig::Embedded { capacity: 2 }, None).unwrap());
        let (first, second) = tokio::join!(
            replay.record_unique("https://gateway.example/oauth2/mcp", "https://idp.example", "grant", 100, 10),
            replay.record_unique("https://gateway.example/oauth2/mcp", "https://idp.example", "grant", 100, 10),
        );
        assert_eq!(usize::from(first.unwrap()) + usize::from(second.unwrap()), 1);
        assert!(
            replay
                .record_unique("https://gateway.example/oauth2/mcp", "https://other.example", "grant", 100, 10)
                .await
                .unwrap()
        );
        assert!(
            replay
                .record_unique("https://gateway.example/oauth2/mcp", "https://idp.example", "third", 100, 10)
                .await
                .is_err()
        );
        assert!(
            replay
                .record_unique("https://gateway.example/oauth2/mcp", "https://idp.example", "third", 200, 100)
                .await
                .unwrap()
        );
        assert!(
            replay
                .record_unique("https://gateway.example/oauth2/mcp", "https://idp.example", "long", 2000, 100)
                .await
                .is_err()
        );
        assert!(McpReplay::new(&McpReplayConfig::Dynamodb { table: "replays".into() }, None).is_err());
    }

    #[test]
    fn first_use_is_accepted() {
        let guard = ReplayGuard::new();
        assert!(guard.record_unique("jti-1", 100, 10));
    }

    #[test]
    fn immediate_replay_is_rejected() {
        let guard = ReplayGuard::new();
        assert!(guard.record_unique("jti-1", 100, 10));
        assert!(!guard.record_unique("jti-1", 100, 10), "second use of the same jti must be rejected");
    }

    #[test]
    fn distinct_ids_are_independent() {
        let guard = ReplayGuard::new();
        assert!(guard.record_unique("jti-1", 100, 10));
        assert!(guard.record_unique("jti-2", 100, 10), "a different jti must be accepted");
    }

    #[test]
    fn expired_record_can_be_reused() {
        let guard = ReplayGuard::new();
        assert!(guard.record_unique("jti-1", 100, 10));
        // At now=150 the prior record (exp=100) has expired, so the id is free again.
        assert!(guard.record_unique("jti-1", 300, 150), "an expired record must not block a fresh grant");
    }

    #[test]
    fn prune_drops_expired_entries() {
        let guard = ReplayGuard::new();
        assert!(guard.record_unique("a", 100, 10));
        assert!(guard.record_unique("b", 500, 10));
        guard.prune(200);
        assert_eq!(guard.len(), 1, "only the unexpired entry remains");
        // The pruned id is redeemable again; the still-valid one is not.
        assert!(guard.record_unique("a", 600, 200));
        assert!(!guard.record_unique("b", 600, 200));
    }

    #[test]
    fn unknown_backend_falls_back_to_in_process() {
        let backend = build_replay_backend("does-not-exist");
        assert!(backend.record_unique("jti-x", 100, 10));
        assert!(!backend.record_unique("jti-x", 100, 10), "fallback backend must still enforce single-use");
    }

    #[test]
    fn registered_backend_is_selected() {
        register_replay_backend("test-backend", Arc::new(|| Arc::new(ReplayGuard::new())));
        let backend = build_replay_backend("test-backend");
        assert!(backend.record_unique("jti-y", 100, 10));
    }
}
