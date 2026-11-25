//! Single-use guard for ID-JAG redemption.
//!
//! An ID-JAG is a short-lived, single-use authorization grant (RFC 8693 /
//! `draft-ietf-oauth-identity-assertion-authz-grant`). Once redeemed for an
//! access token it must not be redeemable again within its validity window.
//! Each redemption records a digest of the grant's issuer and `jti` until the
//! grant's `exp` in the single-use store
//! ([`crate::storage::single_use`]), so a replay is refused across restarts
//! and, with a shared store, across nodes.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage::single_use::{Namespace, SingleUseStore};
use crate::sts::errors::StsError;

/// `sts.mcp_replay`. `Embedded` records MCP ID-JAG redemptions in the
/// single-use store; its `capacity` is still validated but no longer bounds
/// anything.
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

    pub fn validate(&self) -> Result<(), StsError> {
        let valid = match self {
            Self::Embedded { capacity } => (1..=100_000).contains(capacity),
            Self::Dynamodb { table } => crate::storage::single_use::is_valid_table_name(table),
        };
        if valid {
            Ok(())
        } else {
            Err(StsError::InvalidRequest("Invalid MCP replay storage configuration".into()))
        }
    }
}

pub enum McpReplay {
    Embedded(Arc<SingleUseStore>),
    Dynamodb { client: aws_sdk_dynamodb::Client, table: String },
}

impl std::fmt::Debug for McpReplay {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Embedded(_) => "McpReplay::Embedded",
            Self::Dynamodb { .. } => "McpReplay::Dynamodb",
        })
    }
}

impl McpReplay {
    pub fn new(
        config: &McpReplayConfig,
        client: Option<aws_sdk_dynamodb::Client>,
    ) -> Result<Self, StsError> {
        config.validate()?;
        Ok(match config {
            McpReplayConfig::Embedded { .. } => Self::Embedded(
                crate::storage::single_use::global()
                    .map_err(|_| StsError::ServerError("MCP replay storage unavailable".into()))?,
            ),
            McpReplayConfig::Dynamodb { table } => Self::Dynamodb {
                client: client.ok_or_else(|| StsError::ServerError("MCP replay database client unavailable".into()))?,
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
        max_lifetime_secs: u64,
    ) -> Result<bool, StsError> {
        if profile_issuer.is_empty()
            || profile_issuer.len() > 4096
            || grant_issuer.is_empty()
            || grant_issuer.len() > 4096
            || jti.is_empty()
            || jti.len() > 1024
            || expiry
                .checked_sub(now)
                .is_none_or(|ttl| ttl == 0 || ttl > max_lifetime_secs)
        {
            return Err(StsError::InvalidGrant("MCP ID-JAG identity or lifetime is invalid".into()));
        }
        let digest = binding_digest(&(profile_issuer, grant_issuer, jti))?;
        match self {
            Self::Embedded(store) => store
                .record_unique(Namespace::McpIdJag, &digest, expiry, now)
                .await
                .map_err(|error| {
                    tracing::error!(%error, "Failed to record an MCP ID-JAG redemption");
                    StsError::ServerError("MCP replay storage unavailable".into())
                }),
            Self::Dynamodb { client, table } => {
                crate::storage::single_use::dynamodb_record_unique(client, table, "StsMcpReplay", &digest, expiry, now)
                    .await
                    .map_err(|error| {
                        tracing::error!(%error, "Failed to record an MCP ID-JAG redemption");
                        StsError::ServerError("MCP replay storage unavailable".into())
                    })
            }
        }
    }
}

/// Records the redemption of the ID-JAG `jti` issued by `issuer` until
/// `expiry`: `true` on its first redemption, `false` on a replay. A store
/// failure is a server error, so no grant is issued.
pub async fn record_id_jag(
    store: &SingleUseStore,
    issuer: &str,
    jti: &str,
    expiry: u64,
    now: u64,
) -> Result<bool, StsError> {
    let digest = binding_digest(&(issuer, jti))?;
    store
        .record_unique(Namespace::IdJag, &digest, expiry, now)
        .await
        .map_err(|error| {
            tracing::error!(%error, "Failed to record an ID-JAG redemption");
            StsError::ServerError("ID-JAG replay storage unavailable".into())
        })
}

fn binding_digest(binding: &impl Serialize) -> Result<[u8; 32], StsError> {
    let binding =
        serde_json_canonicalizer::to_vec(binding).map_err(|_| StsError::ServerError("Replay key failed".into()))?;
    Ok(Sha256::digest(binding).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "https://gateway.example/oauth2/mcp";

    #[tokio::test]
    async fn mcp_replay_is_issuer_scoped_atomic_and_lifetime_capped() {
        let replay = Arc::new(McpReplay::Embedded(Arc::new(SingleUseStore::in_memory())));
        let (first, second) = tokio::join!(
            replay.record_unique(PROFILE, "https://idp.example", "grant", 100, 10, 900),
            replay.record_unique(PROFILE, "https://idp.example", "grant", 100, 10, 900),
        );
        assert_eq!(usize::from(first.unwrap()) + usize::from(second.unwrap()), 1);
        assert!(
            replay
                .record_unique(PROFILE, "https://other.example", "grant", 100, 10, 900)
                .await
                .unwrap()
        );
        assert!(
            replay
                .record_unique(PROFILE, "https://idp.example", "grant", 200, 100, 900)
                .await
                .unwrap(),
            "an expired redemption no longer blocks"
        );
        assert!(
            replay
                .record_unique(PROFILE, "https://idp.example", "long", 2000, 100, 900)
                .await
                .is_err()
        );
        assert!(
            replay
                .record_unique(PROFILE, "https://idp.example", "long", 2000, 100, 3600)
                .await
                .unwrap(),
            "the configured cap, not a fixed one, bounds the lifetime"
        );
        assert!(McpReplay::new(&McpReplayConfig::Dynamodb { table: "replays".into() }, None).is_err());
    }

    #[tokio::test]
    async fn embedded_mcp_replay_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let open = || async {
            McpReplay::Embedded(Arc::new(
                SingleUseStore::open(&crate::storage::single_use::SingleUseStoreConfig::Disk {}, dir.path(), None, 10)
                    .await
                    .unwrap(),
            ))
        };
        assert!(
            open()
                .await
                .record_unique(PROFILE, "https://idp.example", "grant", 100, 10, 900)
                .await
                .unwrap()
        );
        assert!(
            !open()
                .await
                .record_unique(PROFILE, "https://idp.example", "grant", 100, 20, 900)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn an_id_jag_is_redeemed_once_per_issuer_even_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let open = || async {
            SingleUseStore::open(&crate::storage::single_use::SingleUseStoreConfig::Disk {}, dir.path(), None, 10)
                .await
                .unwrap()
        };
        let store = open().await;
        assert!(
            record_id_jag(&store, "https://idp.example", "grant", 100, 10)
                .await
                .unwrap()
        );
        assert!(
            record_id_jag(&store, "https://other.example", "grant", 100, 10)
                .await
                .unwrap(),
            "the same jti from another issuer is another grant"
        );
        drop(store);

        let reopened = open().await;
        assert!(
            !record_id_jag(&reopened, "https://idp.example", "grant", 100, 20)
                .await
                .unwrap()
        );
        assert!(
            !record_id_jag(&reopened, "https://other.example", "grant", 100, 20)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_store_failure_fails_the_redemption() {
        let err = record_id_jag(&SingleUseStore::failing(), "https://idp.example", "grant", 100, 10)
            .await
            .unwrap_err();
        assert_eq!(err.error_code(), "server_error");
    }
}
