use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{ConsentSnapshot, DelegationToken, FileSystemDelegationVaultStore, same_owner};
use crate::delegation_vault::OAuthTokenResponse;
use crate::storage::filesystem::StorableEntity;

const REFRESH_CLAIM_SECS: u64 = 45;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RefreshError {
    #[error("Credential refresh storage is unavailable")]
    Unavailable,
    #[error("Credential changed or was revoked")]
    Changed,
    #[error("Credential refresh is already in progress")]
    InProgress,
    #[error("Previous credential refresh outcome is uncertain")]
    Uncertain,
    #[error("Credential cannot be refreshed")]
    NotRefreshable,
    #[error("Credential refresh response is invalid")]
    InvalidResponse,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RefreshRecord {
    id: String,
    claim_id: Uuid,
    version: DateTime<Utc>,
    refresh_digest: [u8; 32],
    started_at: u64,
    expires_at: u64,
    snapshot: ConsentSnapshot,
}

impl StorableEntity for RefreshRecord {
    fn id(&self) -> &str {
        &self.id
    }
}

pub struct RefreshClaim {
    record: RefreshRecord,
    token: DelegationToken,
}

impl RefreshClaim {
    pub fn token(&self) -> &DelegationToken {
        &self.token
    }
}

impl FileSystemDelegationVaultStore {
    pub(super) async fn claim_refresh_locked(
        &self,
        expected: &DelegationToken,
        now: u64,
    ) -> Result<RefreshClaim, RefreshError> {
        let current = self
            .storage
            .get(&expected.id)
            .await
            .map_err(|_| RefreshError::Unavailable)?
            .ok_or(RefreshError::Changed)?;
        if !same_owner(&current, expected) || current.updated_at != expected.updated_at {
            return Err(RefreshError::Changed);
        }
        let refresh_token = current
            .refresh_token
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or(RefreshError::NotRefreshable)?;
        let refresh_digest: [u8; 32] = Sha256::digest(refresh_token.as_bytes()).into();
        if let Some(previous) = self
            .refreshes
            .get(&current.id)
            .await
            .map_err(|_| RefreshError::Unavailable)?
            && previous.refresh_digest == refresh_digest
        {
            return Err(if now >= previous.started_at && now < previous.expires_at {
                RefreshError::InProgress
            } else {
                RefreshError::Uncertain
            });
        }
        let snapshot = self
            .consent_snapshot_locked(&current.agent_did, &current.user_identity_hash, &current.credential_provider_id)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        let record = RefreshRecord {
            id: current.id.clone(),
            claim_id: Uuid::new_v4(),
            version: current.updated_at,
            refresh_digest,
            started_at: now,
            expires_at: now
                .checked_add(REFRESH_CLAIM_SECS)
                .ok_or(RefreshError::Unavailable)?,
            snapshot,
        };
        self.refreshes
            .save_atomic(&record)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        Ok(RefreshClaim { record, token: current })
    }

    pub(super) async fn complete_refresh_locked(
        &self,
        claim: RefreshClaim,
        response: OAuthTokenResponse,
        now: u64,
    ) -> Result<DelegationToken, RefreshError> {
        if now < claim.record.started_at || now >= claim.record.expires_at {
            return Err(RefreshError::Uncertain);
        }
        if response
            .access_token
            .is_empty()
            || !response
                .token_type
                .eq_ignore_ascii_case("Bearer")
            || response
                .expires_in
                .is_some_and(|seconds| seconds <= 0 || seconds > 366 * 86400)
            || response
                .refresh_token
                .as_deref()
                .is_some_and(str::is_empty)
        {
            return Err(RefreshError::InvalidResponse);
        }
        let stored_claim = self
            .refreshes
            .get(&claim.record.id)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        if stored_claim.as_ref() != Some(&claim.record) {
            return Err(RefreshError::Changed);
        }
        let mut token = self
            .storage
            .get(&claim.record.id)
            .await
            .map_err(|_| RefreshError::Unavailable)?
            .ok_or(RefreshError::Changed)?;
        let snapshot = self
            .consent_snapshot_locked(&token.agent_did, &token.user_identity_hash, &token.credential_provider_id)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        if snapshot != claim.record.snapshot
            || !same_owner(&token, &claim.token)
            || token.updated_at != claim.record.version
        {
            return Err(RefreshError::Changed);
        }
        if let Some(scope) = response.scope {
            let scopes = scope
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>();
            if scopes.len() > 128
                || scopes
                    .iter()
                    .any(|scope| !token.scopes.contains(scope))
            {
                return Err(RefreshError::InvalidResponse);
            }
            token.scopes = scopes;
        }
        token.access_token = response.access_token;
        token.token_type = response.token_type;
        if let Some(refresh_token) = response.refresh_token {
            token.refresh_token = Some(refresh_token);
        }
        let issued_at = i64::try_from(now)
            .ok()
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
            .ok_or(RefreshError::InvalidResponse)?;
        token.expires_at = response
            .expires_in
            .map(|seconds| {
                issued_at
                    .checked_add_signed(chrono::Duration::seconds(seconds))
                    .ok_or(RefreshError::InvalidResponse)
            })
            .transpose()?;
        token.updated_at = super::next_version(token.updated_at).map_err(|_| RefreshError::Unavailable)?;
        self.storage
            .save_atomic(&token)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        self.refreshes
            .delete(&token.id)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::storage::DelegationVaultStorage;

    fn response() -> OAuthTokenResponse {
        OAuthTokenResponse {
            access_token: "refreshed-access".into(),
            refresh_token: Some("rotated-refresh".into()),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            scope: None,
        }
    }

    #[tokio::test]
    async fn refresh_claims_are_single_use_across_instances_and_survive_ambiguous_failure() {
        let directory = tempfile::tempdir().unwrap();
        let first = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let second = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let token = first
            .store(crate::delegation_vault::tests::make_token(Some(-60), true))
            .await
            .unwrap();
        let (left, right) = tokio::join!(first.claim_refresh(&token, 100), second.claim_refresh(&token, 100));
        let claim = match (left, right) {
            (Ok(claim), Err(RefreshError::InProgress)) | (Err(RefreshError::InProgress), Ok(claim)) => claim,
            _ => panic!("exactly one refresh may claim a credential"),
        };
        assert_eq!(claim.token().id, token.id);
        second
            .mark_used(&token.id)
            .await
            .unwrap();
        let updated = second
            .complete_refresh(claim, response(), 101)
            .await
            .unwrap();
        assert_eq!(updated.access_token, "refreshed-access");
        assert_eq!(
            updated
                .refresh_token
                .as_deref(),
            Some("rotated-refresh")
        );
        assert!(updated.last_used_at.is_some());
        assert!(updated.updated_at > token.updated_at);
        assert!(matches!(
            first
                .claim_refresh(&token, 102)
                .await,
            Err(RefreshError::Changed)
        ));
        let abandoned = first
            .claim_refresh(&updated, 102)
            .await
            .unwrap();
        drop(abandoned);
        let restarted = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        assert!(matches!(
            restarted
                .claim_refresh(&updated, 103)
                .await,
            Err(RefreshError::InProgress)
        ));
        assert!(matches!(
            restarted
                .claim_refresh(&updated, 147)
                .await,
            Err(RefreshError::Uncertain)
        ));
    }

    #[tokio::test]
    async fn revoked_replaced_or_scope_widening_refreshes_cannot_publish() {
        for action in ["revoke", "replace", "widen", "expire"] {
            let directory = tempfile::tempdir().unwrap();
            let first = FileSystemDelegationVaultStore::new(directory.path().into())
                .await
                .unwrap();
            let second = FileSystemDelegationVaultStore::new(directory.path().into())
                .await
                .unwrap();
            let token = first
                .store(crate::delegation_vault::tests::make_token(Some(-60), true))
                .await
                .unwrap();
            let claim = first
                .claim_refresh(&token, 100)
                .await
                .unwrap();
            let mut response = response();
            match action {
                "revoke" => {
                    second
                        .delete(&token.id)
                        .await
                        .unwrap();
                }
                "replace" => {
                    second
                        .store(token.clone())
                        .await
                        .unwrap();
                }
                "widen" => {
                    response.scope = Some("admin".into());
                }
                _ => {}
            }
            let result = first
                .complete_refresh(
                    claim,
                    response,
                    if action == "expire" {
                        145
                    } else {
                        101
                    },
                )
                .await;
            assert!(result.is_err(), "{action}");
            assert!(
                second
                    .get(&token.id)
                    .await
                    .unwrap()
                    .is_none_or(|current| current.access_token == token.access_token),
                "{action}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vault_refresh_claims_survive_process_races_revocation_and_crashes() {
        use std::time::Duration;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        if let Ok(directory) = std::env::var("ATG_MCP_VAULT_CHILD_DIR") {
            let directory = std::path::PathBuf::from(directory);
            assert!(
                directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("mcp-vault-process-"))
            );
            let vault = FileSystemDelegationVaultStore::new(directory)
                .await
                .unwrap();
            let tokens = vault
                .list_all()
                .await
                .unwrap();
            assert_eq!(tokens.len(), 1);
            let token = &tokens[0];
            let barrier: std::net::SocketAddr = std::env::var("ATG_MCP_VAULT_BARRIER")
                .unwrap()
                .parse()
                .unwrap();
            assert!(barrier.ip().is_loopback());
            let index: u8 = std::env::var("ATG_MCP_VAULT_CHILD_INDEX")
                .unwrap()
                .parse()
                .unwrap();
            assert!(index < 4);
            tokio::time::timeout(Duration::from_secs(30), async {
                let mut stream = tokio::net::TcpStream::connect(barrier)
                    .await
                    .unwrap();
                stream
                    .write_u8(index)
                    .await
                    .unwrap();
                stream
                    .read_u8()
                    .await
                    .unwrap();
                let claim = match vault
                    .claim_refresh(token, 100)
                    .await
                {
                    Ok(claim) => Some(claim),
                    Err(RefreshError::InProgress) => None,
                    other => panic!("unexpected refresh outcome: {:?}", other.err()),
                };
                stream
                    .write_u8(u8::from(claim.is_some()))
                    .await
                    .unwrap();
                if let Some(claim) = claim {
                    stream
                        .read_u8()
                        .await
                        .unwrap();
                    assert!(matches!(
                        vault
                            .complete_refresh(claim, response(), 101)
                            .await,
                        Err(RefreshError::Changed)
                    ));
                    assert!(
                        vault
                            .get(&token.id)
                            .await
                            .unwrap()
                            .is_none()
                    );
                    stream
                        .write_u8(2)
                        .await
                        .unwrap();
                }
            })
            .await
            .expect("child vault refresh timed out");
            return;
        }

        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        for revoke in [true, false] {
            let directory = tempfile::Builder::new()
                .prefix("mcp-vault-process-")
                .tempdir()
                .unwrap();
            let vault = FileSystemDelegationVaultStore::new(directory.path().into())
                .await
                .unwrap();
            let token = vault
                .store(crate::delegation_vault::tests::make_token(Some(-60), true))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(30), async {
                let barrier = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .unwrap();
                let mut children = Vec::new();
                for index in 0..4 {
                    children.push(Some(
                        tokio::process::Command::new(std::env::current_exe().unwrap())
                            .args(["--exact", &test_name, "--nocapture"])
                            .env("ATG_MCP_VAULT_CHILD_DIR", directory.path())
                            .env(
                                "ATG_MCP_VAULT_BARRIER",
                                barrier
                                    .local_addr()
                                    .unwrap()
                                    .to_string(),
                            )
                            .env("ATG_MCP_VAULT_CHILD_INDEX", index.to_string())
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .kill_on_drop(true)
                            .spawn()
                            .unwrap(),
                    ));
                }
                let mut streams = Vec::new();
                let mut indices = std::collections::HashSet::new();
                for _process in 0..4 {
                    let (mut stream, _) = barrier
                        .accept()
                        .await
                        .unwrap();
                    let index = usize::from(
                        stream
                            .read_u8()
                            .await
                            .unwrap(),
                    );
                    assert!(index < 4 && indices.insert(index));
                    streams.push((index, stream));
                }
                for (_, stream) in &mut streams {
                    stream
                        .write_u8(1)
                        .await
                        .unwrap();
                }
                let mut winner = None;
                for (index, stream) in &mut streams {
                    match stream
                        .read_u8()
                        .await
                        .unwrap()
                    {
                        1 => assert!(
                            winner
                                .replace(*index)
                                .is_none(),
                            "only one process may own a refresh"
                        ),
                        0 => {}
                        other => panic!("unexpected child response: {other}"),
                    }
                }
                let winner = winner.expect("one process must claim the refresh");
                if revoke {
                    assert!(
                        vault
                            .delete(&token.id)
                            .await
                            .unwrap()
                    );
                    let (_, stream) = streams
                        .iter_mut()
                        .find(|(index, _)| *index == winner)
                        .unwrap();
                    stream
                        .write_u8(1)
                        .await
                        .unwrap();
                    assert_eq!(
                        stream
                            .read_u8()
                            .await
                            .unwrap(),
                        2
                    );
                } else {
                    let mut child = children[winner]
                        .take()
                        .unwrap();
                    child.start_kill().unwrap();
                    let output = child
                        .wait_with_output()
                        .await
                        .unwrap();
                    assert!(!output.status.success(), "the refresh owner must terminate abruptly");
                }
                for child in children.into_iter().flatten() {
                    let output = child
                        .wait_with_output()
                        .await
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "refresh child failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                let restarted = FileSystemDelegationVaultStore::new(directory.path().into())
                    .await
                    .unwrap();
                if revoke {
                    assert!(
                        restarted
                            .get(&token.id)
                            .await
                            .unwrap()
                            .is_none()
                    );
                    assert!(matches!(
                        restarted
                            .claim_refresh(&token, 102)
                            .await,
                        Err(RefreshError::Changed)
                    ));
                } else {
                    assert_eq!(
                        restarted
                            .get(&token.id)
                            .await
                            .unwrap()
                            .unwrap()
                            .access_token,
                        token.access_token
                    );
                    assert!(matches!(
                        restarted
                            .claim_refresh(&token, 101)
                            .await,
                        Err(RefreshError::InProgress)
                    ));
                    assert!(matches!(
                        restarted
                            .claim_refresh(&token, 145)
                            .await,
                        Err(RefreshError::Uncertain)
                    ));
                }
            })
            .await
            .expect("multi-process vault refresh timed out");
        }
    }
}
