use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{DelegationToken, FileSystemDelegationVaultStore};
use crate::storage::filesystem::{StorableEntity, StorageBackend, uncached_storage};

const MAX_STAGED_CONSENTS: usize = 100_000;
const EPOCH_ID: &str = "revocation";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentSnapshot {
    pub owner_digest: [u8; 32],
    pub revocation_epoch: Uuid,
    pub credential_version: Option<(String, DateTime<Utc>)>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedConsent {
    pub id: String,
    pub binding_digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub snapshot: ConsentSnapshot,
    pub credential: DelegationToken,
}

impl StorableEntity for StagedConsent {
    fn id(&self) -> &str {
        &self.id
    }
}

impl StagedConsent {
    fn validate(
        &self,
        binding_digest: [u8; 32],
        now: u64,
    ) -> Result<()> {
        ensure!(Uuid::parse_str(&self.id).is_ok_and(|id| !id.is_nil()), "Invalid staged consent ID");
        ensure!(self.binding_digest != [0; 32] && self.binding_digest == binding_digest, "Consent binding mismatch");
        ensure!(self.issued_at <= now && self.expires_at > now, "Consent is not live");
        ensure!(
            self.expires_at
                .checked_sub(self.issued_at)
                .is_some_and(|ttl| ttl <= crate::mcp::continuations::MAX_TTL_SECS),
            "Invalid consent lifetime"
        );
        ensure!(
            !self
                .credential
                .access_token
                .is_empty()
                && self
                    .credential
                    .token_type
                    .eq_ignore_ascii_case("Bearer"),
            "Invalid consent credential"
        );
        ensure!(
            self.credential
                .expires_at
                .is_none_or(|expiry| u64::try_from(expiry.timestamp()).is_ok_and(|expiry| expiry > now)),
            "Consent credential expired"
        );
        ensure!(
            !self
                .snapshot
                .revocation_epoch
                .is_nil(),
            "Invalid consent revocation epoch"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationEpoch {
    id: String,
    value: Uuid,
}

impl StorableEntity for RevocationEpoch {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone)]
pub(super) struct ConsentStorage {
    pub(super) staged: std::sync::Arc<dyn StorageBackend<StagedConsent>>,
    epochs: std::sync::Arc<dyn StorageBackend<RevocationEpoch>>,
}

impl ConsentStorage {
    pub(super) async fn access_revision(&self) -> Result<Option<Uuid>> {
        self.epochs
            .get(EPOCH_ID)
            .await?
            .map(|epoch| {
                ensure!(epoch.id == EPOCH_ID && !epoch.value.is_nil(), "Invalid consent revocation epoch");
                Ok(epoch.value)
            })
            .transpose()
    }

    pub(super) async fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            staged: uncached_storage(path.join("mcp_consent"), "mcp_consent")
                .await?
                .into(),
            epochs: uncached_storage(path.join("mcp_consent_state"), "mcp_consent_state")
                .await?
                .into(),
        })
    }
}

impl FileSystemDelegationVaultStore {
    pub(super) async fn revoke_pending_consents(&self) -> Result<()> {
        self.consents
            .epochs
            .save_atomic(&RevocationEpoch {
                id: EPOCH_ID.into(),
                value: Uuid::new_v4(),
            })
            .await
    }

    pub(super) async fn consent_snapshot_locked(
        &self,
        agent_did: &str,
        user_identity_hash: &str,
        provider_id: &str,
    ) -> Result<ConsentSnapshot> {
        ensure!(
            [agent_did, user_identity_hash, provider_id]
                .iter()
                .all(|value| !value.is_empty() && value.len() <= 4096),
            "Invalid consent identity"
        );
        let epoch = match self
            .consents
            .epochs
            .get(EPOCH_ID)
            .await?
        {
            Some(epoch) => epoch,
            None => {
                let epoch = RevocationEpoch {
                    id: EPOCH_ID.into(),
                    value: Uuid::new_v4(),
                };
                self.consents
                    .epochs
                    .save_atomic(&epoch)
                    .await?;
                epoch
            }
        };
        ensure!(epoch.id == EPOCH_ID && !epoch.value.is_nil(), "Invalid consent revocation epoch");
        let mut matching = self
            .storage
            .list_all()
            .await?
            .into_iter()
            .filter(|token| {
                token.agent_did == agent_did
                    && token.user_identity_hash == user_identity_hash
                    && token.credential_provider_id == provider_id
            });
        let credential_version = matching
            .next()
            .map(|token| (token.id, token.updated_at));
        ensure!(matching.next().is_none(), "Ambiguous delegation credentials for this identity");
        Ok(ConsentSnapshot {
            owner_digest: Sha256::digest(serde_json_canonicalizer::to_vec(&(
                agent_did,
                user_identity_hash,
                provider_id,
            ))?)
            .into(),
            revocation_epoch: epoch.value,
            credential_version,
        })
    }

    async fn consent_snapshot_matches(
        &self,
        consent: &StagedConsent,
    ) -> Result<bool> {
        let credential = &consent.credential;
        Ok(self
            .consent_snapshot_locked(
                &credential.agent_did,
                &credential.user_identity_hash,
                &credential.credential_provider_id,
            )
            .await?
            == consent.snapshot)
    }

    pub(super) async fn stage_consent_locked(
        &self,
        consent: StagedConsent,
        now: u64,
    ) -> Result<()> {
        consent.validate(consent.binding_digest, now)?;
        ensure!(
            self.consent_snapshot_matches(&consent)
                .await?,
            "Consent credentials changed or were revoked"
        );
        let mut retained = 0;
        for staged in self
            .consents
            .staged
            .list_all()
            .await?
        {
            if staged.expires_at <= now
                || staged
                    .snapshot
                    .revocation_epoch
                    != consent
                        .snapshot
                        .revocation_epoch
            {
                self.consents
                    .staged
                    .delete(&staged.id)
                    .await?;
            } else {
                retained += 1;
            }
        }
        ensure!(retained < MAX_STAGED_CONSENTS, "Consent vault capacity reached");
        ensure!(
            self.consents
                .staged
                .get(&consent.id)
                .await?
                .is_none(),
            "Consent credential was already staged"
        );
        self.consents
            .staged
            .save_atomic(&consent)
            .await
    }

    pub(super) async fn staged_consent_locked(
        &self,
        id: Uuid,
        binding_digest: [u8; 32],
        now: u64,
    ) -> Result<Option<StagedConsent>> {
        ensure!(!id.is_nil(), "Invalid consent ID");
        let Some(consent) = self
            .consents
            .staged
            .get(&id.to_string())
            .await?
        else {
            return Ok(None);
        };
        ensure!(consent.id == id.to_string(), "Consent ID mismatch");
        if consent.expires_at <= now
            || !self
                .consent_snapshot_matches(&consent)
                .await?
        {
            self.consents
                .staged
                .delete(&consent.id)
                .await?;
            return Ok(None);
        }
        consent
            .validate(binding_digest, now)
            .context("Invalid staged consent")?;
        Ok(Some(consent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::{VaultLookupResult, storage::DelegationVaultStorage};

    async fn staged(store: &FileSystemDelegationVaultStore) -> (StagedConsent, u64) {
        let token = crate::delegation_vault::tests::make_token(Some(3600), true);
        let now = Utc::now().timestamp() as u64;
        (
            StagedConsent {
                id: Uuid::new_v4().to_string(),
                binding_digest: [1; 32],
                issued_at: now,
                expires_at: now + 300,
                snapshot: store
                    .consent_snapshot(&token.agent_did, &token.user_identity_hash, &token.credential_provider_id)
                    .await
                    .unwrap(),
                credential: token,
            },
            now,
        )
    }

    #[tokio::test]
    async fn staged_consent_is_hidden_bound_and_activated_only_once() {
        let directory = tempfile::tempdir().unwrap();
        let first = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let second = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let (consent, now) = staged(&first).await;
        let id = Uuid::parse_str(&consent.id).unwrap();
        let token = consent.credential.clone();
        first
            .stage_consent(consent.clone(), now)
            .await
            .unwrap();
        assert!(
            first
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            second
                .lookup(&token.agent_did, &token.user_identity_hash, &token.credential_provider_id)
                .await
                .unwrap(),
            VaultLookupResult::NotFound
        ));
        assert!(
            second
                .stage_consent(consent, now)
                .await
                .is_err()
        );
        assert!(
            second
                .activate_consent(id, [2; 32], now)
                .await
                .is_err()
        );
        let (left, right) =
            tokio::join!(first.activate_consent(id, [1; 32], now), second.activate_consent(id, [1; 32], now));
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        assert_eq!(
            first
                .get(&token.id)
                .await
                .unwrap()
                .unwrap()
                .access_token,
            token.access_token
        );
        assert!(
            first
                .staged_consent(id, [1; 32], now)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn revocation_replacement_and_expiry_prevent_stale_consent_publication() {
        let directory = tempfile::tempdir().unwrap();
        let first = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let second = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let (consent, now) = staged(&first).await;
        assert_eq!(
            second
                .delete_by_user(
                    &consent
                        .credential
                        .user_identity_hash
                )
                .await
                .unwrap(),
            0
        );
        assert!(
            first
                .stage_consent(consent, now)
                .await
                .is_err()
        );
        let (consent, now) = staged(&first).await;
        let id = Uuid::parse_str(&consent.id).unwrap();
        first
            .stage_consent(consent, now)
            .await
            .unwrap();
        second
            .delete("already-absent")
            .await
            .unwrap();
        assert!(
            first
                .activate_consent(id, [1; 32], now)
                .await
                .is_err()
        );
        assert!(
            first
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
        let (consent, now) = staged(&first).await;
        let id = Uuid::parse_str(&consent.id).unwrap();
        first
            .stage_consent(consent.clone(), now)
            .await
            .unwrap();
        let mut replacement = consent.credential;
        replacement.access_token = "new-credential".into();
        second
            .store(replacement)
            .await
            .unwrap();
        assert!(
            first
                .activate_consent(id, [1; 32], now)
                .await
                .is_err()
        );
        let (consent, now) = staged(&first).await;
        let id = Uuid::parse_str(&consent.id).unwrap();
        first
            .stage_consent(consent, now)
            .await
            .unwrap();
        assert!(
            first
                .activate_consent(id, [1; 32], now + 300)
                .await
                .is_err()
        );
    }
}
