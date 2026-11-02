//! Single-flight refresh of grants by binding.
//!
//! A refresh is claimed, under the vault's lock, for the grant's current
//! version and refresh token, and recorded in the vault, so on every node that
//! shares the vault only one refresh of a token runs at a time. The claim is
//! timed when the lock is held, and is another call's refresh in progress
//! until its window ends, whatever clock read its start. The rotated tokens
//! are written under the lock, for the version the claim was made for, before
//! the new access token is used, however late they come, as long as nobody
//! took the claim over. Once the grant is written the refresh is done: a claim
//! that cannot be cleared afterwards names a version no longer stored, and the
//! next claim replaces it. A claim of the current version that outlived its
//! window means a refresh may have died between the authorization server's
//! answer and the write, so the refresh token may be spent: such a grant is
//! never refreshed again, and needs a new connect once its access token
//! expires. A refusal of the refresh token deletes the grant only while the
//! claim is still its own, so a grant a reconnect stored meanwhile is kept.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{FileSystemDelegationVaultStore, RefreshError};
use crate::delegation_vault::grants::{DelegatedGrant, FailedRefresh, ObtainedTokens};
use crate::storage::filesystem::StorableEntity;

/// How long a claimed refresh may take before it is taken for dead.
const GRANT_REFRESH_CLAIM_SECS: i64 = 45;

/// The directory of the vault that holds the claims of grants' refreshes:
/// each names a grant's record id and a digest of its refresh token. Excluded
/// from storage exports.
pub const GRANT_REFRESH_CLAIMS_DIRECTORY: &str = "delegated_grant_refreshes";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantRefreshRecord {
    /// The grant's record id.
    id: String,
    claim_id: Uuid,
    /// The grant's `updated_at` when the refresh was claimed.
    version: DateTime<Utc>,
    refresh_digest: [u8; 32],
    started_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl StorableEntity for GrantRefreshRecord {
    fn id(&self) -> &str {
        &self.id
    }
}

/// A claimed refresh of one grant, and the grant as it was claimed.
pub struct GrantRefreshClaim {
    record: GrantRefreshRecord,
    grant: DelegatedGrant,
}

impl GrantRefreshClaim {
    /// The grant the refresh was claimed for.
    pub fn grant(&self) -> &DelegatedGrant {
        &self.grant
    }
}

impl FileSystemDelegationVaultStore {
    /// The grant with this record id, if its own key derives that id.
    async fn current_grant(
        &self,
        id: &str,
    ) -> Result<Option<DelegatedGrant>, RefreshError> {
        let grant = self
            .grants
            .get(id)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        Ok(grant.filter(|grant| grant.id == id && grant.key().record_id() == id))
    }

    /// Claim the refresh of `expected`, timed now, while the vault's lock is
    /// held: `now`, when the caller read its clock, is the earliest it is
    /// timed at.
    pub(super) async fn claim_grant_refresh_locked(
        &self,
        expected: &DelegatedGrant,
        now: DateTime<Utc>,
    ) -> Result<GrantRefreshClaim, RefreshError> {
        let now = now.max(Utc::now());
        let current = self
            .current_grant(&expected.id)
            .await?
            .ok_or(RefreshError::Changed)?;
        if current.updated_at != expected.updated_at {
            return Err(RefreshError::Changed);
        }
        let refresh_token = current
            .refresh_token
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or(RefreshError::NotRefreshable)?;
        let refresh_digest: [u8; 32] = Sha256::digest(refresh_token.as_bytes()).into();
        // A claim of this version and refresh token is another call's refresh,
        // in progress until its window ends: a start later than `now` is
        // another clock, not a dead refresh. A claim of an earlier version
        // ended when its grant was written since, whatever left it behind, and
        // is replaced.
        if let Some(previous) = self
            .grant_refreshes
            .get(&current.id)
            .await
            .map_err(|_| RefreshError::Unavailable)?
            && previous.version == current.updated_at
            && previous.refresh_digest == refresh_digest
        {
            return Err(if now < previous.expires_at {
                RefreshError::InProgress
            } else {
                RefreshError::Uncertain
            });
        }
        let record = GrantRefreshRecord {
            id: current.id.clone(),
            claim_id: Uuid::new_v4(),
            version: current.updated_at,
            refresh_digest,
            started_at: now,
            expires_at: now + chrono::Duration::seconds(GRANT_REFRESH_CLAIM_SECS),
        };
        self.grant_refreshes
            .save_atomic(&record)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        Ok(GrantRefreshClaim { record, grant: current })
    }

    /// The grant `claim` was made for, if the claim is still the stored one
    /// and the grant has not changed since.
    async fn claimed_grant(
        &self,
        claim: &GrantRefreshClaim,
    ) -> Result<DelegatedGrant, RefreshError> {
        let stored = self
            .grant_refreshes
            .get(&claim.record.id)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        if stored.as_ref() != Some(&claim.record) {
            return Err(RefreshError::Changed);
        }
        let grant = self
            .current_grant(&claim.record.id)
            .await?
            .ok_or(RefreshError::Changed)?;
        if grant.updated_at != claim.record.version {
            return Err(RefreshError::Changed);
        }
        Ok(grant)
    }

    /// Clear the claim of the grant with this id once the claim's outcome is
    /// written. A claim that cannot be cleared names a version of the grant
    /// no longer stored, so the next claim replaces it.
    async fn release_claim(
        &self,
        id: &str,
    ) {
        if let Err(error) = self
            .grant_refreshes
            .delete(id)
            .await
        {
            tracing::warn!(
                target: "credential_delegation",
                grant_id = %id,
                error = ?error.to_string(),
                "A grant's refresh claim could not be cleared once its outcome was written; the next refresh \
                 replaces it"
            );
        }
    }

    /// Write the tokens `claim`'s refresh obtained, whenever they come: a
    /// claim nobody took over, by abandoning it once its window passed or by
    /// replacing or removing its grant, is still the grant's, and the tokens
    /// are the grant's own. The scopes they hold were checked against those
    /// asked for, as the grant's provider compares them, before. Every
    /// failure before the write leaves the grant as it was; a failed write
    /// is [`RefreshError::Unconfirmed`], since the record may have been
    /// written all the same.
    pub(super) async fn complete_grant_refresh_locked(
        &self,
        claim: GrantRefreshClaim,
        tokens: ObtainedTokens,
        now: DateTime<Utc>,
    ) -> Result<DelegatedGrant, RefreshError> {
        let mut grant = self
            .claimed_grant(&claim)
            .await?;
        if tokens.access_token.is_empty()
            || tokens
                .refresh_token
                .as_deref()
                .is_some_and(str::is_empty)
        {
            return Err(RefreshError::InvalidResponse);
        }
        grant.access_token = tokens.access_token;
        if let Some(refresh_token) = tokens.refresh_token {
            grant.refresh_token = Some(refresh_token);
        }
        grant.scopes = tokens.scopes;
        grant.expires_at = tokens.expires_at;
        grant.refreshed_at = Some(now);
        grant.refresh_failed_at = None;
        grant.refresh_failures = 0;
        grant.refresh_retry_at = None;
        grant.refresh_refusals = 0;
        grant.updated_at = super::next_version(grant.updated_at).map_err(|_| RefreshError::Unavailable)?;
        self.grants
            .save_atomic(&grant)
            .await
            .map_err(|_| RefreshError::Unconfirmed)?;
        self.release_claim(&grant.id)
            .await;
        Ok(grant)
    }

    pub(super) async fn fail_grant_refresh_locked(
        &self,
        claim: GrantRefreshClaim,
        failure: FailedRefresh,
        now: DateTime<Utc>,
    ) -> Result<DelegatedGrant, RefreshError> {
        let mut grant = self
            .claimed_grant(&claim)
            .await?;
        grant.record_refresh_failure(now, failure);
        grant.updated_at = super::next_version(grant.updated_at).map_err(|_| RefreshError::Unavailable)?;
        self.grants
            .save_atomic(&grant)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        self.release_claim(&grant.id)
            .await;
        Ok(grant)
    }

    /// Delete the grant `claim` was made for, while the claim is still the
    /// stored one and the grant the version it was claimed for, and return it.
    pub(super) async fn discard_grant_refresh_locked(
        &self,
        claim: GrantRefreshClaim,
    ) -> Result<DelegatedGrant, RefreshError> {
        let grant = self
            .claimed_grant(&claim)
            .await?;
        self.grants
            .delete(&grant.id)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        self.release_claim(&grant.id)
            .await;
        Ok(grant)
    }

    /// Mark `expected` as never to be refreshed again, when a claim of its
    /// current refresh token outlived its window: the refresh token may be
    /// spent. The stale claim is removed.
    pub(super) async fn abandon_grant_refresh_locked(
        &self,
        expected: &DelegatedGrant,
        now: DateTime<Utc>,
    ) -> Result<DelegatedGrant, RefreshError> {
        let mut grant = self
            .current_grant(&expected.id)
            .await?
            .ok_or(RefreshError::Changed)?;
        if grant.updated_at != expected.updated_at {
            return Err(RefreshError::Changed);
        }
        grant.record_refresh_failure(now, FailedRefresh::Abandoned);
        grant.updated_at = super::next_version(grant.updated_at).map_err(|_| RefreshError::Unavailable)?;
        self.grants
            .save_atomic(&grant)
            .await
            .map_err(|_| RefreshError::Unavailable)?;
        self.release_claim(&grant.id)
            .await;
        Ok(grant)
    }
}
