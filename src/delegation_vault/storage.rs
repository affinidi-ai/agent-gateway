//! Filesystem storage for delegation vault tokens

use super::grants::{DelegatedGrant, EncryptionRequired, EphemeralPepper, GRANTS_DIRECTORY, GrantKey, StoredGrant};
use super::{DelegationToken, VaultLookupResult};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use tracing::{debug, info, warn};

use crate::storage::filesystem::{StorageBackend, uncached_storage};

mod consent;
pub use consent::{ConsentSnapshot, StagedConsent};
mod refresh;
pub use refresh::{RefreshClaim, RefreshError};

/// Trait for delegation vault storage operations
#[async_trait]
pub trait DelegationVaultStorage: Send + Sync {
    /// Store a delegation token
    async fn store(
        &self,
        token: DelegationToken,
    ) -> Result<DelegationToken>;

    /// Get a token by its UUID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<DelegationToken>>;

    /// Lookup token by composite key (agent_did, user_hash, provider_id)
    async fn lookup(
        &self,
        agent_did: &str,
        user_identity_hash: &str,
        provider_id: &str,
    ) -> Result<VaultLookupResult>;

    /// List all tokens (metadata only traversal)
    async fn list_all(&self) -> Result<Vec<DelegationToken>>;

    /// Delete a token by ID (revoke)
    async fn delete(
        &self,
        id: &str,
    ) -> Result<bool>;

    /// Delete all tokens for a user hash
    async fn delete_by_user(
        &self,
        user_identity_hash: &str,
    ) -> Result<usize>;

    /// Update a token (e.g. after refresh)
    async fn update(
        &self,
        token: DelegationToken,
    ) -> Result<DelegationToken>;

    /// Mark a token as used (update last_used_at)
    async fn mark_used(
        &self,
        id: &str,
    ) -> Result<()>;

    async fn access_revision(&self) -> Result<Option<uuid::Uuid>> {
        anyhow::bail!("This vault does not support subscription access validation")
    }

    async fn consent_snapshot(
        &self,
        _agent_did: &str,
        _user_identity_hash: &str,
        _provider_id: &str,
    ) -> Result<ConsentSnapshot> {
        anyhow::bail!("This vault does not support verified consent publication")
    }

    async fn stage_consent(
        &self,
        _consent: StagedConsent,
        _now: u64,
    ) -> Result<()> {
        anyhow::bail!("This vault does not support verified consent publication")
    }

    async fn staged_consent(
        &self,
        _id: uuid::Uuid,
        _binding_digest: [u8; 32],
        _now: u64,
    ) -> Result<Option<StagedConsent>> {
        anyhow::bail!("This vault does not support verified consent publication")
    }

    async fn activate_consent(
        &self,
        _id: uuid::Uuid,
        _binding_digest: [u8; 32],
        _now: u64,
    ) -> Result<DelegationToken> {
        anyhow::bail!("This vault does not support verified consent publication")
    }

    async fn claim_refresh(
        &self,
        _token: &DelegationToken,
        _now: u64,
    ) -> Result<RefreshClaim, RefreshError> {
        Err(RefreshError::Unavailable)
    }

    async fn complete_refresh(
        &self,
        _claim: RefreshClaim,
        _response: super::OAuthTokenResponse,
        _now: u64,
    ) -> Result<DelegationToken, RefreshError> {
        Err(RefreshError::Unavailable)
    }

    /// The grant stored under `key`, read with one lookup by its record id.
    /// Fails with [`EncryptionRequired`] while at-rest encryption is not active,
    /// and with [`EphemeralPepper`] while the identity hash pepper is not
    /// configured.
    async fn grant(
        &self,
        _key: &GrantKey,
    ) -> Result<Option<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Store `grant` under its key, replacing a grant of the same key, which is
    /// returned so the caller can revoke its tokens. The record id is derived
    /// from the key; the grant's own `id` is ignored. Fails as [`Self::grant`]
    /// does.
    #[allow(dead_code)]
    async fn store_grant(
        &self,
        _grant: DelegatedGrant,
    ) -> Result<StoredGrant> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Every grant made with one credential provider, by the provider its own
    /// record names, whether or not its id is its key's under the current
    /// pepper, so a grant written under an earlier pepper can still be revoked
    /// and deleted. Fails with [`EncryptionRequired`] while at-rest encryption
    /// is not active.
    async fn provider_grants(
        &self,
        _credential_provider_id: &str,
    ) -> Result<Vec<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Every grant stored, as [`Self::provider_grants`] lists them.
    async fn all_grants(&self) -> Result<Vec<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Whether any grant is stored, read without decrypting one, so it can be
    /// answered while at-rest encryption is off.
    async fn has_stored_grants(&self) -> Result<bool> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Delete the grant with this record id, returning it if it existed.
    async fn delete_grant(
        &self,
        _id: &str,
    ) -> Result<Option<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Record that a grant was used, when the vault is not busy.
    async fn mark_grant_used(
        &self,
        _id: &str,
    ) -> Result<()> {
        Ok(())
    }
}

/// Filesystem-backed delegation vault using uncached storage (security-sensitive)
#[derive(Clone)]
pub struct FileSystemDelegationVaultStore {
    storage: std::sync::Arc<dyn StorageBackend<DelegationToken>>,
    mutation_lock_path: PathBuf,
    consents: consent::ConsentStorage,
    refreshes: std::sync::Arc<dyn StorageBackend<refresh::RefreshRecord>>,
    grants: std::sync::Arc<dyn StorageBackend<DelegatedGrant>>,
    grants_directory: PathBuf,
    /// Whether the vault's stores were created with at-rest encryption active.
    encrypted: bool,
    /// Whether the identity hash pepper, which grant ids derive from, was
    /// configured rather than generated for this process.
    stable_grant_ids: bool,
}

impl FileSystemDelegationVaultStore {
    pub async fn new(path: PathBuf) -> Result<Self> {
        let encrypted = crate::storage::filesystem::at_rest_encryption_active();
        let stable_grant_ids = crate::identity::credential_identity::pepper_is_configured();
        // Use uncached storage for security — tokens should not linger in memory
        let storage = uncached_storage(path.clone(), "delegation_token").await?;
        if encrypted {
            info!(
                target: "credential_delegation",
                path = %path.display(),
                "Delegation vault store initialized (uncached, encrypted at rest)"
            );
        } else {
            warn!(
                target: "credential_delegation",
                path = %path.display(),
                "Delegation vault store initialized (uncached, NOT encrypted at rest): delegated tokens are written in \
                 plaintext, and grants by binding are refused until [encryption] is enabled with a key"
            );
        }
        if !stable_grant_ids {
            warn!(
                target: "credential_delegation",
                "AG_IDENTITY_HASH_PEPPER is not set: grants by binding are neither stored nor released, since their \
                 ids derive from the identity hash pepper and one generated for this process changes on restart; \
                 set AG_IDENTITY_HASH_PEPPER to the same value on every node"
            );
        }
        Ok(Self {
            storage: storage.into(),
            mutation_lock_path: path.join(".mutation.lock"),
            consents: consent::ConsentStorage::new(&path).await?,
            refreshes: uncached_storage(path.join("refresh_claims"), "delegation_refresh")
                .await?
                .into(),
            grants: uncached_storage(path.join(GRANTS_DIRECTORY), "delegated_grant")
                .await?
                .into(),
            grants_directory: path.join(GRANTS_DIRECTORY),
            encrypted,
            stable_grant_ids,
        })
    }

    fn require_encryption(&self) -> Result<()> {
        if self.encrypted {
            Ok(())
        } else {
            Err(EncryptionRequired.into())
        }
    }

    /// Storing or releasing a grant needs at-rest encryption and a configured
    /// identity hash pepper.
    fn require_grant_storage(&self) -> Result<()> {
        self.require_encryption()?;
        if self.stable_grant_ids {
            Ok(())
        } else {
            Err(EphemeralPepper.into())
        }
    }

    /// The grant stored under `key`'s record id, if its own key is `key`.
    async fn grant_locked(
        &self,
        key: &GrantKey,
    ) -> Result<Option<DelegatedGrant>> {
        let Some(grant) = self
            .grants
            .get(&key.record_id())
            .await?
        else {
            return Ok(None);
        };
        if grant.key() != *key || grant.id != key.record_id() {
            warn!(
                target: "credential_delegation",
                "A delegated grant record does not belong to the key it is stored under; it is not used"
            );
            return Ok(None);
        }
        Ok(Some(grant))
    }

    async fn mutate<Output, Operation, Pending>(
        &self,
        operation: Operation,
    ) -> Result<Output>
    where
        Output: Send + 'static,
        Operation: FnOnce(Self) -> Pending + Send + 'static,
        Pending: std::future::Future<Output = Result<Output>> + Send,
    {
        let guard = self.mutation_lock().await?;
        let store = self.clone();
        tokio::spawn(async move {
            let _guard = guard;
            operation(store).await
        })
        .await
        .context("Delegation vault mutation task failed")?
    }

    /// Like `mutate`, but runs only when the lock is free right now, and
    /// returns `None` instead of waiting when it is held.
    async fn try_mutate<Output, Operation, Pending>(
        &self,
        operation: Operation,
    ) -> Result<Option<Output>>
    where
        Output: Send + 'static,
        Operation: FnOnce(Self) -> Pending + Send + 'static,
        Pending: std::future::Future<Output = Result<Output>> + Send,
    {
        let file = self
            .open_mutation_lock()
            .await?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).context("Failed to lock delegation vault mutations");
            }
        }
        let store = self.clone();
        tokio::spawn(async move {
            let _guard = file;
            operation(store)
                .await
                .map(Some)
        })
        .await
        .context("Delegation vault mutation task failed")?
    }

    async fn open_mutation_lock(&self) -> Result<File> {
        let path = self
            .mutation_lock_path
            .clone();
        tokio::task::spawn_blocking(move || {
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(path)
                .context("Failed to open delegation vault mutation lock")
        })
        .await
        .context("Delegation vault mutation lock task failed")?
    }

    async fn mutation_lock(&self) -> Result<File> {
        let file = self
            .open_mutation_lock()
            .await?;
        tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            let mut retry = tokio::time::interval(std::time::Duration::from_millis(10));
            retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                match file.try_lock() {
                    Ok(()) => return Ok(file),
                    Err(std::fs::TryLockError::WouldBlock) => {
                        retry.tick().await;
                    }
                    Err(std::fs::TryLockError::Error(error)) => {
                        return Err(error).context("Failed to lock delegation vault mutations");
                    }
                }
            }
        })
        .await
        .context("Delegation vault mutation lock timed out")?
    }

    async fn store_locked(
        &self,
        mut token: DelegationToken,
    ) -> Result<DelegationToken> {
        if let Some(current) = self
            .storage
            .get(&token.id)
            .await?
        {
            anyhow::ensure!(same_owner(&current, &token), "Delegation token ID belongs to another identity");
        }
        let mut existing = self
            .storage
            .list_all()
            .await?
            .into_iter()
            .filter(|current| same_owner(current, &token))
            .collect::<Vec<_>>();
        // Keep the newest and remove the rest, so storing a credential never
        // fails on duplicates.
        existing.sort_by(newest_first);
        for duplicate in existing.iter().skip(1) {
            self.refreshes
                .delete(&duplicate.id)
                .await?;
            self.storage
                .delete(&duplicate.id)
                .await?;
            info!(
                target: "credential_delegation",
                id = %duplicate.id,
                agent_did = %duplicate.agent_did,
                provider_id = %duplicate.provider_id,
                "Removed a duplicate delegation token for this identity"
            );
        }
        if let Some(current) = existing.first() {
            token.id = current.id.clone();
            token.created_at = current.created_at;
            token.updated_at = next_version(current.updated_at)?;
        } else {
            token.updated_at = Utc::now();
        }
        self.storage
            .save_atomic(&token)
            .await
            .context("Failed to store delegation token")?;
        info!(
            target: "credential_delegation",
            id = %token.id,
            agent_did = %token.agent_did,
            user_hash = %token.user_identity_hash,
            provider_id = %token.provider_id,
            scopes = ?token.scopes,
            expires_at = ?token.expires_at,
            "Delegation token stored in vault"
        );
        Ok(token)
    }
}

#[async_trait]
impl DelegationVaultStorage for FileSystemDelegationVaultStore {
    async fn store(
        &self,
        token: DelegationToken,
    ) -> Result<DelegationToken> {
        self.mutate(move |store| async move {
            store
                .store_locked(token)
                .await
        })
        .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<DelegationToken>> {
        self.storage.get(id).await
    }

    async fn lookup(
        &self,
        agent_did: &str,
        user_identity_hash: &str,
        provider_id: &str,
    ) -> Result<VaultLookupResult> {
        let all = self
            .storage
            .list_all()
            .await?;
        let found = all
            .into_iter()
            .filter(|t| {
                t.agent_did == agent_did
                    && t.user_identity_hash == user_identity_hash
                    && t.credential_provider_id == provider_id
            })
            .min_by(newest_first);

        match found {
            Some(token) => {
                if token.is_expired() {
                    if token.can_refresh() {
                        debug!(
                            target: "credential_delegation",
                            agent_did = %agent_did,
                            user_hash = %user_identity_hash,
                            provider_id = %provider_id,
                            "Vault lookup: token expired but refreshable"
                        );
                        Ok(VaultLookupResult::ExpiredRefreshable(token))
                    } else {
                        debug!(
                            target: "credential_delegation",
                            agent_did = %agent_did,
                            user_hash = %user_identity_hash,
                            provider_id = %provider_id,
                            "Vault lookup: token expired, no refresh token"
                        );
                        Ok(VaultLookupResult::ExpiredNoRefresh(token))
                    }
                } else {
                    debug!(
                        target: "credential_delegation",
                        agent_did = %agent_did,
                        user_hash = %user_identity_hash,
                        provider_id = %provider_id,
                        "Vault lookup: valid token found"
                    );
                    Ok(VaultLookupResult::Found(token))
                }
            }
            None => {
                debug!(
                    target: "credential_delegation",
                    agent_did = %agent_did,
                    user_hash = %user_identity_hash,
                    provider_id = %provider_id,
                    "Vault lookup: no token found"
                );
                Ok(VaultLookupResult::NotFound)
            }
        }
    }

    async fn list_all(&self) -> Result<Vec<DelegationToken>> {
        self.storage.list_all().await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<bool> {
        let id = id.to_string();
        self.mutate(move |store| async move {
            let _access_change =
                crate::mcp::subscriptions::AccessChange::begin(crate::mcp::subscriptions::AccessScope::Appliance);
            store
                .revoke_pending_consents()
                .await?;
            let exists = store
                .storage
                .get(&id)
                .await?
                .is_some();
            if exists {
                store
                    .refreshes
                    .delete(&id)
                    .await?;
                store
                    .storage
                    .delete(&id)
                    .await?;
                info!(
                    target: "credential_delegation",
                    id = %id,
                    "Delegation token revoked"
                );
            }
            Ok(exists)
        })
        .await
    }

    async fn delete_by_user(
        &self,
        user_identity_hash: &str,
    ) -> Result<usize> {
        let user_identity_hash = user_identity_hash.to_string();
        self.mutate(move |store| async move {
            let _access_change =
                crate::mcp::subscriptions::AccessChange::begin(crate::mcp::subscriptions::AccessScope::Appliance);
            store
                .revoke_pending_consents()
                .await?;
            let all = store
                .storage
                .list_all()
                .await?;
            let to_delete: Vec<String> = all
                .iter()
                .filter(|t| t.user_identity_hash == user_identity_hash)
                .map(|t| t.id.clone())
                .collect();
            let count = to_delete.len();
            for id in to_delete {
                store
                    .refreshes
                    .delete(&id)
                    .await?;
                store
                    .storage
                    .delete(&id)
                    .await?;
            }
            if count > 0 {
                info!(
                    target: "credential_delegation",
                    user_hash = %user_identity_hash,
                    count = %count,
                    "All delegation tokens revoked for user"
                );
            }
            Ok(count)
        })
        .await
    }

    async fn update(
        &self,
        mut token: DelegationToken,
    ) -> Result<DelegationToken> {
        self.mutate(move |store| async move {
            let current = store
                .storage
                .get(&token.id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Delegation token was revoked"))?;
            anyhow::ensure!(
                current.updated_at == token.updated_at
                    && current.agent_did == token.agent_did
                    && current.user_identity_hash == token.user_identity_hash
                    && current.credential_provider_id == token.credential_provider_id
                    && current.created_at == token.created_at
                    && current.consent_granted_at == token.consent_granted_at,
                "Delegation token changed during refresh"
            );
            token.updated_at = next_version(current.updated_at)?;
            token.last_used_at = current.last_used_at;
            store
                .storage
                .save_atomic(&token)
                .await
                .context("Failed to update delegation token")?;
            Ok(token)
        })
        .await
    }

    async fn mark_used(
        &self,
        id: &str,
    ) -> Result<()> {
        // `last_used_at` is informational, so a request never queues for the vault
        // lock to record it: after a few quick attempts while another write holds
        // the lock, this use is not recorded. The write still takes the lock, so it
        // cannot restore a record that a revocation just deleted.
        const ATTEMPTS: usize = 3;
        for attempt in 1..=ATTEMPTS {
            let id = id.to_string();
            let recorded = self
                .try_mutate(move |store| async move {
                    if let Some(mut token) = store.storage.get(&id).await? {
                        token.last_used_at = Some(Utc::now());
                        store
                            .storage
                            .save_atomic(&token)
                            .await?;
                    }
                    Ok(())
                })
                .await?;
            if recorded.is_some() {
                return Ok(());
            }
            if attempt < ATTEMPTS {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
        tracing::debug!(target: "credential_delegation", "Skipped recording last use; the vault is busy");
        Ok(())
    }

    async fn consent_snapshot(
        &self,
        agent_did: &str,
        user_identity_hash: &str,
        provider_id: &str,
    ) -> Result<ConsentSnapshot> {
        let agent_did = agent_did.to_string();
        let user_identity_hash = user_identity_hash.to_string();
        let provider_id = provider_id.to_string();
        self.mutate(move |store| async move {
            store
                .consent_snapshot_locked(&agent_did, &user_identity_hash, &provider_id)
                .await
        })
        .await
    }

    async fn access_revision(&self) -> Result<Option<uuid::Uuid>> {
        self.consents
            .access_revision()
            .await
    }

    async fn stage_consent(
        &self,
        consent: StagedConsent,
        now: u64,
    ) -> Result<()> {
        self.mutate(move |store| async move {
            store
                .stage_consent_locked(consent, now)
                .await
        })
        .await
    }

    async fn staged_consent(
        &self,
        id: uuid::Uuid,
        binding_digest: [u8; 32],
        now: u64,
    ) -> Result<Option<StagedConsent>> {
        self.mutate(move |store| async move {
            store
                .staged_consent_locked(id, binding_digest, now)
                .await
        })
        .await
    }

    async fn activate_consent(
        &self,
        id: uuid::Uuid,
        binding_digest: [u8; 32],
        now: u64,
    ) -> Result<DelegationToken> {
        self.mutate(move |store| async move {
            let consent = store
                .staged_consent_locked(id, binding_digest, now)
                .await?
                .context("Verified consent is missing, revoked or expired")?;
            let token = store
                .store_locked(consent.credential)
                .await?;
            store
                .consents
                .staged
                .delete(&consent.id)
                .await?;
            Ok(token)
        })
        .await
    }

    async fn claim_refresh(
        &self,
        token: &DelegationToken,
        now: u64,
    ) -> Result<RefreshClaim, RefreshError> {
        let token = token.clone();
        self.mutate(move |store| async move {
            Ok(store
                .claim_refresh_locked(&token, now)
                .await)
        })
        .await
        .map_err(|_| RefreshError::Unavailable)?
    }

    async fn complete_refresh(
        &self,
        claim: RefreshClaim,
        response: super::OAuthTokenResponse,
        now: u64,
    ) -> Result<DelegationToken, RefreshError> {
        self.mutate(move |store| async move {
            Ok(store
                .complete_refresh_locked(claim, response, now)
                .await)
        })
        .await
        .map_err(|_| RefreshError::Unavailable)?
    }

    async fn grant(
        &self,
        key: &GrantKey,
    ) -> Result<Option<DelegatedGrant>> {
        self.require_grant_storage()?;
        self.grant_locked(key).await
    }

    async fn store_grant(
        &self,
        mut grant: DelegatedGrant,
    ) -> Result<StoredGrant> {
        self.require_grant_storage()?;
        let key = grant.key();
        grant.id = key.record_id();
        self.mutate(move |store| async move {
            let _access_change = crate::mcp::subscriptions::AccessChange::begin(
                crate::mcp::subscriptions::AccessScope::owned_by(grant.tenant_id.as_deref()),
            );
            let replaced = store
                .grant_locked(&key)
                .await?;
            grant.updated_at = match replaced.as_ref() {
                Some(previous) => next_version(previous.updated_at)?,
                None => Utc::now(),
            };
            store
                .grants
                .save_atomic(&grant)
                .await
                .context("Failed to store delegated grant")?;
            info!(
                target: "credential_delegation",
                grant_id = %grant.id,
                surface_id = %grant.surface_id,
                hop = %grant.hop,
                credential_provider_id = %grant.credential_provider_id,
                replaced = replaced.is_some(),
                "Delegated grant stored in vault"
            );
            Ok(StoredGrant { grant, replaced })
        })
        .await
    }

    async fn provider_grants(
        &self,
        credential_provider_id: &str,
    ) -> Result<Vec<DelegatedGrant>> {
        Ok(self
            .all_grants()
            .await?
            .into_iter()
            .filter(|grant| grant.credential_provider_id == credential_provider_id)
            .collect())
    }

    async fn all_grants(&self) -> Result<Vec<DelegatedGrant>> {
        self.require_encryption()?;
        self.grants.list_all().await
    }

    async fn has_stored_grants(&self) -> Result<bool> {
        let mut entries = match tokio::fs::read_dir(&self.grants_directory).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).context("Failed to read the delegated grants directory"),
        };
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".json") || name.ends_with(".json.enc") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn delete_grant(
        &self,
        id: &str,
    ) -> Result<Option<DelegatedGrant>> {
        let id = id.to_string();
        self.mutate(move |store| async move {
            let Some(grant) = store.grants.get(&id).await? else {
                return Ok(None);
            };
            let _access_change = crate::mcp::subscriptions::AccessChange::begin(
                crate::mcp::subscriptions::AccessScope::owned_by(grant.tenant_id.as_deref()),
            );
            store
                .grants
                .delete(&id)
                .await?;
            info!(target: "credential_delegation", grant_id = %id, "Delegated grant deleted");
            Ok(Some(grant))
        })
        .await
    }

    async fn mark_grant_used(
        &self,
        id: &str,
    ) -> Result<()> {
        let id = id.to_string();
        let recorded = self
            .try_mutate(move |store| async move {
                if let Some(mut grant) = store.grants.get(&id).await? {
                    grant.last_used_at = Some(Utc::now());
                    store
                        .grants
                        .save_atomic(&grant)
                        .await?;
                }
                Ok(())
            })
            .await?;
        if recorded.is_none() {
            debug!(target: "credential_delegation", "Skipped recording a grant's last use; the vault is busy");
        }
        Ok(())
    }
}

fn same_owner(
    first: &DelegationToken,
    second: &DelegationToken,
) -> bool {
    first.agent_did == second.agent_did
        && first.user_identity_hash == second.user_identity_hash
        && first.credential_provider_id == second.credential_provider_id
}

fn next_version(previous: chrono::DateTime<Utc>) -> Result<chrono::DateTime<Utc>> {
    let incremented = previous
        .checked_add_signed(Duration::nanoseconds(1))
        .context("Delegation token version is out of range")?;
    Ok(Utc::now().max(incremented))
}

/// Orders one identity's records newest first. Earlier releases stored by id
/// alone, so a refresh or callback race can have left several; lookups use the
/// newest until storing a credential consolidates them.
fn newest_first(
    first: &DelegationToken,
    second: &DelegationToken,
) -> std::cmp::Ordering {
    second
        .updated_at
        .cmp(&first.updated_at)
        .then_with(|| {
            second
                .created_at
                .cmp(&first.created_at)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_vault_updates_hold_the_lock_until_their_write_finishes() {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        struct PausedStorage {
            inner: Arc<dyn StorageBackend<DelegationToken>>,
            started: Arc<Semaphore>,
            release: Arc<Semaphore>,
        }

        #[async_trait]
        impl StorageBackend<DelegationToken> for PausedStorage {
            async fn save(
                &self,
                token: &DelegationToken,
            ) -> Result<()> {
                self.started.add_permits(1);
                self.release
                    .acquire()
                    .await
                    .unwrap()
                    .forget();
                self.inner
                    .save_atomic(token)
                    .await
            }
            async fn get(
                &self,
                id: &str,
            ) -> Result<Option<DelegationToken>> {
                self.inner.get(id).await
            }
            async fn list_all(&self) -> Result<Vec<DelegationToken>> {
                self.inner.list_all().await
            }
            async fn delete(
                &self,
                id: &str,
            ) -> Result<()> {
                self.inner.delete(id).await
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let first = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let other = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let mut token = first
            .store(super::super::tests::make_token(Some(3600), true))
            .await
            .unwrap();
        token.access_token = "in-flight-update".into();
        let id = token.id.clone();
        let started = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let paused = FileSystemDelegationVaultStore {
            storage: Arc::new(PausedStorage {
                inner: first.storage.clone(),
                started: started.clone(),
                release: release.clone(),
            }),
            ..first
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let update = tokio::spawn(async move { paused.update(token).await });
            started
                .acquire()
                .await
                .unwrap()
                .forget();
            update.abort();
            assert!(
                update
                    .await
                    .unwrap_err()
                    .is_cancelled()
            );
            let probe = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&other.mutation_lock_path)
                .unwrap();
            assert!(matches!(probe.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
            release.add_permits(1);
            assert!(
                other
                    .delete(&id)
                    .await
                    .unwrap()
            );
            assert!(
                other
                    .get(&id)
                    .await
                    .unwrap()
                    .is_none()
            );
        })
        .await
        .expect("cancelled mutation must eventually release its lock");
    }

    /// Earlier releases stored by id alone, so one identity can hold several
    /// records. Lookups use the newest, and storing a credential for it keeps
    /// the newest record and removes the rest instead of failing.
    #[tokio::test]
    async fn storing_consolidates_duplicate_records_left_by_earlier_releases() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let record = |id: &str, access_token: &str, updated_at: &str| -> DelegationToken {
            serde_json::from_value(serde_json::json!({
                "id": id, "agent_did": "did:example:agent", "user_identity_hash": "user-hash",
                "credential_provider_id": "provider", "provider_id": "provider",
                "access_token": access_token, "scopes": ["read"],
                "consent_granted_at": "2026-09-01T00:00:00Z", "created_at": "2026-09-01T00:00:00Z",
                "updated_at": updated_at
            }))
            .unwrap()
        };
        // Written the way earlier releases wrote them: saved by id, no de-duplication.
        for token in [
            record("older", "older-credential", "2026-09-01T00:00:00Z"),
            record("newer", "newer-credential", "2026-09-02T00:00:00Z"),
        ] {
            store
                .storage
                .save_atomic(&token)
                .await
                .unwrap();
        }
        // Until they are consolidated, a lookup uses the newest.
        match store
            .lookup("did:example:agent", "user-hash", "provider")
            .await
            .unwrap()
        {
            VaultLookupResult::Found(found)
            | VaultLookupResult::ExpiredRefreshable(found)
            | VaultLookupResult::ExpiredNoRefresh(found) => assert_eq!(found.id, "newer"),
            VaultLookupResult::NotFound => panic!("the identity has records"),
        }
        let stored = store
            .store(record("fresh", "fresh-credential", "2026-09-03T00:00:00Z"))
            .await
            .expect("storing for an identity with duplicate records must succeed");
        assert_eq!(stored.id, "newer");
        let remaining = store
            .storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1, "{remaining:?}");
        assert_eq!(remaining[0].id, "newer");
        assert_eq!(remaining[0].access_token, "fresh-credential");
    }

    /// Recording a use never waits for the vault lock: while another write
    /// holds it the use is skipped, and once it is free the use is recorded.
    #[tokio::test]
    async fn marking_a_use_skips_instead_of_waiting_for_a_busy_vault() {
        let directory = tempfile::tempdir().unwrap();
        let first = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let second = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let token: DelegationToken = serde_json::from_value(serde_json::json!({
            "id": "in-use", "agent_did": "did:example:agent", "user_identity_hash": "user-hash",
            "credential_provider_id": "provider", "provider_id": "provider",
            "access_token": "credential", "scopes": ["read"],
            "consent_granted_at": "2026-09-01T00:00:00Z", "created_at": "2026-09-01T00:00:00Z",
            "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap();
        first
            .storage
            .save_atomic(&token)
            .await
            .unwrap();

        let held = first
            .mutation_lock()
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(200), second.mark_used("in-use"))
            .await
            .expect("recording a use must not wait for the vault lock")
            .unwrap();
        let skipped = second
            .storage
            .get("in-use")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(skipped.last_used_at, None);

        drop(held);
        second
            .mark_used("in-use")
            .await
            .unwrap();
        let recorded = second
            .storage
            .get("in-use")
            .await
            .unwrap()
            .unwrap();
        assert!(
            recorded
                .last_used_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn cancelled_vault_lock_waiters_do_not_keep_the_lock() {
        let directory = tempfile::tempdir().unwrap();
        let first = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let second = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let held = first
            .mutation_lock()
            .await
            .unwrap();
        let waiting = tokio::time::timeout(std::time::Duration::from_millis(30), second.mutation_lock()).await;
        assert!(waiting.is_err());
        drop(held);
        let reacquired = tokio::time::timeout(std::time::Duration::from_secs(1), second.mutation_lock())
            .await
            .unwrap()
            .unwrap();
        drop(reacquired);
        assert!(
            first
                .mutation_lock()
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn stale_vault_writes_never_restore_revoked_or_replaced_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let first = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let second = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let original = first
            .store(super::super::tests::make_token(Some(3600), true))
            .await
            .unwrap();
        first
            .mark_used(&original.id)
            .await
            .unwrap();
        let mut refreshed = original.clone();
        refreshed.access_token = "refreshed-credential".into();
        let stored = second
            .update(refreshed.clone())
            .await
            .unwrap();
        assert!(stored.updated_at > original.updated_at);
        assert!(stored.last_used_at.is_some());
        assert!(
            first
                .update(refreshed)
                .await
                .is_err()
        );
        assert_eq!(
            first
                .get(&stored.id)
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "refreshed-credential"
        );
        assert!(
            first
                .delete(&stored.id)
                .await
                .unwrap()
        );
        assert!(
            second
                .update(stored.clone())
                .await
                .is_err()
        );
        second
            .mark_used(&stored.id)
            .await
            .unwrap();
        assert!(
            first
                .get(&stored.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !first
                .delete(&stored.id)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn independent_vault_instances_serialize_refresh_writes() {
        let directory = tempfile::tempdir().unwrap();
        let first = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let second = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let token = first
            .store(super::super::tests::make_token(Some(3600), true))
            .await
            .unwrap();
        let (left, right) = tokio::join!(first.update(token.clone()), second.update(token.clone()));
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let latest = first
            .get(&token.id)
            .await
            .unwrap()
            .unwrap();
        assert!(latest.updated_at > token.updated_at);
        assert_eq!(
            second
                .delete_by_user(&token.user_identity_hash)
                .await
                .unwrap(),
            1
        );
        assert!(
            first
                .update(latest)
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
    }

    #[tokio::test]
    async fn simultaneous_consent_callbacks_replace_one_composite_credential() {
        let directory = tempfile::tempdir().unwrap();
        let first = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let second = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let initial = super::super::tests::make_token(Some(3600), true);
        let mut replacement = initial.clone();
        replacement.id = uuid::Uuid::new_v4().to_string();
        replacement.access_token = "replacement-credential".into();
        let (left, right) = tokio::join!(first.store(initial), second.store(replacement));
        let left = left.unwrap();
        let right = right.unwrap();
        assert_eq!(left.id, right.id);
        assert_ne!(left.updated_at, right.updated_at);
        assert_eq!(
            first
                .list_all()
                .await
                .unwrap()
                .len(),
            1
        );
        let stored = first
            .get(&left.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.updated_at,
            left.updated_at
                .max(right.updated_at)
        );
        let mut other_owner = stored.clone();
        other_owner.user_identity_hash = "another-user".into();
        assert!(
            second
                .store(other_owner)
                .await
                .is_err()
        );
        assert_eq!(
            first
                .get(&stored.id)
                .await
                .unwrap()
                .unwrap()
                .user_identity_hash,
            stored.user_identity_hash
        );
    }

    /// Grants by binding are kept only while at-rest encryption is active.
    fn with_at_rest_encryption() {
        unsafe {
            std::env::set_var("DELEGATED_GRANTS_TEST_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        }
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "DELEGATED_GRANTS_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        })
        .unwrap();
    }

    async fn encrypted_vault(directory: &std::path::Path) -> FileSystemDelegationVaultStore {
        with_at_rest_encryption();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        FileSystemDelegationVaultStore::new(directory.into())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn while_the_pepper_is_ephemeral_grants_are_neither_stored_nor_released() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        vault
            .store_grant(grant(&key(), "owner-access"))
            .await
            .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(false);
        let restarted = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let refused = restarted
            .store_grant(grant(&key(), "other-access"))
            .await
            .unwrap_err();
        assert!(refused.is::<EphemeralPepper>(), "{refused}");
        assert!(
            restarted
                .grant(&key())
                .await
                .unwrap_err()
                .is::<EphemeralPepper>()
        );
        assert_eq!(
            restarted
                .provider_grants("provider")
                .await
                .unwrap()
                .len(),
            1,
            "grants can still be listed, so they can be revoked and removed"
        );
    }

    #[tokio::test]
    async fn a_providers_grants_include_those_stored_under_another_pepper() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let mut earlier = grant(&key(), "earlier-access");
        earlier.id = format!("grant-{}", "e".repeat(64));
        vault
            .grants
            .save_atomic(&earlier)
            .await
            .unwrap();
        let listed = vault
            .provider_grants("provider")
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, earlier.id);
        assert!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .is_none(),
            "a grant whose id is not its key's under this pepper is never released"
        );
        vault
            .delete_grant(&earlier.id)
            .await
            .unwrap()
            .expect("the grant is deleted by the id it was stored under");
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_grant_is_found_by_its_key_and_by_no_other() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let stored = vault
            .store_grant(grant(&key(), "owner-access"))
            .await
            .unwrap();
        assert_eq!(stored.grant.id, key().record_id());
        assert!(stored.replaced.is_none());
        let found = vault
            .grant(&key())
            .await
            .unwrap()
            .expect("the grant is found under its key");
        assert_eq!(found.access_token, "owner-access");
        let caller =
            GrantKey::caller(Some("tenant-a"), "surface", "transit-point-id", "provider", &"a".repeat(64)).unwrap();
        for other in [
            GrantKey { tenant_id: None, ..key() },
            GrantKey {
                tenant_id: Some("tenant-b".into()),
                ..key()
            },
            GrantKey {
                surface_id: "other-surface".into(),
                ..key()
            },
            GrantKey {
                hop: "other-transit-point".into(),
                ..key()
            },
            GrantKey {
                credential_provider_id: "other-provider".into(),
                ..key()
            },
            caller,
        ] {
            assert!(
                vault
                    .grant(&other)
                    .await
                    .unwrap()
                    .is_none(),
                "{other:?}"
            );
        }
        assert!(
            vault
                .list_all()
                .await
                .unwrap()
                .is_empty(),
            "grants are not agent-keyed tokens"
        );
    }

    #[tokio::test]
    async fn a_grant_is_written_encrypted_under_an_id_that_names_nothing() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        vault
            .store_grant(grant(&key(), "owner-access"))
            .await
            .unwrap();
        let files: Vec<_> = std::fs::read_dir(
            directory
                .path()
                .join("delegated_grants"),
        )
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
        assert_eq!(files.len(), 1, "{files:?}");
        let name = files[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(name, format!("{}.json.enc", key().record_id()));
        let content = std::fs::read_to_string(&files[0]).unwrap();
        for plaintext in ["owner-access", "owner-access-refresh", "transit-point-id", "tenant-a"] {
            assert!(!content.contains(plaintext), "the file shows {plaintext}");
        }
    }

    #[tokio::test]
    async fn without_at_rest_encryption_grants_are_neither_stored_nor_read() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let refused = vault
            .store_grant(grant(&key(), "owner-access"))
            .await
            .unwrap_err();
        assert!(refused.is::<EncryptionRequired>(), "{refused}");
        assert!(
            vault
                .grant(&key())
                .await
                .unwrap_err()
                .is::<EncryptionRequired>()
        );
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap_err()
                .is::<EncryptionRequired>()
        );
        assert!(
            !directory
                .path()
                .join("delegated_grants")
                .join(format!("{}.json", key().record_id()))
                .exists()
        );
    }

    #[tokio::test]
    async fn storing_a_grant_again_replaces_it_and_returns_the_one_replaced() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let first = vault
            .store_grant(grant(&key(), "first-access"))
            .await
            .unwrap()
            .grant;
        let second = vault
            .store_grant(grant(&key(), "second-access"))
            .await
            .unwrap();
        assert_eq!(
            second
                .replaced
                .as_ref()
                .map(|grant| grant.access_token.as_str()),
            Some("first-access")
        );
        assert!(second.grant.updated_at > first.updated_at);
        assert_eq!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "second-access"
        );
    }

    #[tokio::test]
    async fn a_record_under_another_keys_id_is_never_returned() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let mut planted = grant(
            &GrantKey {
                surface_id: "attacker-surface".into(),
                ..key()
            },
            "planted-access",
        );
        planted.id = key().record_id();
        vault
            .grants
            .save_atomic(&planted)
            .await
            .unwrap();
        assert!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            vault
                .provider_grants("provider")
                .await
                .unwrap()
                .len(),
            1,
            "its provider's listing names it, so deleting the provider removes it"
        );
    }

    #[tokio::test]
    async fn a_providers_grants_are_listed_and_deleted_one_by_one() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let other_hop = GrantKey {
            hop: "other-transit-point".into(),
            ..key()
        };
        let other_provider = GrantKey {
            credential_provider_id: "other-provider".into(),
            ..key()
        };
        for key in [key(), other_hop.clone(), other_provider.clone()] {
            vault
                .store_grant(grant(&key, "access"))
                .await
                .unwrap();
        }
        let mut ids: Vec<String> = vault
            .provider_grants("provider")
            .await
            .unwrap()
            .into_iter()
            .map(|grant| grant.id)
            .collect();
        ids.sort();
        let mut expected = vec![key().record_id(), other_hop.record_id()];
        expected.sort();
        assert_eq!(ids, expected);

        let deleted = vault
            .delete_grant(&key().record_id())
            .await
            .unwrap()
            .expect("the grant existed");
        assert_eq!(deleted.access_token, "access");
        assert!(
            vault
                .delete_grant(&key().record_id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            vault
                .grant(&other_provider)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn using_a_grant_records_when() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        vault
            .store_grant(grant(&key(), "access"))
            .await
            .unwrap();
        vault
            .mark_grant_used(&key().record_id())
            .await
            .unwrap();
        assert!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .unwrap()
                .last_used_at
                .is_some()
        );
    }
}
