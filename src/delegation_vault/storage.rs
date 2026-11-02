//! Filesystem storage for delegation vault tokens

use super::connects::{
    CLAIMED_CONNECTS_DIRECTORY, ConnectClaim, MAX_PENDING_CONNECTS_PER_BINDING, MAX_PENDING_CONNECTS_PER_PRINCIPAL,
    PENDING_CONNECTS_DIRECTORY, PendingConnect, TooManyPendingConnects,
};
use super::grants::{
    DelegatedGrant, EncryptionRequired, EphemeralPepper, FailedRefresh, GRANTS_DIRECTORY, GrantBinding, GrantKey,
    ObtainedTokens, PEPPER_FINGERPRINT_FILE, PepperMismatch, Principals, StoredGrant, UnreadableGrant,
    UnreadableReason,
};
use super::{DelegationToken, VaultLookupResult};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use tracing::{debug, info, warn};

use crate::storage::filesystem::{StorageBackend, uncached_storage};

mod consent;
pub use consent::{ConsentSnapshot, StagedConsent};
mod refresh;
pub use refresh::{RefreshClaim, RefreshError};
mod grant_refresh;
pub use grant_refresh::{GRANT_REFRESH_CLAIMS_DIRECTORY, GrantRefreshClaim};
mod deferred_revocation;
pub use deferred_revocation::{DEFERRED_REVOCATIONS_DIRECTORY, Deferral, DeferredRevocation};

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
    /// with [`EphemeralPepper`] while the identity hash pepper is not
    /// configured, and with [`PepperMismatch`] when no grant is found and the
    /// grants stored were written under another pepper.
    async fn grant(
        &self,
        _key: &GrantKey,
    ) -> Result<Option<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Store `grant` under its key, replacing a grant of the same key, which is
    /// returned so the caller can revoke its tokens. The record id is derived
    /// from the key; the grant's own `id` is ignored. Fails as [`Self::grant`]
    /// does, and with [`PepperMismatch`] while grants written under another
    /// pepper are stored.
    async fn store_grant(
        &self,
        _grant: DelegatedGrant,
    ) -> Result<StoredGrant> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// The grants of `binding` that `principals` names, found by their record
    /// ids, so no other binding's grant is read or decrypted. Fails with
    /// [`UnreadableGrant`] when one of them cannot be read, including while
    /// at-rest encryption is off, and with [`PepperMismatch`] when none is
    /// found and the grants stored were written under another pepper.
    async fn binding_grants(
        &self,
        _binding: &GrantBinding,
        _principals: Principals,
    ) -> Result<Vec<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Every grant made with one credential provider, found by their record
    /// ids, so no other provider's grant is read. Fails as
    /// [`Self::binding_grants`] does.
    async fn provider_grants(
        &self,
        _credential_provider_id: &str,
    ) -> Result<Vec<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// The record ids of every grant stored for `binding`, read from the file
    /// names alone, so it can be answered whatever the grants hold. Fails with
    /// [`PepperMismatch`] when none is found and the grants stored were
    /// written under another pepper, whose ids this gateway cannot derive.
    async fn binding_grant_ids(
        &self,
        _binding: &GrantBinding,
    ) -> Result<Vec<String>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Delete the grant with this record id, returning it if it existed.
    #[cfg(test)]
    async fn delete_grant(
        &self,
        _id: &str,
    ) -> Result<Option<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Delete the grant with this record id only while it holds
    /// `access_token`, the one a vendor refused, returning it; `None` when no
    /// grant is stored there, or it holds another token since, as after a
    /// refresh or a reconnect, and is kept.
    async fn delete_grant_holding(
        &self,
        _id: &str,
        _access_token: &str,
    ) -> Result<Option<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Delete the grant with this record id only while it is the connection
    /// made at `connected_at`, its `created_at`, however often it was
    /// refreshed since, returning it; `None` when no grant is stored there, or
    /// the person connected again since, whose grant is kept.
    async fn delete_grant_of_connection(
        &self,
        _id: &str,
        _connected_at: DateTime<Utc>,
    ) -> Result<Option<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Keep `grant`, removed from the vault already, until whether to revoke
    /// it can be decided: its provider's revocation ends the person's whole
    /// authorization, and the vault could not tell whether another grant of
    /// theirs still uses it. The daily sweep decides. Kept encrypted, and only
    /// while at-rest encryption is active.
    async fn defer_revocation(
        &self,
        _grant: DelegatedGrant,
    ) -> Result<()> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Keep `revocation`, new or tried again, under its id, until it is
    /// forgotten ([`Self::forget_deferred_revocation`]), so a revocation under
    /// way survives a stop. Kept encrypted, and only while at-rest encryption
    /// is active.
    async fn keep_revocation(
        &self,
        _revocation: &DeferredRevocation,
    ) -> Result<()> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Every revocation deferred, oldest first. One that cannot be read is
    /// left out, and logged.
    async fn deferred_revocations(&self) -> Result<Vec<DeferredRevocation>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Forget a deferred revocation once it was decided.
    async fn forget_deferred_revocation(
        &self,
        _id: &str,
    ) -> Result<()> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Delete the grant record with this id without reading it, so an
    /// unreadable grant can be removed. `tenant_id` is the tenant whose access
    /// the removal changes, `None` when it is untenanted or unknown. Returns
    /// whether a record was there. Refuses an id that is not a grant's.
    async fn purge_grant(
        &self,
        _id: &str,
        _tenant_id: Option<&str>,
    ) -> Result<bool> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Record that a grant was used, when the vault is not busy.
    async fn mark_grant_used(
        &self,
        _id: &str,
    ) -> Result<()> {
        Ok(())
    }

    /// The record ids of every grant stored, read from the file names alone.
    async fn grant_ids(&self) -> Result<Vec<String>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Whether this gateway derives the record ids the grants stored were
    /// written under: `AG_IDENTITY_HASH_PEPPER` is set, and no grant stored
    /// was written under another pepper. Until it does, a grant's id says
    /// nothing about whether it can still be released.
    async fn derives_stored_grant_ids(&self) -> Result<bool> {
        Ok(false)
    }

    /// The grant stored under the record id `id`, read whatever pepper it was
    /// written under; `None` when there is none. Fails when it cannot be read.
    async fn grant_by_id(
        &self,
        _id: &str,
    ) -> Result<Option<DelegatedGrant>> {
        anyhow::bail!("This vault does not keep grants by binding")
    }

    /// Claim the refresh of `grant`, as it was read, once across every node
    /// sharing the vault: [`RefreshError::Changed`] when it has changed since,
    /// [`RefreshError::InProgress`] while another refresh of its refresh token
    /// runs, and [`RefreshError::Uncertain`] when one died part way.
    async fn claim_grant_refresh(
        &self,
        _grant: &DelegatedGrant,
        _now: DateTime<Utc>,
    ) -> Result<GrantRefreshClaim, RefreshError> {
        Err(RefreshError::Unavailable)
    }

    /// Write the tokens a claimed refresh obtained, and return the grant.
    async fn complete_grant_refresh(
        &self,
        _claim: GrantRefreshClaim,
        _tokens: ObtainedTokens,
        _now: DateTime<Utc>,
    ) -> Result<DelegatedGrant, RefreshError> {
        Err(RefreshError::Unavailable)
    }

    /// Record that a claimed refresh failed, as `failure` says.
    async fn fail_grant_refresh(
        &self,
        _claim: GrantRefreshClaim,
        _failure: FailedRefresh,
        _now: DateTime<Utc>,
    ) -> Result<DelegatedGrant, RefreshError> {
        Err(RefreshError::Unavailable)
    }

    /// Delete the grant a claimed refresh was for, once the authorization
    /// server refused its refresh token (`invalid_grant`), and return it so
    /// its tokens can be revoked: only while the claim is still the stored
    /// one and the grant the version it was claimed for, otherwise
    /// [`RefreshError::Changed`] and nothing is deleted, so a grant a
    /// reconnect stored meanwhile is kept.
    async fn discard_grant_refresh(
        &self,
        _claim: GrantRefreshClaim,
    ) -> Result<DelegatedGrant, RefreshError> {
        Err(RefreshError::Unavailable)
    }

    /// Never refresh `grant` again, after a refresh of its refresh token died
    /// part way ([`RefreshError::Uncertain`]).
    async fn abandon_grant_refresh(
        &self,
        _grant: &DelegatedGrant,
        _now: DateTime<Utc>,
    ) -> Result<DelegatedGrant, RefreshError> {
        Err(RefreshError::Unavailable)
    }

    /// Keep `connect` until it is claimed or expires, unless its binding
    /// already has [`MAX_PENDING_CONNECTS_PER_BINDING`] open, or its principal
    /// [`MAX_PENDING_CONNECTS_PER_PRINCIPAL`], which fails with
    /// [`TooManyPendingConnects`]; the open connects are counted from their
    /// file names alone. Fails as [`Self::store_grant`] does while grants
    /// cannot be kept.
    async fn start_connect(
        &self,
        _connect: PendingConnect,
    ) -> Result<()> {
        anyhow::bail!("This vault does not keep pending connects")
    }

    /// The pending connect with this id, claimed or not, without claiming it.
    async fn pending_connect(
        &self,
        _id: &str,
    ) -> Result<Option<PendingConnect>> {
        anyhow::bail!("This vault does not keep pending connects")
    }

    /// Claim the pending connect with this id at `now`, once.
    async fn claim_connect(
        &self,
        _id: &str,
        _now: DateTime<Utc>,
    ) -> Result<ConnectClaim> {
        anyhow::bail!("This vault does not keep pending connects")
    }

    /// Remove every pending connect, claimed or not, that expired by `before`,
    /// as its id says, returning how many. No connect is read.
    async fn sweep_connects(
        &self,
        _before: DateTime<Utc>,
    ) -> Result<usize> {
        anyhow::bail!("This vault does not keep pending connects")
    }
}

/// A store of external consent, `what` (such as "delegated grants"), opened
/// and its plaintext records encrypted. A store that cannot be opened, or
/// migrated, never keeps the vault from starting, since agent-keyed tokens do
/// not depend on it: it is logged, and every read and write of it then fails,
/// so nothing that may be stored is reported missing.
async fn open_store<T: crate::storage::filesystem::StorableEntity>(
    directory: &std::path::Path,
    entity_name: &'static str,
    what: &'static str,
) -> std::sync::Arc<dyn StorageBackend<T>> {
    let opened = async {
        let store = uncached_storage(directory.to_path_buf(), entity_name).await?;
        store
            .migrate_plaintext_at_rest()
            .await?;
        anyhow::Ok(store)
    }
    .await;
    match opened {
        Ok(store) => store.into(),
        Err(error) => {
            tracing::error!(
                target: "credential_delegation",
                path = %directory.display(),
                error = ?format!("{error:#}"),
                "The {what} store cannot be opened: no grant by binding is stored, released or removed, and a \
                 change that would remove one is refused, until it can be; agent-keyed delegated tokens are \
                 unaffected. Fix the directory's permissions or type and restart"
            );
            std::sync::Arc::new(Unopened(std::marker::PhantomData))
        }
    }
}

/// A store of external consent whose directory could not be opened: every
/// call fails.
struct Unopened<T>(std::marker::PhantomData<fn() -> T>);

#[async_trait]
impl<T: crate::storage::filesystem::StorableEntity> StorageBackend<T> for Unopened<T> {
    async fn save(
        &self,
        _entity: &T,
    ) -> Result<()> {
        anyhow::bail!("A store of external consent could not be opened")
    }

    async fn get(
        &self,
        _id: &str,
    ) -> Result<Option<T>> {
        anyhow::bail!("A store of external consent could not be opened")
    }

    async fn list_all(&self) -> Result<Vec<T>> {
        anyhow::bail!("A store of external consent could not be opened")
    }

    async fn delete(
        &self,
        _id: &str,
    ) -> Result<()> {
        anyhow::bail!("A store of external consent could not be opened")
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
    grant_refreshes: std::sync::Arc<dyn StorageBackend<grant_refresh::GrantRefreshRecord>>,
    deferred_revocations: std::sync::Arc<dyn StorageBackend<DeferredRevocation>>,
    deferred_revocations_directory: PathBuf,
    connects: std::sync::Arc<dyn StorageBackend<PendingConnect>>,
    connects_directory: PathBuf,
    /// The connects claimed, their verifiers wiped, kept until they expire.
    claimed_connects: std::sync::Arc<dyn StorageBackend<PendingConnect>>,
    claimed_connects_directory: PathBuf,
    /// Whether the vault's stores were created with at-rest encryption active.
    encrypted: bool,
    /// Whether the identity hash pepper, which grant ids derive from, was
    /// configured rather than generated for this process.
    stable_grant_ids: bool,
    /// [`super::grants::pepper_fingerprint`] of this gateway's pepper, kept
    /// beside the grants it writes.
    pepper_fingerprint: String,
}

/// How the pepper the stored grants were written under compares with ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredPepper {
    /// No fingerprint is stored: no grant was written since grants were
    /// fingerprinted.
    Unrecorded,
    /// The grants were written under this gateway's pepper.
    Ours,
    /// The fingerprint names another pepper.
    Another,
}

impl FileSystemDelegationVaultStore {
    pub async fn new(path: PathBuf) -> Result<Self> {
        let encrypted = crate::storage::filesystem::at_rest_encryption_active();
        let stable_grant_ids = crate::identity::credential_identity::pepper_is_configured();
        // Use uncached storage for security — tokens should not linger in memory
        let storage = uncached_storage(path.clone(), "delegation_token").await?;
        // Uncached stores load nothing at boot, so records restored in
        // plaintext would stay so until read: encrypt them now.
        storage
            .migrate_plaintext_at_rest()
            .await?;
        let grants = open_store(&path.join(GRANTS_DIRECTORY), "delegated_grant", "delegated grants").await;
        let connects = open_store(&path.join(PENDING_CONNECTS_DIRECTORY), "pending_connect", "pending connects").await;
        let claimed_connects_directory = path
            .join(PENDING_CONNECTS_DIRECTORY)
            .join(CLAIMED_CONNECTS_DIRECTORY);
        let claimed_connects = open_store(&claimed_connects_directory, "claimed_connect", "claimed connects").await;
        let deferred_revocations_directory = path.join(DEFERRED_REVOCATIONS_DIRECTORY);
        let deferred_revocations =
            open_store(&deferred_revocations_directory, "deferred_grant_revocation", "deferred revocations").await;
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
        let store = Self {
            storage: storage.into(),
            mutation_lock_path: path.join(".mutation.lock"),
            consents: consent::ConsentStorage::new(&path).await?,
            refreshes: uncached_storage(path.join("refresh_claims"), "delegation_refresh")
                .await?
                .into(),
            grants,
            grants_directory: path.join(GRANTS_DIRECTORY),
            grant_refreshes: uncached_storage(
                path.join(grant_refresh::GRANT_REFRESH_CLAIMS_DIRECTORY),
                "delegated_grant_refresh",
            )
            .await?
            .into(),
            deferred_revocations,
            deferred_revocations_directory,
            connects,
            connects_directory: path.join(PENDING_CONNECTS_DIRECTORY),
            claimed_connects,
            claimed_connects_directory,
            encrypted,
            stable_grant_ids,
            pepper_fingerprint: super::grants::pepper_fingerprint(),
        };
        // Only grants by binding depend on the fingerprint, so failing to read
        // it never keeps the vault, and its agent-keyed tokens, from starting.
        match store.pepper_mismatch().await {
            Ok(false) => {}
            Ok(true) if stable_grant_ids => tracing::error!(
                target: "credential_delegation",
                path = %store.grants_directory.display(),
                "The delegated grants stored were written under another identity hash pepper than \
                 AG_IDENTITY_HASH_PEPPER now sets: no grant is stored or released, and no binding with consent_mode \
                 external can be removed, until the pepper they were written under is restored, or they are purged \
                 (DELETE /api/v1/delegation-vault/grants/{{id}}, the ids being the file names in the delegated_grants \
                 directory without .json.enc, or by deleting that directory, which leaves them unrevoked at the \
                 vendor)"
            ),
            Ok(true) => tracing::error!(
                target: "credential_delegation",
                path = %store.grants_directory.display(),
                "The delegated grants stored were written under another identity hash pepper, and \
                 AG_IDENTITY_HASH_PEPPER is not set, so this process generated its own: they cannot be found, and no \
                 binding with consent_mode external can be removed, until AG_IDENTITY_HASH_PEPPER is set to the \
                 pepper they were written under, or they are purged (DELETE /api/v1/delegation-vault/grants/{{id}}, \
                 the ids being the file names in the delegated_grants directory without .json.enc, or by deleting \
                 that directory, which leaves them unrevoked at the vendor)"
            ),
            Err(error) => tracing::error!(
                target: "credential_delegation",
                path = %store.grants_directory.display(),
                error = ?format!("{error:#}"),
                "The delegated grants' pepper fingerprint cannot be read: no grant by binding is stored, and a \
                 lookup or removal that finds no grant fails rather than answering none, until it can be read; \
                 agent-keyed delegated tokens are unaffected"
            ),
        }
        Ok(store)
    }

    /// The record ids of the grants stored whose id starts with `prefix`, read
    /// from the file names alone.
    async fn grant_ids_with_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<String>> {
        ids_with_prefix(&self.grants_directory, prefix, super::grants::is_record_id).await
    }

    /// How many of the connects stored open, whose ids start with `prefix`,
    /// are still open at `now`, read from their file names alone.
    async fn open_connects(
        &self,
        prefix: &str,
        now: DateTime<Utc>,
    ) -> Result<usize> {
        Ok(ids_with_prefix(&self.connects_directory, prefix, super::grants::is_connect_id)
            .await?
            .iter()
            .filter(|id| super::grants::connect_expiry(id).is_some_and(|expires_at| now < expires_at))
            .count())
    }

    /// Whether a connect with this id was claimed, read from the file names
    /// of the claimed connects alone.
    async fn connect_claimed(
        &self,
        id: &str,
    ) -> Result<bool> {
        Ok(ids_with_prefix(&self.claimed_connects_directory, id, super::grants::is_connect_id)
            .await?
            .iter()
            .any(|claimed| claimed == id))
    }

    async fn stored_pepper(&self) -> Result<StoredPepper> {
        match tokio::fs::read_to_string(
            self.grants_directory
                .join(PEPPER_FINGERPRINT_FILE),
        )
        .await
        {
            Ok(stored) if stored.trim() == self.pepper_fingerprint => Ok(StoredPepper::Ours),
            Ok(_) => Ok(StoredPepper::Another),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(StoredPepper::Unrecorded),
            Err(error) => Err(error).context("Failed to read the delegated grants' pepper fingerprint"),
        }
    }

    /// With no fingerprint recorded, whether this pepper is the one the grants
    /// stored were written under: true when none is stored, or one that can be
    /// read has the id this pepper derives for it. A fingerprint lost with
    /// grants beside it, under a wrong pepper, then never passes for ours.
    async fn unrecorded_grants_are_ours(&self) -> Result<bool> {
        let ids = self
            .grant_ids_with_prefix("")
            .await?;
        if ids.is_empty() {
            return Ok(true);
        }
        for id in ids {
            if let Ok(Some(grant)) = self.grants.get(&id).await
                && grant.key().record_id() == grant.id
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether grants are stored that were written under another pepper: the
    /// fingerprint names another, or none is recorded and no stored grant has
    /// this pepper's id ([`Self::unrecorded_grants_are_ours`]).
    async fn pepper_mismatch(&self) -> Result<bool> {
        match self.stored_pepper().await? {
            StoredPepper::Ours => Ok(false),
            StoredPepper::Another => Ok(!self
                .grant_ids_with_prefix("")
                .await?
                .is_empty()),
            StoredPepper::Unrecorded => Ok(!self
                .unrecorded_grants_are_ours()
                .await?),
        }
    }

    /// Record this gateway's pepper beside the grants before one is written,
    /// refusing while grants written under another are stored, whether the
    /// fingerprint names it or was lost ([`Self::pepper_mismatch`]). A
    /// fingerprint with no grant beside it is replaced. Called with the
    /// mutation lock held.
    async fn claim_pepper_locked(&self) -> Result<()> {
        let stored = self.stored_pepper().await?;
        if stored == StoredPepper::Ours {
            return Ok(());
        }
        if self.pepper_mismatch().await? {
            return Err(PepperMismatch.into());
        }
        if stored == StoredPepper::Another {
            warn!(
                target: "credential_delegation",
                "The delegated grants' pepper fingerprint named another identity hash pepper, but no grant is \
                 stored; it now names this gateway's"
            );
        }
        crate::storage::filesystem::atomic_write_file_with_mode(
            &self
                .grants_directory
                .join(PEPPER_FINGERPRINT_FILE),
            self.pepper_fingerprint
                .as_bytes(),
            Some(0o600),
        )
        .await
        .map_err(|error| anyhow::anyhow!("Failed to record the delegated grants' pepper fingerprint: {error:?}"))
    }

    /// Read the grants with these record ids, failing with [`UnreadableGrant`]
    /// on the first that cannot be read, and with [`PepperMismatch`] when there
    /// are none and grants written under another pepper are stored.
    async fn read_grants(
        &self,
        ids: Vec<String>,
    ) -> Result<Vec<DelegatedGrant>> {
        if ids.is_empty() {
            if self.pepper_mismatch().await? {
                return Err(PepperMismatch.into());
            }
            return Ok(Vec::new());
        }
        let mut grants = Vec::with_capacity(ids.len());
        for id in ids {
            if !self.encrypted {
                return Err(UnreadableGrant {
                    grant_id: id,
                    reason: UnreadableReason::EncryptionOff,
                }
                .into());
            }
            match self.grants.get(&id).await {
                Ok(Some(grant)) => grants.push(grant),
                Ok(None) => {}
                Err(error) => return Err(unreadable_or_unavailable(error, &id)),
            }
        }
        Ok(grants)
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

    /// The grant stored under `id`, `key`'s record id, if its own key is `key`.
    /// The id is computed by the caller, since a mutation runs on a task of its
    /// own.
    async fn grant_locked(
        &self,
        key: &GrantKey,
        id: &str,
    ) -> Result<Option<DelegatedGrant>> {
        let Some(grant) = self.grants.get(id).await? else {
            return Ok(None);
        };
        if grant.key() != *key || grant.id != id {
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
        let id = key.record_id();
        let found = self
            .grant_locked(key, &id)
            .await
            .map_err(|error| unreadable_or_unavailable(error, &id))?;
        // A grant found under its key's id was written under this pepper; when
        // none is, say so if the grants stored were written under another.
        if found.is_none() && self.pepper_mismatch().await? {
            return Err(PepperMismatch.into());
        }
        Ok(found)
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
            store
                .claim_pepper_locked()
                .await?;
            let replaced = store
                .grant_locked(&key, &grant.id)
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
                surface_id = ?grant.surface_id,
                hop = ?grant.hop,
                credential_provider_id = %grant.credential_provider_id,
                replaced = replaced.is_some(),
                "Delegated grant stored in vault"
            );
            Ok(StoredGrant { grant, replaced })
        })
        .await
    }

    async fn binding_grants(
        &self,
        binding: &GrantBinding,
        principals: Principals,
    ) -> Result<Vec<DelegatedGrant>> {
        let ids = self
            .grant_ids_with_prefix(&binding.record_id_prefix())
            .await?
            .into_iter()
            .filter(|id| binding.names(principals, id))
            .collect();
        self.read_grants(ids).await
    }

    async fn provider_grants(
        &self,
        credential_provider_id: &str,
    ) -> Result<Vec<DelegatedGrant>> {
        let ids = self
            .grant_ids_with_prefix(&super::grants::provider_record_id_prefix(credential_provider_id))
            .await?;
        self.read_grants(ids).await
    }

    async fn binding_grant_ids(
        &self,
        binding: &GrantBinding,
    ) -> Result<Vec<String>> {
        let ids = self
            .grant_ids_with_prefix(&binding.record_id_prefix())
            .await?;
        if ids.is_empty() && self.pepper_mismatch().await? {
            return Err(PepperMismatch.into());
        }
        Ok(ids)
    }

    async fn purge_grant(
        &self,
        id: &str,
        tenant_id: Option<&str>,
    ) -> Result<bool> {
        anyhow::ensure!(super::grants::is_record_id(id), "Not the id of a delegated grant");
        let id = id.to_string();
        let tenant_id = tenant_id.map(str::to_string);
        self.mutate(move |store| async move {
            let _access_change = crate::mcp::subscriptions::AccessChange::begin(
                crate::mcp::subscriptions::AccessScope::owned_by(tenant_id.as_deref()),
            );
            let existed = ["json.enc", "json"]
                .iter()
                .any(|extension| {
                    store
                        .grants_directory
                        .join(format!("{id}.{extension}"))
                        .exists()
                });
            store
                .grants
                .delete(&id)
                .await?;
            store
                .grant_refreshes
                .delete(&id)
                .await?;
            if existed {
                info!(target: "credential_delegation", grant_id = %id, "Delegated grant deleted without reading it");
            }
            Ok(existed)
        })
        .await
    }

    #[cfg(test)]
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
            store
                .grant_refreshes
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

    async fn grant_ids(&self) -> Result<Vec<String>> {
        self.grant_ids_with_prefix("")
            .await
    }

    async fn derives_stored_grant_ids(&self) -> Result<bool> {
        Ok(self.stable_grant_ids && !self.pepper_mismatch().await?)
    }

    async fn grant_by_id(
        &self,
        id: &str,
    ) -> Result<Option<DelegatedGrant>> {
        anyhow::ensure!(super::grants::is_record_id(id), "Not the id of a delegated grant");
        self.require_encryption()?;
        self.grants
            .get(id)
            .await
            .map_err(|error| unreadable_or_unavailable(error, id))
    }

    async fn claim_grant_refresh(
        &self,
        grant: &DelegatedGrant,
        now: DateTime<Utc>,
    ) -> Result<GrantRefreshClaim, RefreshError> {
        self.require_grant_storage()
            .map_err(|_| RefreshError::Unavailable)?;
        let grant = grant.clone();
        self.mutate(move |store| async move {
            Ok(store
                .claim_grant_refresh_locked(&grant, now)
                .await)
        })
        .await
        .map_err(|_| RefreshError::Unavailable)?
    }

    async fn complete_grant_refresh(
        &self,
        claim: GrantRefreshClaim,
        tokens: ObtainedTokens,
        now: DateTime<Utc>,
    ) -> Result<DelegatedGrant, RefreshError> {
        self.mutate(move |store| async move {
            let _access_change =
                crate::mcp::subscriptions::AccessChange::begin(crate::mcp::subscriptions::AccessScope::owned_by(
                    claim
                        .grant()
                        .tenant_id
                        .as_deref(),
                ));
            Ok(store
                .complete_grant_refresh_locked(claim, tokens, now)
                .await)
        })
        .await
        .map_err(|error| {
            // The lock was never taken, so nothing was written; a task that
            // failed may have written the grant before it did.
            if error.is::<tokio::task::JoinError>() {
                RefreshError::Unconfirmed
            } else {
                RefreshError::Unavailable
            }
        })?
    }

    async fn fail_grant_refresh(
        &self,
        claim: GrantRefreshClaim,
        failure: FailedRefresh,
        now: DateTime<Utc>,
    ) -> Result<DelegatedGrant, RefreshError> {
        self.mutate(move |store| async move {
            Ok(store
                .fail_grant_refresh_locked(claim, failure, now)
                .await)
        })
        .await
        .map_err(|_| RefreshError::Unavailable)?
    }

    async fn abandon_grant_refresh(
        &self,
        grant: &DelegatedGrant,
        now: DateTime<Utc>,
    ) -> Result<DelegatedGrant, RefreshError> {
        let grant = grant.clone();
        self.mutate(move |store| async move {
            Ok(store
                .abandon_grant_refresh_locked(&grant, now)
                .await)
        })
        .await
        .map_err(|_| RefreshError::Unavailable)?
    }

    async fn discard_grant_refresh(
        &self,
        claim: GrantRefreshClaim,
    ) -> Result<DelegatedGrant, RefreshError> {
        self.mutate(move |store| async move {
            let _access_change =
                crate::mcp::subscriptions::AccessChange::begin(crate::mcp::subscriptions::AccessScope::owned_by(
                    claim
                        .grant()
                        .tenant_id
                        .as_deref(),
                ));
            let discarded = store
                .discard_grant_refresh_locked(claim)
                .await;
            if let Ok(grant) = &discarded {
                info!(
                    target: "credential_delegation",
                    grant_id = %grant.id,
                    "Delegated grant deleted: its refresh token was refused"
                );
            }
            Ok(discarded)
        })
        .await
        .map_err(|_| RefreshError::Unavailable)?
    }

    async fn delete_grant_holding(
        &self,
        id: &str,
        access_token: &str,
    ) -> Result<Option<DelegatedGrant>> {
        let id = id.to_string();
        let access_token = zeroize::Zeroizing::new(access_token.to_string());
        self.mutate(move |store| async move {
            let Some(grant) = store.grants.get(&id).await? else {
                return Ok(None);
            };
            if !bool::from(subtle::ConstantTimeEq::ct_eq(grant.access_token.as_bytes(), access_token.as_bytes())) {
                return Ok(None);
            }
            let _access_change = crate::mcp::subscriptions::AccessChange::begin(
                crate::mcp::subscriptions::AccessScope::owned_by(grant.tenant_id.as_deref()),
            );
            store
                .grants
                .delete(&id)
                .await?;
            store
                .grant_refreshes
                .delete(&id)
                .await?;
            info!(target: "credential_delegation", grant_id = %id, "Delegated grant deleted: the vendor refused it");
            Ok(Some(grant))
        })
        .await
    }

    async fn delete_grant_of_connection(
        &self,
        id: &str,
        connected_at: DateTime<Utc>,
    ) -> Result<Option<DelegatedGrant>> {
        let id = id.to_string();
        self.mutate(move |store| async move {
            let Some(grant) = store.grants.get(&id).await? else {
                return Ok(None);
            };
            if grant.created_at != connected_at {
                info!(
                    target: "credential_delegation",
                    grant_id = %id,
                    "Kept a delegated grant connected again since its removal read it"
                );
                return Ok(None);
            }
            let _access_change = crate::mcp::subscriptions::AccessChange::begin(
                crate::mcp::subscriptions::AccessScope::owned_by(grant.tenant_id.as_deref()),
            );
            store
                .grants
                .delete(&id)
                .await?;
            store
                .grant_refreshes
                .delete(&id)
                .await?;
            info!(target: "credential_delegation", grant_id = %id, "Delegated grant deleted");
            Ok(Some(grant))
        })
        .await
    }

    async fn defer_revocation(
        &self,
        grant: DelegatedGrant,
    ) -> Result<()> {
        self.require_encryption()?;
        let deferred = DeferredRevocation::new(grant, Utc::now(), Deferral::AuthorizationInUse);
        self.deferred_revocations
            .save_atomic(&deferred)
            .await
            .context("Failed to defer a delegated grant's revocation")?;
        info!(
            target: "credential_delegation",
            grant_id = %deferred.grant.id,
            deferred_revocation_id = %deferred.id,
            "A removed delegated grant's revocation is deferred to the daily sweep"
        );
        Ok(())
    }

    async fn keep_revocation(
        &self,
        revocation: &DeferredRevocation,
    ) -> Result<()> {
        self.require_encryption()?;
        anyhow::ensure!(
            deferred_revocation::is_deferred_revocation_id(&revocation.id),
            "Not the id of a deferred revocation"
        );
        self.deferred_revocations
            .save_atomic(revocation)
            .await
            .context("Failed to keep a delegated grant's revocation")
    }

    async fn deferred_revocations(&self) -> Result<Vec<DeferredRevocation>> {
        self.require_encryption()?;
        let mut deferred = Vec::new();
        for id in
            ids_with_prefix(&self.deferred_revocations_directory, "", deferred_revocation::is_deferred_revocation_id)
                .await?
        {
            match self
                .deferred_revocations
                .get(&id)
                .await
            {
                Ok(Some(revocation)) => deferred.push(revocation),
                Ok(None) => {}
                Err(error) => warn!(
                    target: "credential_delegation",
                    deferred_revocation_id = %id,
                    error = ?error.to_string(),
                    "A deferred revocation cannot be read now; it is tried again at the next sweep"
                ),
            }
        }
        deferred.sort_by_key(|revocation| revocation.deferred_at);
        Ok(deferred)
    }

    async fn forget_deferred_revocation(
        &self,
        id: &str,
    ) -> Result<()> {
        anyhow::ensure!(deferred_revocation::is_deferred_revocation_id(id), "Not the id of a deferred revocation");
        self.deferred_revocations
            .delete(id)
            .await
    }

    async fn start_connect(
        &self,
        connect: PendingConnect,
    ) -> Result<()> {
        self.require_grant_storage()?;
        anyhow::ensure!(super::grants::is_connect_id(&connect.id), "Not the id of a pending connect");
        self.mutate(move |store| async move {
            let principal_open = store
                .open_connects(
                    &connect
                        .key()
                        .connect_id_prefix(),
                    connect.created_at,
                )
                .await?;
            if principal_open >= MAX_PENDING_CONNECTS_PER_PRINCIPAL {
                return Err(TooManyPendingConnects.into());
            }
            let binding_open = store
                .open_connects(
                    &connect
                        .binding()
                        .connect_id_prefix(),
                    connect.created_at,
                )
                .await?;
            if binding_open >= MAX_PENDING_CONNECTS_PER_BINDING {
                return Err(TooManyPendingConnects.into());
            }
            store
                .connects
                .save_atomic(&connect)
                .await
                .context("Failed to store a pending connect")?;
            info!(
                target: "credential_delegation",
                connect_id = %connect.id,
                surface_id = ?connect.surface_id,
                hop = ?connect.hop,
                credential_provider_id = %connect.credential_provider_id,
                "External consent connect started"
            );
            Ok(())
        })
        .await
    }

    async fn pending_connect(
        &self,
        id: &str,
    ) -> Result<Option<PendingConnect>> {
        if !super::grants::is_connect_id(id) {
            return Ok(None);
        }
        self.require_encryption()?;
        match self.connects.get(id).await? {
            Some(open) => Ok(Some(open)),
            None => {
                self.claimed_connects
                    .get(id)
                    .await
            }
        }
    }

    /// The open connect is read, and its claimed copy written, outside the
    /// vault's lock, which then only decides, by the file names, which claim
    /// came first: no claim makes the vault wait on a decryption or a key
    /// service. An open connect never changes once written, so the copy read
    /// is the one claimed.
    async fn claim_connect(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<ConnectClaim> {
        if !super::grants::is_connect_id(id) {
            return Ok(ConnectClaim::NotFound);
        }
        self.require_grant_storage()?;
        let Some(connect) = self.connects.get(id).await? else {
            return Ok(
                if self
                    .connect_claimed(id)
                    .await?
                {
                    ConnectClaim::AlreadyUsed
                } else {
                    ConnectClaim::NotFound
                },
            );
        };
        if now >= connect.expires_at {
            let id = id.to_string();
            self.mutate(move |store| async move {
                store
                    .connects
                    .delete(&id)
                    .await
            })
            .await?;
            return Ok(ConnectClaim::Expired);
        }
        let used = PendingConnect {
            code_verifier: None,
            claimed_at: Some(now),
            ..connect.clone()
        };
        self.claimed_connects
            .save_atomic(&used)
            .await
            .context("Failed to claim a pending connect")?;
        let id = id.to_string();
        let first = self
            .mutate(move |store| async move {
                if !ids_with_prefix(&store.connects_directory, &id, super::grants::is_connect_id)
                    .await?
                    .contains(&id)
                {
                    return Ok(false);
                }
                store
                    .connects
                    .delete(&id)
                    .await?;
                Ok(true)
            })
            .await?;
        if !first {
            return Ok(ConnectClaim::AlreadyUsed);
        }
        Ok(ConnectClaim::Claimed(Box::new(PendingConnect {
            claimed_at: Some(now),
            ..connect
        })))
    }

    async fn sweep_connects(
        &self,
        before: DateTime<Utc>,
    ) -> Result<usize> {
        self.mutate(move |store| async move {
            let mut removed = 0usize;
            for (directory, connects) in [
                (&store.connects_directory, &store.connects),
                (&store.claimed_connects_directory, &store.claimed_connects),
            ] {
                for id in ids_with_prefix(directory, "", super::grants::is_connect_id).await? {
                    if super::grants::connect_expiry(&id).is_some_and(|expires_at| before >= expires_at) {
                        connects.delete(&id).await?;
                        removed += 1;
                    }
                }
            }
            Ok(removed)
        })
        .await
    }
}

/// The error of a failed read of grant `id`: [`UnreadableGrant`] when the
/// record itself cannot be decrypted or parsed, which only a purge removes;
/// otherwise the failure as it is, such as a disk or key service outage, after
/// which the same grant may read again, so it is never taken for unreadable.
fn unreadable_or_unavailable(
    error: anyhow::Error,
    id: &str,
) -> anyhow::Error {
    if error.is::<crate::storage::filesystem::UnreadableRecord>() {
        warn!(
            target: "credential_delegation",
            grant_id = %id,
            error = ?error.to_string(),
            "A delegated grant cannot be read; removing its binding or provider is refused until it can be read or \
             is purged"
        );
        UnreadableGrant {
            grant_id: id.to_string(),
            reason: UnreadableReason::Undecryptable,
        }
        .into()
    } else {
        warn!(
            target: "credential_delegation",
            grant_id = %id,
            error = ?error.to_string(),
            "A delegated grant could not be read now; the vault's storage or key service is unavailable"
        );
        error.context(format!("Delegated grant {id} could not be read now"))
    }
}

/// The ids of the records in `directory` whose id starts with `prefix` and
/// has the shape `valid` accepts, read from the file names alone.
async fn ids_with_prefix(
    directory: &std::path::Path,
    prefix: &str,
    valid: fn(&str) -> bool,
) -> Result<Vec<String>> {
    let mut entries = match tokio::fs::read_dir(directory).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("Failed to read {}", directory.display())),
    };
    let mut ids = std::collections::BTreeSet::new();
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(id) = name
            .strip_suffix(".json.enc")
            .or_else(|| name.strip_suffix(".json"))
        else {
            continue;
        };
        if id.starts_with(prefix) && valid(id) {
            ids.insert(id.to_string());
        }
    }
    Ok(ids.into_iter().collect())
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
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "AG_TEST_MASTER_KEY".to_string(),
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
    async fn records_restored_in_plaintext_are_encrypted_when_the_vault_starts() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let grants = directory
            .path()
            .join("delegated_grants");
        std::fs::create_dir_all(&grants).unwrap();
        let mut restored = grant(&key(), "restored-access");
        restored.id = key().record_id();
        let plaintext_grant = grants.join(format!("{}.json", restored.id));
        std::fs::write(&plaintext_grant, serde_json::to_vec(&restored).unwrap()).unwrap();
        let plaintext_token = directory
            .path()
            .join("restored-token.json");
        std::fs::write(
            &plaintext_token,
            serde_json::to_vec(&serde_json::json!({
                "id": "restored-token", "agent_did": "did:web:agent.example",
                "user_identity_hash": "sha256:user", "credential_provider_id": "provider",
                "provider_id": "provider", "access_token": "restored-token-access", "scopes": ["read"],
                "consent_granted_at": "2026-09-01T00:00:00Z",
                "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
            }))
            .unwrap(),
        )
        .unwrap();

        let vault = encrypted_vault(directory.path()).await;

        for (plaintext, secret) in [(plaintext_grant, "restored-access"), (plaintext_token, "restored-token-access")] {
            assert!(!plaintext.exists(), "{} is left in plaintext", plaintext.display());
            let encrypted = plaintext.with_extension("json.enc");
            assert!(encrypted.exists(), "{}", encrypted.display());
            assert!(!String::from_utf8_lossy(&std::fs::read(&encrypted).unwrap()).contains(secret));
        }
        assert_eq!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "restored-access"
        );
    }

    #[tokio::test]
    async fn a_grants_transit_point_and_surface_are_logged_escaped() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        use crate::delegation_vault::grants::tests::grant;
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface\nINFO forged surface", "hop\nINFO forged hop", "provider");
        let logs = FormattedLogs::capture();
        vault
            .store_grant(grant(&key, "access"))
            .await
            .unwrap();
        let text = logs.text();
        assert!(text.contains("Delegated grant stored in vault"), "{text}");
        assert!(!text.contains("\nINFO forged"), "a stored name starts a log line of its own: {text}");
    }

    /// A pepper fingerprint that cannot be read at startup is named in an
    /// `ERROR`, and disables only grants by binding: the vault still starts,
    /// so agent-keyed tokens keep working.
    #[tokio::test]
    async fn an_unreadable_pepper_fingerprint_disables_grants_by_binding_only() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(
            directory
                .path()
                .join("delegated_grants")
                .join(PEPPER_FINGERPRINT_FILE),
        )
        .unwrap();
        with_at_rest_encryption();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let logs = FormattedLogs::capture();
        let vault = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .expect("the vault starts");
        let startup = logs.text();
        assert!(startup.contains("ERROR"), "{startup}");
        assert!(startup.contains("pepper fingerprint"), "{startup}");

        let token: DelegationToken = serde_json::from_value(serde_json::json!({
            "id": "agent-keyed", "agent_did": "did:web:agent.example",
            "user_identity_hash": "sha256:user", "credential_provider_id": "provider",
            "provider_id": "provider", "access_token": "agent-keyed-access", "scopes": ["read"],
            "consent_granted_at": "2026-09-01T00:00:00Z",
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap();
        vault
            .store(token)
            .await
            .expect("agent-keyed tokens are stored");
        assert_eq!(
            vault
                .get("agent-keyed")
                .await
                .unwrap()
                .expect("and read")
                .access_token,
            "agent-keyed-access"
        );
        assert!(
            vault
                .store_grant(grant(&key(), "access"))
                .await
                .is_err(),
            "no grant is stored while the fingerprint cannot be read"
        );
        assert!(
            vault
                .grant(&key())
                .await
                .is_err(),
            "nor is a missing grant reported as none"
        );
    }

    /// A grants directory the vault cannot open never keeps the vault, and its
    /// agent-keyed tokens, from starting: the startup log names it, and every
    /// grant read or write fails rather than answering none.
    #[tokio::test]
    async fn a_grants_directory_that_cannot_be_opened_fails_only_grant_reads() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory
                .path()
                .join(GRANTS_DIRECTORY),
            b"not a directory",
        )
        .unwrap();
        with_at_rest_encryption();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let logs = FormattedLogs::capture();
        let vault = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .expect("the vault starts");
        let startup = logs.text();
        assert!(startup.contains("ERROR"), "{startup}");
        assert!(startup.contains("delegated grants store cannot be opened"), "{startup}");

        let token: DelegationToken = serde_json::from_value(serde_json::json!({
            "id": "agent-keyed", "agent_did": "did:web:agent.example",
            "user_identity_hash": "sha256:user", "credential_provider_id": "provider",
            "provider_id": "provider", "access_token": "agent-keyed-access", "scopes": ["read"],
            "consent_granted_at": "2026-09-01T00:00:00Z",
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap();
        vault
            .store(token)
            .await
            .expect("agent-keyed tokens are stored");
        assert!(
            vault
                .get("agent-keyed")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            vault
                .store_grant(grant(&key(), "access"))
                .await
                .is_err()
        );
        assert!(
            vault
                .grant(&key())
                .await
                .is_err(),
            "a grant read fails rather than answering none"
        );
        assert!(
            vault
                .binding_grants(&key().binding(), Principals::All)
                .await
                .is_err(),
            "a removal must not pass for having found nothing"
        );
    }

    /// Without `AG_IDENTITY_HASH_PEPPER` each start generates a pepper, so a
    /// restarted gateway finds the grants written under another one: they are
    /// neither stored, released nor listed, and the startup log says the
    /// pepper was generated rather than set.
    #[tokio::test]
    async fn while_the_pepper_is_ephemeral_grants_are_neither_stored_nor_released() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        use crate::delegation_vault::grants::tests::{grant, key};
        use crate::identity::credential_identity::configure_pepper_bytes_for_tests;
        let directory = tempfile::tempdir().unwrap();
        configure_pepper_bytes_for_tests(&[3; 32]);
        let vault = encrypted_vault(directory.path()).await;
        vault
            .store_grant(grant(&key(), "owner-access"))
            .await
            .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(false);
        configure_pepper_bytes_for_tests(&[4; 32]);
        let logs = FormattedLogs::capture();
        let restarted = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let startup = logs.text();
        assert!(startup.contains("ERROR"), "{startup}");
        assert!(startup.contains("AG_IDENTITY_HASH_PEPPER is not set"), "{startup}");
        assert!(!startup.contains("than AG_IDENTITY_HASH_PEPPER now sets"), "{startup}");
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
        assert!(
            restarted
                .provider_grants("provider")
                .await
                .unwrap_err()
                .is::<super::super::grants::PepperMismatch>(),
            "the grants of another start's pepper cannot be found to be revoked; an operator purges them"
        );
    }

    /// Grants are filed by binding under ids that derive from the pepper, so a
    /// gateway with another pepper could neither find them to remove them nor
    /// keep its own beside them: it refuses both, and says why at startup.
    #[tokio::test]
    async fn grants_written_under_another_pepper_are_neither_released_nor_added_to() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        use crate::delegation_vault::grants::tests::{grant, key};
        use crate::identity::credential_identity::configure_pepper_bytes_for_tests;
        let directory = tempfile::tempdir().unwrap();
        configure_pepper_bytes_for_tests(&[1; 32]);
        let first = encrypted_vault(directory.path()).await;
        first
            .store_grant(grant(&key(), "first-access"))
            .await
            .unwrap();
        let fingerprint = std::fs::read_to_string(
            directory
                .path()
                .join("delegated_grants/pepper-fingerprint"),
        )
        .expect("the pepper is fingerprinted beside the grants");
        assert!(!fingerprint.contains(&hex::encode([1u8; 32])), "the fingerprint shows the pepper");

        configure_pepper_bytes_for_tests(&[2; 32]);
        let logs = FormattedLogs::capture();
        let other = encrypted_vault(directory.path()).await;
        let startup = logs.text();
        assert!(startup.contains("ERROR"), "{startup}");
        assert!(startup.contains("written under another identity hash pepper"), "{startup}");
        let refused = other
            .store_grant(grant(&key(), "second-access"))
            .await
            .unwrap_err();
        assert!(refused.is::<super::super::grants::PepperMismatch>(), "{refused}");
        assert!(
            other
                .grant(&key())
                .await
                .unwrap_err()
                .is::<super::super::grants::PepperMismatch>()
        );
        assert!(
            other
                .binding_grants(&key().binding(), Principals::All)
                .await
                .unwrap_err()
                .is::<super::super::grants::PepperMismatch>(),
            "a removal must not pass for having found nothing"
        );

        configure_pepper_bytes_for_tests(&[1; 32]);
        let stored_id = key().record_id();
        configure_pepper_bytes_for_tests(&[2; 32]);
        assert!(
            other
                .purge_grant(&stored_id, Some("tenant-a"))
                .await
                .unwrap(),
            "an operator purges it by its id"
        );
        other
            .store_grant(grant(&key(), "second-access"))
            .await
            .expect("with no grant left, the fingerprint is this gateway's");
        assert_eq!(
            other
                .grant(&key())
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "second-access"
        );
    }

    /// With the fingerprint file lost, a gateway with another pepper is told
    /// apart by the grants themselves: none has the id its pepper derives, so
    /// it refuses to store or release a grant, says why at startup, and never
    /// records its own fingerprint over them. The pepper they were written
    /// under goes on as before and records its fingerprint again.
    #[tokio::test]
    async fn a_lost_fingerprint_never_lets_another_pepper_claim_the_grants() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        use crate::delegation_vault::grants::tests::{grant, key};
        use crate::identity::credential_identity::configure_pepper_bytes_for_tests;
        let directory = tempfile::tempdir().unwrap();
        let fingerprint = directory
            .path()
            .join("delegated_grants/pepper-fingerprint");
        configure_pepper_bytes_for_tests(&[1; 32]);
        encrypted_vault(directory.path())
            .await
            .store_grant(grant(&key(), "first-access"))
            .await
            .unwrap();
        std::fs::remove_file(&fingerprint).unwrap();

        configure_pepper_bytes_for_tests(&[2; 32]);
        let logs = FormattedLogs::capture();
        let other = encrypted_vault(directory.path()).await;
        let startup = logs.text();
        assert!(startup.contains("written under another identity hash pepper"), "{startup}");
        let refused = other
            .store_grant(grant(&key(), "second-access"))
            .await
            .unwrap_err();
        assert!(refused.is::<super::super::grants::PepperMismatch>(), "{refused}");
        assert!(!fingerprint.exists(), "another pepper's fingerprint is never recorded over the grants");
        assert!(
            other
                .grant(&key())
                .await
                .unwrap_err()
                .is::<super::super::grants::PepperMismatch>()
        );
        assert!(
            !other
                .derives_stored_grant_ids()
                .await
                .unwrap()
        );

        configure_pepper_bytes_for_tests(&[1; 32]);
        let first = encrypted_vault(directory.path()).await;
        assert!(
            first
                .derives_stored_grant_ids()
                .await
                .unwrap()
        );
        first
            .store_grant(grant(&key(), "again-access"))
            .await
            .expect("the grants' own pepper stores as before");
        assert!(fingerprint.exists(), "and records its fingerprint again");
        assert_eq!(
            first
                .grant(&key())
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "again-access"
        );
    }

    fn corrupt(
        directory: &std::path::Path,
        id: &str,
    ) {
        std::fs::write(
            directory
                .join("delegated_grants")
                .join(format!("{id}.json.enc")),
            "not a grant",
        )
        .unwrap();
    }

    /// Grants are read by the record ids of one binding or one provider, so a
    /// grant that cannot be read is reported by its id and blocks only the
    /// removals that need it.
    #[tokio::test]
    async fn an_unreadable_grant_is_named_and_blocks_only_its_own_binding_and_provider() {
        use crate::delegation_vault::grants::tests::{grant, key};
        use crate::delegation_vault::grants::{UnreadableGrant, UnreadableReason};
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
        let caller =
            GrantKey::caller(Some("tenant-a"), "surface", "transit-point-id", "provider", &"a".repeat(64)).unwrap();
        for key in [key(), other_hop.clone(), other_provider.clone(), caller.clone()] {
            vault
                .store_grant(grant(&key, "access"))
                .await
                .unwrap();
        }
        corrupt(directory.path(), &key().record_id());

        let refused = vault
            .binding_grants(&key().binding(), Principals::All)
            .await
            .unwrap_err();
        assert_eq!(
            refused.downcast_ref::<UnreadableGrant>(),
            Some(&UnreadableGrant {
                grant_id: key().record_id(),
                reason: UnreadableReason::Undecryptable,
            }),
            "{refused}"
        );
        assert!(
            vault
                .binding_grants(&key().binding(), Principals::Owner)
                .await
                .is_err()
        );
        let callers = vault
            .binding_grants(&key().binding(), Principals::Callers)
            .await
            .expect("the binding's caller grants are read without its owner grant");
        assert_eq!(
            callers
                .iter()
                .map(|grant| grant.id.clone())
                .collect::<Vec<_>>(),
            [caller.record_id()]
        );
        assert_eq!(
            vault
                .binding_grants(&other_hop.binding(), Principals::All)
                .await
                .expect("another binding is read without the unreadable grant")
                .len(),
            1
        );
        assert_eq!(
            vault
                .provider_grants("other-provider")
                .await
                .expect("another provider's grants are read without it")
                .len(),
            1
        );
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap_err()
                .is::<UnreadableGrant>()
        );
    }

    #[tokio::test]
    async fn an_unreadable_grant_is_purged_by_its_id_or_its_binding_without_reading_it() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let caller =
            GrantKey::caller(Some("tenant-a"), "surface", "transit-point-id", "provider", &"a".repeat(64)).unwrap();
        let other_hop = GrantKey {
            hop: "other-transit-point".into(),
            ..key()
        };
        for key in [key(), caller.clone(), other_hop.clone()] {
            vault
                .store_grant(grant(&key, "access"))
                .await
                .unwrap();
        }
        corrupt(directory.path(), &key().record_id());
        corrupt(directory.path(), &caller.record_id());

        assert!(
            vault
                .purge_grant(&key().record_id(), Some("tenant-a"))
                .await
                .unwrap()
        );
        assert!(
            !vault
                .purge_grant(&key().record_id(), Some("tenant-a"))
                .await
                .unwrap(),
            "it is gone"
        );
        let mut ids = vault
            .binding_grant_ids(&key().binding())
            .await
            .unwrap();
        assert_eq!(ids, [caller.record_id()]);
        for id in ids.drain(..) {
            assert!(
                vault
                    .purge_grant(&id, Some("tenant-a"))
                    .await
                    .unwrap()
            );
        }
        assert!(
            vault
                .binding_grants(&key().binding(), Principals::All)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            vault
                .grant(&other_hop)
                .await
                .unwrap()
                .is_some(),
            "another binding's grant is kept"
        );
        for not_a_grant in ["pepper-fingerprint", "../vault", "grant-1"] {
            assert!(
                vault
                    .purge_grant(not_a_grant, None)
                    .await
                    .is_err(),
                "{not_a_grant}"
            );
        }
        assert!(
            directory
                .path()
                .join("delegated_grants/pepper-fingerprint")
                .exists()
        );
    }

    /// While at-rest encryption is off, a binding's grants cannot be read, but
    /// a binding with none stored is not held back by another's.
    #[tokio::test]
    async fn with_encryption_off_only_a_binding_with_stored_grants_cannot_be_read() {
        use crate::delegation_vault::grants::tests::{grant, key};
        use crate::delegation_vault::grants::{UnreadableGrant, UnreadableReason};
        let directory = tempfile::tempdir().unwrap();
        encrypted_vault(directory.path())
            .await
            .store_grant(grant(&key(), "access"))
            .await
            .unwrap();
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig::default()).unwrap();
        let vault = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let refused = vault
            .binding_grants(&key().binding(), Principals::All)
            .await
            .unwrap_err();
        assert_eq!(
            refused.downcast_ref::<UnreadableGrant>(),
            Some(&UnreadableGrant {
                grant_id: key().record_id(),
                reason: UnreadableReason::EncryptionOff,
            })
        );
        let other_hop = GrantKey {
            hop: "other-transit-point".into(),
            ..key()
        };
        assert!(
            vault
                .binding_grants(&other_hop.binding(), Principals::All)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            vault
                .binding_grant_ids(&key().binding())
                .await
                .unwrap(),
            [key().record_id()]
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
        .filter(|path| !path.ends_with(PEPPER_FINGERPRINT_FILE))
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
                .unwrap()
                .is_empty(),
            "with none stored, there is nothing to read"
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
        vault
            .store_grant(grant(
                &GrantKey {
                    credential_provider_id: "other-provider".into(),
                    ..key()
                },
                "genuine-access",
            ))
            .await
            .unwrap();
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

    /// A pending connect is kept encrypted, read back by its id, and claimed
    /// once: the claim carries the verifier, which is then wiped from the
    /// vault, and a second claim is refused as already used.
    #[tokio::test]
    async fn a_pending_connect_is_claimed_once_and_its_verifier_wiped() {
        use crate::delegation_vault::connects::{ConnectClaim, PendingConnect};
        use crate::delegation_vault::grants::tests::key;
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let other = encrypted_vault(directory.path()).await;
        let now = Utc::now();
        let (connect, _) = PendingConnect::start(&key(), vec!["read".into()], "https://boris.example/cb".into(), now);
        let verifier = connect
            .code_verifier
            .clone()
            .unwrap();
        vault
            .start_connect(connect.clone())
            .await
            .unwrap();
        let file = directory
            .path()
            .join("pending_connects")
            .join(format!("{}.json.enc", connect.id));
        let on_disk = std::fs::read(&file).unwrap();
        assert!(!String::from_utf8_lossy(&on_disk).contains(&verifier), "kept encrypted");
        assert_eq!(
            vault
                .pending_connect(&connect.id)
                .await
                .unwrap()
                .unwrap()
                .principal,
            "owner"
        );

        let (left, right) = tokio::join!(vault.claim_connect(&connect.id, now), other.claim_connect(&connect.id, now));
        let outcomes = [left.unwrap(), right.unwrap()];
        let claimed: Vec<&PendingConnect> = outcomes
            .iter()
            .filter_map(|outcome| match outcome {
                ConnectClaim::Claimed(claimed) => Some(claimed.as_ref()),
                _ => None,
            })
            .collect();
        assert_eq!(claimed.len(), 1, "{outcomes:?}");
        assert_eq!(
            claimed[0]
                .code_verifier
                .as_deref(),
            Some(verifier.as_str())
        );
        assert!(
            outcomes
                .iter()
                .any(|outcome| matches!(outcome, ConnectClaim::AlreadyUsed))
        );
        assert!(
            vault
                .pending_connect(&connect.id)
                .await
                .unwrap()
                .unwrap()
                .code_verifier
                .is_none(),
            "the verifier is gone from the vault once claimed"
        );
        assert!(matches!(
            vault
                .claim_connect(&connect.id, now)
                .await
                .unwrap(),
            ConnectClaim::AlreadyUsed
        ));
        assert!(matches!(
            vault
                .claim_connect("connect-../x", now)
                .await
                .unwrap(),
            ConnectClaim::NotFound
        ));
    }

    /// An expired connect cannot be claimed; the sweep removes expired
    /// connects, claimed or not, and keeps the open ones.
    #[tokio::test]
    async fn an_expired_connect_is_refused_and_swept() {
        use crate::delegation_vault::connects::{ConnectClaim, PendingConnect};
        use crate::delegation_vault::grants::tests::key;
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let now = Utc::now();
        let start = |at| PendingConnect::start(&key(), vec!["read".into()], "https://boris.example/cb".into(), at).0;
        let expired = start(now - chrono::Duration::minutes(11));
        let claimed = start(now - chrono::Duration::minutes(5));
        let open = start(now);
        for connect in [&expired, &claimed, &open] {
            vault
                .start_connect(connect.clone())
                .await
                .unwrap();
        }
        assert!(matches!(
            vault
                .claim_connect(&claimed.id, now)
                .await
                .unwrap(),
            ConnectClaim::Claimed(_)
        ));
        assert!(matches!(
            vault
                .claim_connect(&expired.id, now)
                .await
                .unwrap(),
            ConnectClaim::Expired
        ));
        assert!(
            vault
                .pending_connect(&expired.id)
                .await
                .unwrap()
                .is_none()
        );
        let late = now + chrono::Duration::minutes(6);
        assert_eq!(
            vault
                .sweep_connects(late)
                .await
                .unwrap(),
            1,
            "only the claimed connect has expired by then"
        );
        assert!(
            vault
                .pending_connect(&claimed.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            vault
                .pending_connect(&open.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Each principal of a binding may have only a few connects open, and the
    /// binding only so many in all, so one caller reopening a connect link
    /// never blocks the others; claimed and expired ones do not count, and
    /// another binding is unaffected. The open connects are counted from their
    /// file names alone: no connect is read, let alone decrypted, to count it.
    #[tokio::test]
    async fn each_principal_and_binding_has_a_limited_number_of_open_connects() {
        use crate::delegation_vault::connects::{
            MAX_PENDING_CONNECTS_PER_BINDING, MAX_PENDING_CONNECTS_PER_PRINCIPAL, PendingConnect,
            TooManyPendingConnects,
        };
        use crate::delegation_vault::grants::{GrantKey, tests::key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let now = Utc::now();
        let start = |key: &GrantKey, at| {
            PendingConnect::start(key, vec!["read".into()], "https://boris.example/cb".into(), at).0
        };
        let caller = |index: usize| {
            GrantKey::caller(Some("tenant-a"), "surface", "transit-point-id", "provider", &format!("{index:064x}"))
                .unwrap()
        };
        let first = start(&caller(0), now);
        vault
            .start_connect(first.clone())
            .await
            .unwrap();
        for _ in 1..MAX_PENDING_CONNECTS_PER_PRINCIPAL {
            vault
                .start_connect(start(&caller(0), now))
                .await
                .unwrap();
        }
        let refused = vault
            .start_connect(start(&caller(0), now))
            .await
            .unwrap_err();
        assert!(refused.is::<TooManyPendingConnects>(), "one principal's share is used up: {refused}");
        vault
            .claim_connect(&first.id, now)
            .await
            .unwrap();
        vault
            .start_connect(start(&caller(0), now))
            .await
            .expect("a claimed connect no longer counts");
        vault
            .start_connect(start(&caller(0), now + chrono::Duration::minutes(11)))
            .await
            .expect("expired connects no longer count");

        let principals = MAX_PENDING_CONNECTS_PER_BINDING / MAX_PENDING_CONNECTS_PER_PRINCIPAL;
        for index in 1..=principals {
            for _ in 0..MAX_PENDING_CONNECTS_PER_PRINCIPAL {
                let _ = vault
                    .start_connect(start(&caller(index), now))
                    .await;
            }
        }
        let other_binding = GrantKey {
            hop: "other-hop".into(),
            ..key()
        };
        vault
            .start_connect(start(&other_binding, now))
            .await
            .expect("another binding has its own limit");
        let connects = directory
            .path()
            .join("pending_connects");
        for entry in std::fs::read_dir(&connects).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                std::fs::write(&path, "not a connect").unwrap();
            }
        }
        let refused = vault
            .start_connect(start(&caller(principals + 1), now))
            .await
            .unwrap_err();
        assert!(refused.is::<TooManyPendingConnects>(), "the binding's limit is used up: {refused}");
    }

    /// Connects are kept only while grants can be: with at-rest encryption
    /// and a configured pepper.
    #[tokio::test]
    async fn connects_are_refused_while_grants_cannot_be_kept() {
        use crate::delegation_vault::connects::PendingConnect;
        use crate::delegation_vault::grants::tests::key;
        let directory = tempfile::tempdir().unwrap();
        with_at_rest_encryption();
        crate::identity::credential_identity::configure_pepper_for_tests(false);
        let vault = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let (connect, _) =
            PendingConnect::start(&key(), vec!["read".into()], "https://boris.example/cb".into(), Utc::now());
        assert!(
            vault
                .start_connect(connect)
                .await
                .unwrap_err()
                .is::<EphemeralPepper>()
        );
    }

    fn tokens(access_token: &str) -> crate::delegation_vault::grants::ObtainedTokens {
        crate::delegation_vault::grants::ObtainedTokens {
            access_token: access_token.into(),
            refresh_token: Some(format!("{access_token}-refresh")),
            scopes: vec!["read".into()],
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        }
    }

    /// A grant's refresh is claimed once across every node sharing the vault;
    /// the rotated tokens are written for the claimed version only, and a
    /// claim made for an earlier version is refused as changed.
    #[tokio::test]
    async fn a_grants_refresh_is_claimed_once_and_written_for_its_version() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let first = encrypted_vault(directory.path()).await;
        let second = encrypted_vault(directory.path()).await;
        let stored = first
            .store_grant(grant(&key(), "access"))
            .await
            .unwrap()
            .grant;
        let now = Utc::now();
        let (left, right) =
            tokio::join!(first.claim_grant_refresh(&stored, now), second.claim_grant_refresh(&stored, now));
        let claim = match (left, right) {
            (Ok(claim), Err(RefreshError::InProgress)) | (Err(RefreshError::InProgress), Ok(claim)) => claim,
            _ => panic!("exactly one refresh may claim a grant"),
        };
        assert_eq!(claim.grant().access_token, "access");
        let refreshed = second
            .complete_grant_refresh(claim, tokens("rotated"), now)
            .await
            .unwrap();
        assert_eq!(refreshed.access_token, "rotated");
        assert_eq!(
            refreshed
                .refresh_token
                .as_deref(),
            Some("rotated-refresh")
        );
        assert_eq!(refreshed.refreshed_at, Some(now));
        assert!(refreshed.updated_at > stored.updated_at);
        assert_eq!(
            first
                .grant(&key())
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "rotated"
        );
        assert!(matches!(
            first
                .claim_grant_refresh(&stored, now)
                .await,
            Err(RefreshError::Changed)
        ));

        let claim = first
            .claim_grant_refresh(&refreshed, now)
            .await
            .unwrap();
        let late = now + chrono::Duration::seconds(120);
        let written = first
            .complete_grant_refresh(claim, tokens("late"), late)
            .await
            .expect("a late answer to a claim nobody took over is written");
        assert_eq!(written.access_token, "late");
        assert_eq!(
            first
                .grant(&key())
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "late"
        );
    }

    /// A refresh refused with `invalid_grant` deletes the grant only while it
    /// is still the version the refresh was claimed for, and hands it back so
    /// its tokens are revoked: a grant a reconnect stored meanwhile is kept.
    /// A grant the vendor refused is deleted only while it still holds the
    /// access token the vendor refused.
    #[tokio::test]
    async fn a_refusal_removes_only_the_grant_it_was_about() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let first = vault
            .store_grant(grant(&key(), "first"))
            .await
            .unwrap()
            .grant;
        let now = Utc::now();
        let claim = vault
            .claim_grant_refresh(&first, now)
            .await
            .unwrap();
        let reconnected = vault
            .store_grant(grant(&key(), "second"))
            .await
            .unwrap()
            .grant;
        assert!(matches!(
            vault
                .discard_grant_refresh(claim)
                .await,
            Err(RefreshError::Changed)
        ));
        let kept = vault
            .grant(&key())
            .await
            .unwrap()
            .expect("the reconnected grant is kept");
        assert_eq!(kept.access_token, "second");

        let claim = vault
            .claim_grant_refresh(&reconnected, now)
            .await
            .unwrap();
        let discarded = vault
            .discard_grant_refresh(claim)
            .await
            .unwrap();
        assert_eq!(discarded.access_token, "second", "the grant deleted is handed back");
        assert!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .is_none()
        );

        let third = vault
            .store_grant(grant(&key(), "third"))
            .await
            .unwrap()
            .grant;
        assert!(
            vault
                .delete_grant_holding(&third.id, "second")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .is_some(),
            "a grant holding another token is kept"
        );
        assert_eq!(
            vault
                .delete_grant_holding(&third.id, "third")
                .await
                .unwrap()
                .map(|grant| grant.access_token)
                .as_deref(),
            Some("third")
        );
        assert!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// A failed refresh is recorded with its wait, and the claim released; a
    /// claim that outlived its window is uncertain, and the grant is never
    /// refreshed again. Deleting a grant drops its claim.
    #[tokio::test]
    async fn a_failed_or_uncertain_refresh_is_recorded_on_the_grant() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let stored = vault
            .store_grant(grant(&key(), "access"))
            .await
            .unwrap()
            .grant;
        let now = Utc::now();
        let claim = vault
            .claim_grant_refresh(&stored, now)
            .await
            .unwrap();
        let failed = vault
            .fail_grant_refresh(claim, FailedRefresh::Retried, now)
            .await
            .unwrap();
        assert_eq!(failed.refresh_failures, 1);
        assert_eq!(failed.refresh_retry_at, Some(now + chrono::Duration::seconds(30)));
        assert_eq!(failed.access_token, "access");

        let claim = vault
            .claim_grant_refresh(&failed, now)
            .await
            .unwrap();
        drop(claim);
        assert!(matches!(
            vault
                .claim_grant_refresh(&failed, now)
                .await,
            Err(RefreshError::InProgress)
        ));
        let late = now + chrono::Duration::seconds(46);
        assert!(matches!(
            vault
                .claim_grant_refresh(&failed, late)
                .await,
            Err(RefreshError::Uncertain)
        ));
        let abandoned = vault
            .abandon_grant_refresh(&failed, late)
            .await
            .unwrap();
        assert!(abandoned.refresh_abandoned());
        assert_eq!(abandoned.state(), "refresh_failed");

        let claim = vault
            .claim_grant_refresh(&abandoned, late)
            .await
            .unwrap();
        drop(claim);
        vault
            .delete_grant(&abandoned.id)
            .await
            .unwrap();
        vault
            .store_grant(grant(&key(), "access"))
            .await
            .unwrap();
        let fresh = vault
            .grant(&key())
            .await
            .unwrap()
            .unwrap();
        assert!(
            vault
                .claim_grant_refresh(&fresh, late)
                .await
                .is_ok(),
            "a deleted grant's claim does not outlive it"
        );
    }

    /// A refresh claimed for a grant is in progress for every other call until
    /// the claim's window ends, whatever that call's clock read: one that read
    /// the time before the claim was taken, or a node whose clock is behind,
    /// waits for the refresh rather than take it for dead. The window starts
    /// when the claim is taken, under the vault's lock, not when the call that
    /// took it read its clock.
    #[tokio::test]
    async fn a_running_refresh_is_never_taken_for_dead_before_its_window_ends() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let stored = vault
            .store_grant(grant(&key(), "access"))
            .await
            .unwrap()
            .grant;
        let t0 = Utc::now();
        let claimed_at = t0 + chrono::Duration::milliseconds(500);
        let claim = vault
            .claim_grant_refresh(&stored, claimed_at)
            .await
            .unwrap();
        assert!(
            matches!(
                vault
                    .claim_grant_refresh(&stored, t0)
                    .await,
                Err(RefreshError::InProgress)
            ),
            "a claim timed after this call read its clock is in progress"
        );
        assert!(matches!(
            vault
                .claim_grant_refresh(&stored, claimed_at + chrono::Duration::seconds(46))
                .await,
            Err(RefreshError::Uncertain)
        ));
        drop(claim);

        let other = GrantKey::owner(Some("tenant-a"), "surface", "other-hop", "provider");
        let stored = vault
            .store_grant(grant(&other, "other"))
            .await
            .unwrap()
            .grant;
        let _claim = vault
            .claim_grant_refresh(&stored, Utc::now() - chrono::Duration::seconds(60))
            .await
            .unwrap();
        assert!(
            matches!(
                vault
                    .claim_grant_refresh(&stored, Utc::now())
                    .await,
                Err(RefreshError::InProgress)
            ),
            "a call that read its clock long before it got the lock starts its claim's window when it takes it"
        );
    }

    /// A claim whose grant was written since, at another version, is over:
    /// whatever left it behind, a crash between writing the grant and
    /// clearing its claim or a claim that could not be cleared, it neither
    /// holds up nor abandons the next refresh, even of a refresh token the
    /// authorization server did not rotate.
    #[tokio::test]
    async fn a_claim_left_behind_by_an_earlier_version_never_holds_up_a_refresh() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let stored = vault
            .store_grant(grant(&key(), "access"))
            .await
            .unwrap()
            .grant;
        let now = Utc::now();
        let claim = vault
            .claim_grant_refresh(&stored, now)
            .await
            .unwrap();
        let left = vault
            .grant_refreshes
            .get(&stored.id)
            .await
            .unwrap()
            .unwrap();
        let not_rotated = ObtainedTokens {
            access_token: "second".into(),
            refresh_token: None,
            scopes: vec!["read".into()],
            expires_at: Some(now + chrono::Duration::hours(1)),
        };
        let refreshed = vault
            .complete_grant_refresh(claim, not_rotated, now)
            .await
            .unwrap();
        assert_eq!(refreshed.refresh_token, stored.refresh_token);
        vault
            .grant_refreshes
            .save_atomic(&left)
            .await
            .unwrap();
        let claim = vault
            .claim_grant_refresh(&refreshed, now)
            .await
            .expect("within the window of the claim left behind");
        drop(claim);
        vault
            .grant_refreshes
            .save_atomic(&left)
            .await
            .unwrap();
        assert!(
            vault
                .claim_grant_refresh(&refreshed, now + chrono::Duration::seconds(60))
                .await
                .is_ok(),
            "and after it"
        );
    }

    /// A refresh whose outcome was written counts as done even when its claim
    /// cannot be cleared afterwards, as when the vault's disk refuses the
    /// delete: the grant holds what was written, and the claim left behind is
    /// over, since the grant's version moved on.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_written_refresh_stands_when_its_claim_cannot_be_cleared() {
        use crate::delegation_vault::grants::tests::{grant, key};
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let stored = vault
            .store_grant(grant(&key(), "access"))
            .await
            .unwrap()
            .grant;
        let now = Utc::now();
        let claims = directory
            .path()
            .join(GRANT_REFRESH_CLAIMS_DIRECTORY);
        let read_only = || std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o555)).unwrap();
        let writable = || std::fs::set_permissions(&claims, std::fs::Permissions::from_mode(0o755)).unwrap();

        let claim = vault
            .claim_grant_refresh(&stored, now)
            .await
            .unwrap();
        read_only();
        if std::fs::write(claims.join("probe"), b"").is_ok() {
            // Running as root: no delete is refused, so there is nothing to show.
            writable();
            return;
        }
        let completed = vault
            .complete_grant_refresh(claim, tokens("rotated"), now)
            .await;
        writable();
        let refreshed = completed.expect("the tokens were written");
        assert_eq!(refreshed.access_token, "rotated");
        assert_eq!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "rotated"
        );
        let claim = vault
            .claim_grant_refresh(&refreshed, now)
            .await
            .expect("the claim left behind is over");

        read_only();
        let failed = vault
            .fail_grant_refresh(claim, FailedRefresh::Retried, now)
            .await;
        writable();
        assert_eq!(
            failed
                .expect("the failure was written")
                .refresh_failures,
            1
        );
    }

    /// A removal tied to the connection it read deletes that connection's
    /// grant however often it was refreshed since, but never the grant of a
    /// connect the person made again since.
    #[tokio::test]
    async fn a_removal_deletes_the_connection_it_read_and_never_a_reconnect() {
        use crate::delegation_vault::grants::tests::{grant, key};
        let directory = tempfile::tempdir().unwrap();
        let vault = encrypted_vault(directory.path()).await;
        let stored = vault
            .store_grant(grant(&key(), "first"))
            .await
            .unwrap()
            .grant;
        let now = Utc::now();
        let claim = vault
            .claim_grant_refresh(&stored, now)
            .await
            .unwrap();
        vault
            .complete_grant_refresh(claim, tokens("refreshed"), now)
            .await
            .unwrap();
        assert_eq!(
            vault
                .delete_grant_of_connection(&stored.id, stored.created_at)
                .await
                .unwrap()
                .map(|grant| grant.access_token)
                .as_deref(),
            Some("refreshed")
        );
        assert!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .is_none()
        );

        let first = vault
            .store_grant(grant(&key(), "first"))
            .await
            .unwrap()
            .grant;
        let reconnected = vault
            .store_grant(grant(&key(), "second"))
            .await
            .unwrap()
            .grant;
        assert_ne!(first.created_at, reconnected.created_at);
        assert!(
            vault
                .delete_grant_of_connection(&first.id, first.created_at)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            vault
                .grant(&key())
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "second"
        );
    }
}
