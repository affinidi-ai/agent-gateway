//! The daily sweep of the delegation vault's grants by binding.
//!
//! A backstop for what the management API does at once: it removes pending
//! connects that expired, claimed or not; grants whose binding the surface no
//! longer serves, as after a surface file was edited by hand, or whose scopes
//! it no longer permits; grants written under an earlier identity hash pepper,
//! which can never be released again; grants whose access token expired and
//! cannot be refreshed; and grants whose access token expired more than
//! [`FAILING_GRANT_DAYS`] days ago and whose refresh has failed ever since.
//! While the pepper is not set, or is not the one the grants stored were
//! written under, it removes no grant. Every grant it removes is revoked at its authorization server, as every
//! removal is. It also decides the revocations a removal left to it because
//! the vault could not tell whether the vendor account's authorization was
//! still in use ([`super::revocation::revoke_deferred_of`]), and tries again the
//! pending revocations kept: those in flight when the gateway stopped, which
//! it also tries when the gateway starts, and those that could not reach
//! their vendor ([`super::revocation::revoke_pending_of`]).
//!
//! Grants are found by their file names, one binding at a time: the sweep
//! reads one of the binding's grants to learn its surface, takes that
//! surface's lock, and only then reads the binding's grants it decides on, so
//! it never races a surface write or a connect's completion, and never
//! removes a grant a reconnect stored while it waited. A grant that cannot be
//! read is left for an operator to purge. A binding whose surface or provider
//! cannot be read is left as it is, and counted, until the next sweep.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::grants::DelegatedGrant;
use super::storage::DelegationVaultStorage;
use crate::credential_providers::CredentialProvider;
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::secrets::SecretsStore;
use crate::surfaces::AgentSurfaceStore;

/// How often the sweep runs.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after startup the first sweep runs.
pub const FIRST_SWEEP_DELAY: Duration = Duration::from_secs(10 * 60);

/// What the sweep needs.
#[derive(Clone)]
pub struct Sweeper {
    pub vault: Arc<dyn DelegationVaultStorage>,
    pub surfaces: Arc<dyn AgentSurfaceStore>,
    pub providers: Arc<dyn CredentialProviderStorage>,
    pub secrets: Option<Arc<dyn SecretsStore>>,
    /// The test allow-list of authorization server fixtures; `None` in
    /// production.
    pub exact_allowlist: Option<String>,
}

/// What one sweep removed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepReport {
    pub expired_connects: usize,
    pub unbound_grants: usize,
    pub earlier_pepper_grants: usize,
    pub expired_grants: usize,
    /// Grants whose access token expired more than [`FAILING_GRANT_DAYS`]
    /// days ago and whose refresh has failed ever since.
    pub failing_grants: usize,
    pub unreadable_grants: usize,
    /// Bindings left as they are because what deciding on them needs could
    /// not be read: their surface or their provider.
    pub skipped_bindings: usize,
    /// Revocations deferred by a removal that could not tell whether the
    /// vendor account's authorization was in use, decided now.
    pub deferred_revocations: usize,
}

/// How many days after its access token expired a grant whose refresh keeps
/// failing is removed.
pub const FAILING_GRANT_DAYS: i64 = 30;

/// Why the sweep removes a grant.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Removal {
    Unbound,
    EarlierPepper,
    Expired,
    Failing,
}

/// The binding part of a grant's record id: `grant-<provider tag>-<binding
/// tag>-`.
fn binding_prefix(id: &str) -> Option<&str> {
    let mut dashes = id
        .match_indices('-')
        .map(|(index, _)| index);
    let third = dashes.nth(2)?;
    Some(&id[..=third])
}

impl Sweeper {
    /// Try again the pending revocations kept, at once while the node is
    /// active and again each time it becomes active, then run the sweep every
    /// [`SWEEP_INTERVAL`], the first after [`FIRST_SWEEP_DELAY`], while the
    /// node is active.
    pub fn spawn(self) {
        tokio::spawn(async move {
            let mut mode_changes = crate::server::mode::subscribe_mode_changes();
            if !crate::server::mode::is_standby() {
                self.retry_pending_logged()
                    .await;
            }
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + FIRST_SWEEP_DELAY, SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut listening = true;
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    change = mode_changes.recv(), if listening => {
                        listening = !matches!(change, Err(tokio::sync::broadcast::error::RecvError::Closed));
                        if became_active(&change) && !crate::server::mode::is_standby() {
                            self.retry_pending_logged().await;
                        }
                        continue;
                    }
                }
                if crate::server::mode::is_standby() {
                    continue;
                }
                let report = self
                    .sweep_while(Utc::now(), || !crate::server::mode::is_standby())
                    .await;
                tracing::info!(
                    target: "credential_delegation",
                    expired_connects = report.expired_connects,
                    unbound_grants = report.unbound_grants,
                    earlier_pepper_grants = report.earlier_pepper_grants,
                    expired_grants = report.expired_grants,
                    failing_grants = report.failing_grants,
                    unreadable_grants = report.unreadable_grants,
                    skipped_bindings = report.skipped_bindings,
                    deferred_revocations = report.deferred_revocations,
                    "Swept the delegation vault's grants by binding"
                );
            }
        });
    }

    /// Sweep once, as of `now`.
    #[cfg(test)]
    pub async fn sweep(
        &self,
        now: DateTime<Utc>,
    ) -> SweepReport {
        self.sweep_while(now, || true)
            .await
    }

    /// Sweep once, as of `now`, stopping between bindings once `keep_going`
    /// says no: a sweep waits for each binding's revocations, so it can
    /// outlast the node being active.
    pub async fn sweep_while(
        &self,
        now: DateTime<Utc>,
        keep_going: impl Fn() -> bool,
    ) -> SweepReport {
        let mut report = SweepReport {
            expired_connects: self
                .vault
                .sweep_connects(now)
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(target: "credential_delegation", error = %error, "Failed to sweep pending connects");
                    0
                }),
            ..SweepReport::default()
        };
        if !keep_going() {
            return report;
        }
        let mut providers = HashMap::new();
        report.deferred_revocations = self
            .decide_deferred(now, &mut providers)
            .await;
        match self
            .vault
            .derives_stored_grant_ids()
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(
                    target: "credential_delegation",
                    "Swept no grant: AG_IDENTITY_HASH_PEPPER is not set, or the grants stored were written under \
                     another pepper, so no grant's id tells whether it can still be released; restore the pepper \
                     they were written under, or have an operator purge them"
                );
                return report;
            }
            Err(error) => {
                tracing::warn!(
                    target: "credential_delegation",
                    error = %error,
                    "Swept no grant: the pepper the grants stored were written under cannot be read"
                );
                return report;
            }
        }
        let ids = match self.vault.grant_ids().await {
            Ok(ids) => ids,
            Err(error) => {
                tracing::warn!(target: "credential_delegation", error = %error, "Failed to list grants to sweep");
                return report;
            }
        };
        let mut bindings: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for id in ids {
            if let Some(prefix) = binding_prefix(&id) {
                bindings
                    .entry(prefix.to_string())
                    .or_default()
                    .push(id);
            }
        }
        for ids in bindings.into_values() {
            if !keep_going() {
                break;
            }
            self.sweep_binding(ids, now, &mut providers, &mut report)
                .await;
        }
        report
    }

    async fn retry_pending_logged(&self) {
        let tried = self.retry_pending().await;
        tracing::info!(
            target: "credential_delegation",
            pending_revocations = tried,
            "Tried again the revocations kept pending"
        );
    }

    /// Try again the pending revocations kept, with the providers of their
    /// grants. Those whose provider cannot be read wait for the next sweep.
    pub async fn retry_pending(&self) -> usize {
        let Some((revoker, kept)) = self
            .kept_revoker(&mut HashMap::new())
            .await
        else {
            return 0;
        };
        super::revocation::revoke_pending_of(revoker, kept).await
    }

    /// Decide, as of `now`, the revocations kept, with the providers of their
    /// grants. Those whose provider cannot be read wait for the next sweep.
    async fn decide_deferred(
        &self,
        now: DateTime<Utc>,
        providers: &mut HashMap<String, Option<CredentialProvider>>,
    ) -> usize {
        let Some((revoker, kept)) = self
            .kept_revoker(providers)
            .await
        else {
            return 0;
        };
        super::revocation::revoke_deferred_of(revoker, kept, now).await
    }

    /// The revocations kept that can be decided now, and their revoker, with
    /// the provider of each of their grants that still exists. Those whose
    /// provider cannot be read are left out, so one unreadable provider never
    /// holds up the others, and never has its revocations taken for a gone
    /// provider's. `None` when none are left, or they cannot be read.
    async fn kept_revoker(
        &self,
        providers: &mut HashMap<String, Option<CredentialProvider>>,
    ) -> Option<(super::revocation::Revoker, Vec<crate::delegation_vault::storage::DeferredRevocation>)> {
        let deferred = match self
            .vault
            .deferred_revocations()
            .await
        {
            Ok(deferred) => deferred,
            Err(error) => {
                tracing::warn!(target: "credential_delegation", error = %error, "Failed to read kept revocations");
                return None;
            }
        };
        if deferred.is_empty() {
            return None;
        }
        let mut known = HashMap::new();
        let mut unreadable = std::collections::HashSet::new();
        for deferral in &deferred {
            let id = &deferral
                .grant
                .credential_provider_id;
            if known.contains_key(id) || unreadable.contains(id) {
                continue;
            }
            match self
                .provider(id, providers)
                .await
            {
                Ok(Some(provider)) => {
                    known.insert(id.clone(), provider);
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        target: "credential_delegation",
                        error = %error,
                        "Failed to read a provider to decide its kept revocations; they wait for the next sweep"
                    );
                    unreadable.insert(id.clone());
                }
            }
        }
        let decidable: Vec<_> = deferred
            .into_iter()
            .filter(|deferral| {
                !unreadable.contains(
                    &deferral
                        .grant
                        .credential_provider_id,
                )
            })
            .collect();
        if decidable.is_empty() {
            return None;
        }
        Some((
            super::revocation::Revoker {
                providers: known,
                secrets: self.secrets.clone(),
                exact_allowlist: self.exact_allowlist.clone(),
                actor: None,
                vault: Some(self.vault.clone()),
            },
            decidable,
        ))
    }

    /// The provider `id`, read once per sweep. A provider store that cannot
    /// be read is an error, never a provider that is gone.
    async fn provider(
        &self,
        id: &str,
        providers: &mut HashMap<String, Option<CredentialProvider>>,
    ) -> anyhow::Result<Option<CredentialProvider>> {
        if let Some(provider) = providers.get(id) {
            return Ok(provider.clone());
        }
        let provider = self
            .providers
            .get_checked(id)
            .await?;
        providers.insert(id.to_string(), provider.clone());
        Ok(provider)
    }

    /// Sweep the grants of one binding, reading them, and deciding, under its
    /// surface's lock. One grant is read first to learn the surface.
    async fn sweep_binding(
        &self,
        ids: Vec<String>,
        now: DateTime<Utc>,
        providers: &mut HashMap<String, Option<CredentialProvider>>,
        report: &mut SweepReport,
    ) {
        let mut unreadable = 0;
        let mut surface_id = None;
        for id in &ids {
            match self
                .vault
                .grant_by_id(id)
                .await
            {
                Ok(Some(grant)) => {
                    surface_id = Some(grant.surface_id);
                    break;
                }
                Ok(None) => {}
                Err(_) => unreadable += 1,
            }
        }
        let Some(surface_id) = surface_id else {
            report.unreadable_grants += unreadable;
            return;
        };
        let lock = crate::identity::handlers::surface_grants::lock_surface(&surface_id).await;
        let surface = match self
            .surfaces
            .get_checked(&surface_id)
            .await
        {
            Ok(surface) => surface,
            Err(error) => {
                tracing::warn!(target: "credential_delegation", error = %error, "Failed to read a surface to sweep its grants");
                report.skipped_bindings += 1;
                return;
            }
        };
        let mut grants = Vec::with_capacity(ids.len());
        for id in ids {
            match self
                .vault
                .grant_by_id(&id)
                .await
            {
                Ok(Some(grant)) => grants.push(grant),
                Ok(None) => {}
                Err(_) => report.unreadable_grants += 1,
            }
        }
        let mut removals = Vec::new();
        let mut revocation_providers = HashMap::new();
        for grant in grants {
            let provider = match self
                .provider(&grant.credential_provider_id, providers)
                .await
            {
                Ok(provider) => provider,
                Err(error) => {
                    tracing::warn!(
                        target: "credential_delegation",
                        error = %error,
                        "Failed to read a provider to sweep its grants; the binding is left until the next sweep"
                    );
                    report.skipped_bindings += 1;
                    return;
                }
            };
            let default_scopes = provider
                .as_ref()
                .map_or(&[][..], |provider| &provider.default_scopes);
            let removal = if grant.key().record_id() != grant.id {
                Some(Removal::EarlierPepper)
            } else if !surface
                .as_ref()
                .is_some_and(|surface| {
                    crate::identity::handlers::surface_grants::serves_grant(surface, &grant, default_scopes)
                })
            {
                Some(Removal::Unbound)
            } else if grant.is_expired() && !refreshable(&grant, provider.as_ref()) {
                Some(Removal::Expired)
            } else if grant.failing_for(now, FAILING_GRANT_DAYS) {
                Some(Removal::Failing)
            } else {
                None
            };
            if let Some(removal) = removal {
                if let Some(provider) = provider {
                    revocation_providers.insert(provider.id.clone(), provider);
                }
                removals.push((grant, removal));
            }
        }
        if removals.is_empty() {
            return;
        }
        let removed: Vec<DelegatedGrant> = removals
            .iter()
            .map(|(grant, _)| grant.clone())
            .collect();
        let revoker = super::revocation::Revoker {
            providers: revocation_providers,
            secrets: self.secrets.clone(),
            exact_allowlist: self.exact_allowlist.clone(),
            actor: None,
            vault: Some(self.vault.clone()),
        };
        match super::revocation::delete_then_revoke(&self.vault, removed, revoker, lock, None).await {
            Ok(revocations) => {
                for (_, removal) in removals {
                    match removal {
                        Removal::Unbound => report.unbound_grants += 1,
                        Removal::EarlierPepper => report.earlier_pepper_grants += 1,
                        Removal::Expired => report.expired_grants += 1,
                        Removal::Failing => report.failing_grants += 1,
                    }
                }
                // One binding's revocations at a time, so a sweep never has
                // more vendor calls open than one revocation task allows.
                if let Err(error) = revocations.await {
                    tracing::warn!(target: "credential_delegation", error = %error, "A swept binding's revocations ended early");
                }
            }
            Err(error) => {
                tracing::warn!(target: "credential_delegation", error = %error, "Failed to remove swept grants");
            }
        }
    }
}

/// Whether a mode change, as received, may have made the node active: a
/// promotion, or changes missed while the receiver lagged.
fn became_active(change: &Result<crate::server::mode::ModeChange, tokio::sync::broadcast::error::RecvError>) -> bool {
    match change {
        Ok(change) => change.mode == crate::server::mode::ServerMode::Active,
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
        Err(tokio::sync::broadcast::error::RecvError::Closed) => false,
    }
}

/// Whether an expired grant can still be refreshed, with `provider`, its
/// provider, when there is one.
fn refreshable(
    grant: &DelegatedGrant,
    provider: Option<&CredentialProvider>,
) -> bool {
    grant
        .refresh_token
        .as_deref()
        .is_some_and(|token| !token.is_empty())
        && !grant.refresh_abandoned()
        && provider.is_some_and(|provider| provider.token_refresh_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::connects::PendingConnect;
    use crate::delegation_vault::grants::GrantKey;
    use crate::delegation_vault::revocation::tests::RecordingServer;
    use serde_json::json;

    /// A sweeper over an encrypted vault, a surface that serves `vendor` for
    /// its owner at `served`, and `providers`: a store holding `vendor`, whose
    /// refresh is enabled as `refresh` says, unless the test brings its own.
    async fn sweeper(
        directory: &tempfile::TempDir,
        server: &RecordingServer,
        refresh: bool,
    ) -> Sweeper {
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "AG_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        })
        .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let providers = crate::credential_providers::storage::FileSystemCredentialProviderStore::new(
            directory
                .path()
                .join("providers"),
        )
        .await
        .unwrap();
        let mut provider = crate::delegation_vault::revocation::tests::provider(Some(&server.url), "none", None);
        provider.id = "vendor".into();
        provider.token_refresh_enabled = refresh;
        providers
            .create(provider)
            .await
            .unwrap();
        let surfaces = crate::surfaces::FileSystemAgentSurfaceStore::new(
            directory
                .path()
                .join("surfaces"),
        )
        .await
        .unwrap();
        surfaces
            .save(
                &serde_json::from_value(json!({
                    "surface_id": "surface", "name": "surface", "tenant_id": "tenant-a",
                    "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
                    "target": {"endpoint": "https://managed.example/agent"},
                    "transit": {"points": [{"id": "served", "alias": "served",
                        "target_endpoint": "https://vendor.example/mcp", "require_transit_token": true,
                        "transit_credentials": {"credential_provider_id": "vendor", "consent_mode": "external",
                            "subject": "owner"}}]}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        Sweeper {
            vault: Arc::new(
                crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                    .await
                    .unwrap(),
            ),
            surfaces: Arc::new(surfaces),
            providers: Arc::new(providers),
            secrets: None,
            exact_allowlist: Some(server.origin()),
        }
    }

    async fn store(
        sweeper: &Sweeper,
        key: &GrantKey,
        access: &str,
        expires_in: i64,
    ) {
        let mut grant = crate::delegation_vault::grants::tests::grant(key, access);
        grant.expires_at = Some(Utc::now() + chrono::Duration::seconds(expires_in));
        sweeper
            .vault
            .store_grant(grant)
            .await
            .unwrap();
    }

    /// A store of credential providers that cannot be read.
    struct UnreadableProviders;

    #[async_trait::async_trait]
    impl CredentialProviderStorage for UnreadableProviders {
        async fn get_checked(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<crate::credential_providers::CredentialProvider>> {
            self.get(id).await
        }

        async fn create(
            &self,
            _provider: CredentialProvider,
        ) -> anyhow::Result<CredentialProvider> {
            anyhow::bail!("unreadable")
        }

        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<CredentialProvider>> {
            anyhow::bail!("unreadable")
        }

        async fn list(&self) -> anyhow::Result<Vec<CredentialProvider>> {
            anyhow::bail!("unreadable")
        }

        async fn update(
            &self,
            _provider: CredentialProvider,
        ) -> anyhow::Result<CredentialProvider> {
            anyhow::bail!("unreadable")
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<bool> {
            anyhow::bail!("unreadable")
        }

        async fn find_by_provider_id(
            &self,
            _tenant_id: Option<&str>,
            _provider_id: &str,
        ) -> anyhow::Result<Option<CredentialProvider>> {
            anyhow::bail!("unreadable")
        }
    }

    /// Kept revocations are tried again on a promotion to active, and after
    /// mode changes were missed, never on a step down to standby.
    #[test]
    fn a_promotion_tries_the_kept_revocations_again() {
        use crate::server::mode::{ModeChange, ServerMode};
        use tokio::sync::broadcast::error::RecvError;
        let change = |mode| Ok(ModeChange { mode, generation: 1 });
        assert!(became_active(&change(ServerMode::Active)));
        assert!(!became_active(&change(ServerMode::Standby)));
        assert!(became_active(&Err(RecvError::Lagged(3))));
        assert!(!became_active(&Err(RecvError::Closed)));
    }

    /// While the grants stored were written under another pepper, recorded
    /// or not, or no pepper is set, every grant's id differs from the one this
    /// gateway derives: the sweep removes and revokes none of them, whatever
    /// else it would remove them for. With the pepper restored it sweeps as
    /// before, with its fingerprint lost or not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sweep_removes_no_grant_while_the_pepper_is_not_the_grants() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        crate::identity::credential_identity::configure_pepper_bytes_for_tests(&[1; 32]);
        let mut sweeper = sweeper(&directory, &server, false).await;
        store(&sweeper, &GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor"), "served", 3600).await;
        store(&sweeper, &GrantKey::owner(Some("tenant-a"), "surface", "removed-hop", "vendor"), "unbound", 3600).await;
        let fingerprint = directory
            .path()
            .join("vault/delegated_grants/pepper-fingerprint");
        let ours = std::fs::read_to_string(&fingerprint).unwrap();
        let open = |pepper_set: bool| {
            let path = directory.path().join("vault");
            async move {
                crate::identity::credential_identity::configure_pepper_for_tests(pepper_set);
                let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
                    crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(path)
                        .await
                        .unwrap(),
                );
                vault
            }
        };

        std::fs::write(&fingerprint, "another pepper").unwrap();
        sweeper.vault = open(true).await;
        assert_eq!(
            sweeper
                .sweep(Utc::now())
                .await,
            SweepReport::default(),
            "another pepper"
        );

        std::fs::write(&fingerprint, &ours).unwrap();
        sweeper.vault = open(false).await;
        assert_eq!(
            sweeper
                .sweep(Utc::now())
                .await,
            SweepReport::default(),
            "no pepper set"
        );

        std::fs::remove_file(&fingerprint).unwrap();
        crate::identity::credential_identity::configure_pepper_bytes_for_tests(&[2; 32]);
        sweeper.vault = open(true).await;
        assert_eq!(
            sweeper
                .sweep(Utc::now())
                .await,
            SweepReport::default(),
            "another pepper, its fingerprint lost"
        );

        assert_eq!(
            sweeper
                .vault
                .grant_ids()
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(server.requests().is_empty(), "nothing was revoked");

        crate::identity::credential_identity::configure_pepper_bytes_for_tests(&[1; 32]);
        sweeper.vault = open(true).await;
        let report = sweeper
            .sweep(Utc::now())
            .await;
        assert_eq!(report.unbound_grants, 1, "with the pepper restored, its fingerprint still lost");
        assert_eq!(report.earlier_pepper_grants, 0);
        assert_eq!(
            sweeper
                .vault
                .grant_ids()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// When the provider store cannot be read, the sweep cannot tell whether
    /// an expired grant can be refreshed: it skips the binding, and removes
    /// nothing, rather than take the provider for gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sweep_skips_a_binding_whose_provider_cannot_be_read() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let mut sweeper = sweeper(&directory, &server, true).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        store(&sweeper, &key, "expired", -60).await;
        sweeper.providers = Arc::new(UnreadableProviders);
        let report = sweeper
            .sweep(Utc::now())
            .await;
        assert_eq!(report.expired_grants, 0);
        assert_eq!(report.skipped_bindings, 1);
        assert!(
            sweeper
                .vault
                .grant(&key)
                .await
                .unwrap()
                .is_some(),
            "the grant is kept"
        );
        assert!(server.requests().is_empty(), "and not revoked");
    }

    /// A surface whose file is stored but cannot be read is not a surface that
    /// is gone: the sweep skips its binding, and removes and revokes nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sweep_skips_a_binding_whose_surface_cannot_be_read() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let mut sweeper = sweeper(&directory, &server, true).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        store(&sweeper, &key, "live", 3600).await;
        let surfaces = directory
            .path()
            .join("surfaces");
        for entry in std::fs::read_dir(&surfaces).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with("surface.json")
                })
            {
                std::fs::write(path, b"not a surface").unwrap();
            }
        }
        sweeper.surfaces = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(surfaces)
                .await
                .unwrap(),
        );
        let report = sweeper
            .sweep(Utc::now())
            .await;
        assert_eq!(report.unbound_grants, 0);
        assert_eq!(report.skipped_bindings, 1);
        assert!(
            sweeper
                .vault
                .grant(&key)
                .await
                .unwrap()
                .is_some(),
            "the grant is kept"
        );
        assert!(server.requests().is_empty(), "and not revoked");
    }

    /// A sweep told to stop, as when the node is demoted, decides no further
    /// binding: nothing is removed or revoked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sweep_told_to_stop_decides_no_further_binding() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, false).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "removed-hop", "vendor");
        store(&sweeper, &key, "unbound", 3600).await;

        let report = sweeper
            .sweep_while(Utc::now(), || false)
            .await;

        assert_eq!(report.unbound_grants, 0);
        assert!(
            sweeper
                .vault
                .grant(&key)
                .await
                .unwrap()
                .is_some()
        );
        assert!(server.requests().is_empty());
    }

    /// A sweep told to stop partway decides the bindings before it and leaves
    /// the rest: `keep_going` is asked before each binding, not once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sweep_told_to_stop_partway_leaves_the_bindings_after_it() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, false).await;
        let keys = [
            GrantKey::owner(Some("tenant-a"), "surface", "removed-hop-a", "vendor"),
            GrantKey::owner(Some("tenant-a"), "surface", "removed-hop-b", "vendor"),
        ];
        for (key, access) in keys
            .iter()
            .zip(["unbound-a", "unbound-b"])
        {
            store(&sweeper, key, access, 3600).await;
        }
        let asked = std::sync::atomic::AtomicUsize::new(0);

        // Asked once before the kept revocations, then before each binding.
        let report = sweeper
            .sweep_while(Utc::now(), || asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2)
            .await;

        assert_eq!(report.unbound_grants, 1);
        let mut kept = 0;
        for key in &keys {
            if sweeper
                .vault
                .grant(key)
                .await
                .unwrap()
                .is_some()
            {
                kept += 1;
            }
        }
        assert_eq!(kept, 1, "the binding after the stop is left");
    }

    /// The kept revocations of a provider that cannot be read wait for the
    /// next sweep; those of every other provider are decided.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unreadable_provider_holds_up_only_its_own_kept_revocations() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let mut sweeper = sweeper(&directory, &server, false).await;
        for (provider, access) in [("vendor", "readable"), ("broken", "unreadable")] {
            let key = GrantKey::owner(Some("tenant-a"), "surface", "removed-hop", provider);
            let mut removed = crate::delegation_vault::grants::tests::grant(&key, access);
            removed.id = key.record_id();
            sweeper
                .vault
                .defer_revocation(removed)
                .await
                .unwrap();
        }
        let providers = directory
            .path()
            .join("providers");
        std::fs::write(providers.join("broken.json"), b"not a provider").unwrap();
        sweeper.providers = Arc::new(
            crate::credential_providers::storage::FileSystemCredentialProviderStore::new(providers)
                .await
                .unwrap(),
        );

        let report = sweeper
            .sweep(Utc::now())
            .await;

        assert_eq!(report.deferred_revocations, 1, "{report:?}");
        revoked(&server, &["readable", "readable-refresh"]).await;
        let kept: Vec<_> = sweeper
            .vault
            .deferred_revocations()
            .await
            .unwrap()
            .into_iter()
            .map(|kept| {
                kept.grant
                    .credential_provider_id
            })
            .collect();
        assert_eq!(kept, ["broken"]);
    }

    /// The sweep reads a binding's grants under its surface's lock, so a
    /// person who reconnects while the sweep waits for the lock keeps the new
    /// grant: the sweep decides on it, not on the expired one it replaced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reconnect_while_the_sweep_waits_for_the_lock_is_kept() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, false).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        store(&sweeper, &key, "expired", -60).await;
        let held = crate::identity::handlers::surface_grants::lock_surface("surface").await;
        let sweep = tokio::spawn({
            let sweeper = sweeper.clone();
            async move {
                sweeper
                    .sweep(Utc::now())
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!sweep.is_finished(), "the sweep waits for the surface's lock");
        store(&sweeper, &key, "reconnected", 3600).await;
        drop(held);
        let report = sweep.await.unwrap();
        assert_eq!(report.expired_grants, 0, "{report:?}");
        assert_eq!(
            sweeper
                .vault
                .grant(&key)
                .await
                .unwrap()
                .expect("the reconnected grant is kept")
                .access_token,
            "reconnected"
        );
        assert!(server.requests().is_empty());
    }

    /// The pending revocations a stop left behind are tried again when the
    /// gateway starts ([`Sweeper::retry_pending`]) and by the daily sweep.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_revocations_are_tried_again_at_startup_and_by_the_sweep() {
        use crate::delegation_vault::storage::{Deferral, DeferredRevocation};
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, false).await;
        let removed = |access: &str| {
            let key = GrantKey::owner(Some("tenant-a"), "surface", access, "vendor");
            let mut grant = crate::delegation_vault::grants::tests::grant(&key, access);
            grant.id = key.record_id();
            DeferredRevocation::new(grant, Utc::now(), Deferral::Pending)
        };
        sweeper
            .vault
            .keep_revocation(&removed("at-startup"))
            .await
            .unwrap();
        assert_eq!(sweeper.retry_pending().await, 1);
        revoked(&server, &["at-startup", "at-startup-refresh"]).await;

        sweeper
            .vault
            .keep_revocation(&removed("at-the-sweep"))
            .await
            .unwrap();
        let report = sweeper
            .sweep(Utc::now())
            .await;
        assert_eq!(report.deferred_revocations, 1, "{report:?}");
        revoked(&server, &["at-startup", "at-startup-refresh", "at-the-sweep", "at-the-sweep-refresh"]).await;
        assert!(
            sweeper
                .vault
                .deferred_revocations()
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Wait, up to five seconds, until `server` has revoked `tokens`.
    async fn revoked(
        server: &RecordingServer,
        tokens: &[&str],
    ) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while server.revoked_tokens() != tokens {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{tokens:?} are revoked, not {:?}", server.revoked_tokens()));
    }

    /// The sweep removes, and revokes, a grant whose access token expired more
    /// than thirty days ago and whose refresh has failed ever since: it keeps
    /// answering that its connector is unavailable, and nobody connected
    /// again. One whose token expired a day ago is kept.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sweep_removes_a_grant_whose_refresh_has_failed_for_thirty_days() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        let now = Utc::now();
        let failing = |access: &str, expired_days: i64| {
            let mut grant = crate::delegation_vault::grants::tests::grant(&key, access);
            grant.expires_at = Some(now - chrono::Duration::days(expired_days));
            grant.record_refresh_failure(
                now - chrono::Duration::hours(1),
                crate::delegation_vault::grants::FailedRefresh::Refused,
            );
            grant
        };
        sweeper
            .vault
            .store_grant(failing("recent", 1))
            .await
            .unwrap();
        let report = sweeper.sweep(now).await;
        assert_eq!(report.failing_grants, 0, "{report:?}");
        assert!(
            sweeper
                .vault
                .grant(&key)
                .await
                .unwrap()
                .is_some()
        );

        sweeper
            .vault
            .store_grant(failing("long-failing", FAILING_GRANT_DAYS + 1))
            .await
            .unwrap();
        let report = sweeper.sweep(now).await;
        assert_eq!(report.failing_grants, 1, "{report:?}");
        assert!(
            sweeper
                .vault
                .grant(&key)
                .await
                .unwrap()
                .is_none()
        );
        revoked(&server, &["long-failing", "long-failing-refresh"]).await;
    }

    /// The sweep decides the revocations a removal deferred because it could
    /// not tell whether the vendor account's authorization was still in use:
    /// with no other grant of that account stored, the tokens are revoked and
    /// the deferral forgotten.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sweep_revokes_what_a_removal_deferred() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        let mut provider = sweeper
            .providers
            .get("vendor")
            .await
            .unwrap()
            .unwrap();
        provider.revocation_ends_authorization = true;
        sweeper
            .providers
            .update(provider)
            .await
            .unwrap();
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        let mut removed = crate::delegation_vault::grants::tests::grant(&key, "deferred");
        removed.id = key.record_id();
        removed.vendor_subject = Some("account-1".into());
        sweeper
            .vault
            .defer_revocation(removed)
            .await
            .unwrap();
        let report = sweeper
            .sweep(Utc::now())
            .await;
        assert_eq!(report.deferred_revocations, 1, "{report:?}");
        revoked(&server, &["deferred", "deferred-refresh"]).await;
        assert!(
            sweeper
                .vault
                .deferred_revocations()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_record_ids_binding_prefix_is_its_first_three_parts() {
        let key = crate::delegation_vault::grants::tests::key();
        assert_eq!(
            binding_prefix(&key.record_id()),
            Some(
                key.binding()
                    .record_id_prefix()
                    .as_str()
            )
        );
        assert_eq!(binding_prefix("grant-a"), None);
    }

    /// The sweep removes expired connects, grants whose binding is gone,
    /// grants of an earlier pepper and expired grants that cannot be
    /// refreshed, revoking each; it keeps every grant still served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sweep_removes_what_can_never_be_released_and_revokes_it() {
        let directory = tempfile::tempdir().unwrap();
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "AG_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        })
        .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        crate::identity::credential_identity::configure_pepper_bytes_for_tests(&[1; 32]);
        let server = RecordingServer::start(200).await;
        let providers = crate::credential_providers::storage::FileSystemCredentialProviderStore::new(
            directory
                .path()
                .join("providers"),
        )
        .await
        .unwrap();
        let mut provider = crate::delegation_vault::revocation::tests::provider(Some(&server.url), "none", None);
        provider.id = "vendor".into();
        provider.token_refresh_enabled = false;
        providers
            .create(provider)
            .await
            .unwrap();
        let surfaces = crate::surfaces::FileSystemAgentSurfaceStore::new(
            directory
                .path()
                .join("surfaces"),
        )
        .await
        .unwrap();
        surfaces
            .save(
                &serde_json::from_value(json!({
                    "surface_id": "surface", "name": "surface", "tenant_id": "tenant-a",
                    "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
                    "target": {"endpoint": "https://managed.example/agent"},
                    "transit": {"points": [{"id": "served", "alias": "served",
                        "target_endpoint": "https://vendor.example/mcp", "require_transit_token": true,
                        "transit_credentials": {"credential_provider_id": "vendor", "consent_mode": "external",
                            "subject": "owner"}}]}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
            crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let store = |key: GrantKey, access: &'static str, expires_in: i64| {
            let vault = vault.clone();
            async move {
                let mut grant = crate::delegation_vault::grants::tests::grant(&key, access);
                grant.expires_at = Some(Utc::now() + chrono::Duration::seconds(expires_in));
                vault
                    .store_grant(grant)
                    .await
                    .unwrap();
            }
        };
        let served = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        let earlier = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        store(earlier.clone(), "earlier", 3600).await;
        let earlier_id = earlier.record_id();
        crate::identity::credential_identity::configure_pepper_bytes_for_tests(&[2; 32]);
        store(served.clone(), "served", 3600).await;
        store(GrantKey::owner(Some("tenant-a"), "surface", "removed-hop", "vendor"), "unbound", 3600).await;
        store(GrantKey::owner(Some("tenant-a"), "deleted-surface", "served", "vendor"), "orphan", 3600).await;
        let expiring = GrantKey::caller(Some("tenant-a"), "surface", "served", "vendor", &"c".repeat(64)).unwrap();
        store(expiring, "caller-of-an-owner-binding", 3600).await;
        let now = Utc::now();
        let (stale, _) = PendingConnect::start(
            &served,
            vec![],
            "https://boris.example/cb".into(),
            now - chrono::Duration::minutes(11),
        );
        vault
            .start_connect(stale)
            .await
            .unwrap();

        let sweeper = Sweeper {
            vault: vault.clone(),
            surfaces: Arc::new(surfaces),
            providers: Arc::new(providers),
            secrets: None,
            exact_allowlist: Some(server.origin()),
        };
        let report = sweeper.sweep(now).await;
        assert_eq!(
            report,
            SweepReport {
                expired_connects: 1,
                unbound_grants: 3,
                earlier_pepper_grants: 1,
                expired_grants: 0,
                failing_grants: 0,
                unreadable_grants: 0,
                skipped_bindings: 0,
                deferred_revocations: 0,
            }
        );
        let left = vault
            .grant_ids()
            .await
            .unwrap();
        assert_eq!(left, [served.record_id()]);
        assert!(!left.contains(&earlier_id));
        tokio::time::timeout(Duration::from_secs(5), async {
            while server.revoked_tokens().len() < 8 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("every swept grant is revoked");
        assert!(
            !server
                .revoked_tokens()
                .contains(&"served".to_string())
        );

        let mut expired = crate::delegation_vault::grants::tests::grant(&served, "served");
        expired.expires_at = Some(now - chrono::Duration::seconds(1));
        vault
            .store_grant(expired)
            .await
            .unwrap();
        assert_eq!(
            sweeper
                .sweep(Utc::now())
                .await
                .expired_grants,
            1,
            "refresh is off for the provider"
        );
        assert!(
            vault
                .grant_ids()
                .await
                .unwrap()
                .is_empty()
        );
    }
}
