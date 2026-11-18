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
//! Every [`CONSENT_SWEEP_INTERVAL`] it also removes the consents past their
//! time limit ([`super::consent_age`]) that no request has needed since:
//! agent-keyed tokens, and grants by binding, which it revokes as well. A
//! consent given ahead of this gateway's clock is left where it is and
//! counted. When it starts on an active node, the sweeper logs how many
//! stored consents the gateway's own default or ceiling ends
//! ([`Sweeper::gateway_limit_impact`]).
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

use super::consent_age::{self, ConsentAge, ConsentLimits};
use super::grants::DelegatedGrant;
use super::storage::DelegationVaultStorage;
use crate::config::agent_surface::AgentSurface;
use crate::credential_providers::CredentialProvider;
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::secrets::SecretsStore;
use crate::surfaces::AgentSurfaceStore;

/// How often the sweep runs.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after startup the first sweep runs.
pub const FIRST_SWEEP_DELAY: Duration = Duration::from_secs(10 * 60);
/// How often the consents past their time limit are removed.
pub const CONSENT_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

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
    /// Agent-keyed tokens whose consent was past its time limit.
    pub ended_consent_tokens: usize,
    /// Agent-keyed tokens left as they are because their provider could not
    /// be read, so whether their consent ended is not known.
    pub skipped_consent_tokens: usize,
    /// Grants by binding whose consent was past its time limit.
    pub ended_consent_grants: usize,
    /// Agent-keyed tokens and grants by binding left as they are because
    /// their consent time lies ahead of this gateway's clock
    /// ([`ConsentAge::AheadOfClock`]).
    pub consents_ahead_of_clock: usize,
}

/// The grants the hourly pass removed at the end of their consent, each kept
/// as a pending revocation, and the providers to revoke them at.
#[derive(Default)]
struct ExpiredGrants {
    kept: Vec<super::revocation::ToRevoke>,
    providers: HashMap<String, CredentialProvider>,
}

/// The consents to one credential provider that have not ended, and how many
/// of them a consent time limit would end at once.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ConsentImpact {
    pub active_consents: usize,
    pub ending_consents: usize,
}

/// What saving `provider` with the consent time limit `tried_secs` would end
/// at once, as of `now`: counted over its consents that have not ended under
/// the limits as they are, which are its agent-keyed tokens and those of its
/// grants by binding that `surfaces` still serve. A consent the limit leaves
/// too old ends, as the hourly pass would end it, and so does every consent
/// given on the `2026-07-28` MCP path, which is bound to the provider's
/// record and ends with any save of it. A provider nobody consents to has
/// none: its tokens are service tokens. Nothing is changed.
pub async fn consent_impact(
    vault: &dyn DelegationVaultStorage,
    surfaces: Option<&dyn AgentSurfaceStore>,
    provider: &CredentialProvider,
    tried_secs: Option<u64>,
    now: DateTime<Utc>,
) -> anyhow::Result<ConsentImpact> {
    let tokens = vault.list_all().await?;
    let change = LimitChange {
        before: &|binding_secs| ConsentLimits::of(binding_secs, provider.max_consent_age_secs),
        after: &|binding_secs| ConsentLimits::of(binding_secs, tried_secs),
        ends_bound_consents: true,
    };
    let (of_tokens, of_grants) = impact_of(vault, surfaces, provider, &tokens, &change, now).await?;
    Ok(ConsentImpact {
        active_consents: of_tokens.active_consents + of_grants.active_consents,
        ending_consents: of_tokens.ending_consents + of_grants.ending_consents,
    })
}

/// A change of the limits on a provider's consents: the limits of a binding
/// that sets `binding_secs`, `before` it and `after` it.
struct LimitChange<'change> {
    before: &'change (dyn Fn(Option<u64>) -> ConsentLimits + Sync),
    after: &'change (dyn Fn(Option<u64>) -> ConsentLimits + Sync),
    /// Whether the change also ends every consent bound to the provider's
    /// record, as a save of the provider does.
    ends_bound_consents: bool,
}

/// The consents to `provider` that have not ended `before` the `change`, and
/// how many of them it ends, as of `now`: among `tokens`, its agent-keyed
/// ones, and then those of its grants by binding that `surfaces` still serve.
async fn impact_of(
    vault: &dyn DelegationVaultStorage,
    surfaces: Option<&dyn AgentSurfaceStore>,
    provider: &CredentialProvider,
    tokens: &[super::DelegationToken],
    change: &LimitChange<'_>,
    now: DateTime<Utc>,
) -> anyhow::Result<(ConsentImpact, ConsentImpact)> {
    let (mut of_tokens, mut of_grants) = (ConsentImpact::default(), ConsentImpact::default());
    if !provider.takes_consent() {
        return Ok((of_tokens, of_grants));
    }
    let (before, after) = ((change.before)(None), (change.after)(None));
    for token in tokens
        .iter()
        .filter(|token| token.credential_provider_id == provider.id)
    {
        of_tokens.count(
            !token_consent_ended(before, token, now),
            (change.ends_bound_consents
                && token
                    .consent_identity
                    .is_some())
                || token_consent_ended(after, token, now),
        );
    }
    let Some(surfaces) = surfaces.filter(|_| provider.is_external_consent()) else {
        return Ok((of_tokens, of_grants));
    };
    let mut read = HashMap::new();
    for grant in vault
        .provider_grants(&provider.id)
        .await?
    {
        if !read.contains_key(&grant.surface_id) {
            let surface = surfaces
                .get_checked(&grant.surface_id)
                .await?;
            read.insert(grant.surface_id.clone(), surface);
        }
        let Some(surface) = read
            .get(&grant.surface_id)
            .and_then(Option::as_ref)
            .filter(|surface| grant_is_served(surface, &grant, &provider.default_scopes))
        else {
            continue;
        };
        let binding_secs = crate::identity::handlers::surface_grants::binding_max_consent_age(surface, &grant);
        of_grants.count(
            !grant_consent_ended((change.before)(binding_secs), &grant, now),
            grant_consent_ended((change.after)(binding_secs), &grant, now),
        );
    }
    Ok((of_tokens, of_grants))
}

/// The stored consents that the gateway's own default or ceiling ends and the
/// providers' and bindings' own limits would keep.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GatewayLimitImpact {
    /// Agent-keyed tokens, which are deleted.
    pub tokens: usize,
    /// Grants by binding, which are deleted and revoked at the vendor.
    pub grants: usize,
}

impl ConsentImpact {
    /// Counts one consent that is `active`, and whether the limit tried ends it.
    fn count(
        &mut self,
        active: bool,
        ended_by_tried: bool,
    ) {
        if active {
            self.active_consents += 1;
            self.ending_consents += usize::from(ended_by_tried);
        }
    }
}

/// Whether the consent of the agent-keyed `token` is past `limits` at `now`,
/// for every binding.
fn token_consent_ended(
    limits: ConsentLimits,
    token: &super::DelegationToken,
    now: DateTime<Utc>,
) -> bool {
    limits.judge(token.consent_granted_at, token.consent_expires_at, now) == ConsentAge::Ended
}

/// Whether the consent of `grant` is past `limits` at `now`. A grant has one
/// binding, so one too old for its binding has ended. One given ahead of the
/// clock has not.
fn grant_consent_ended(
    limits: ConsentLimits,
    grant: &DelegatedGrant,
    now: DateTime<Utc>,
) -> bool {
    matches!(
        limits.judge(grant.created_at, grant.consent_expires_at, now),
        ConsentAge::Ended | ConsentAge::TooOldForBinding
    )
}

/// The limits on the consent of `grant`: those of the bindings of `surface`
/// that hold it and of a provider that sets `provider_secs`.
fn grant_limits(
    surface: &AgentSurface,
    grant: &DelegatedGrant,
    provider_secs: Option<u64>,
) -> ConsentLimits {
    ConsentLimits::of(crate::identity::handlers::surface_grants::binding_max_consent_age(surface, grant), provider_secs)
}

/// Whether the consent given at `granted_at`, stored with the end
/// `stored_end`, lies ahead of this gateway's clock under `limits`: the
/// hourly pass leaves such a consent where it is.
fn consent_ahead_of_clock(
    limits: ConsentLimits,
    granted_at: DateTime<Utc>,
    stored_end: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    limits.judge(granted_at, stored_end, now) == ConsentAge::AheadOfClock
}

/// Whether `grant` is one `surface` serves under the id this gateway derives
/// for it, with `default_scopes` its provider's. Any other is the daily
/// sweep's to remove.
fn grant_is_served(
    surface: &AgentSurface,
    grant: &DelegatedGrant,
    default_scopes: &[String],
) -> bool {
    grant.key().record_id() == grant.id
        && crate::identity::handlers::surface_grants::serves_grant(surface, grant, default_scopes)
}

/// One binding's grants, read under the lock of its surface, which is held
/// while they are decided on.
struct BindingGrants {
    lock: tokio::sync::OwnedMutexGuard<()>,
    /// The binding's surface, when it still exists.
    surface: Option<AgentSurface>,
    grants: Vec<DelegatedGrant>,
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
    /// node is active. A node that starts active first says how many stored
    /// consents the gateway's own limits end ([`Self::warn_of_gateway_limits`]).
    pub fn spawn(self) {
        tokio::spawn(async move {
            let mut mode_changes = crate::server::mode::subscribe_mode_changes();
            if !crate::server::mode::is_standby() {
                self.retry_pending_logged()
                    .await;
                self.warn_of_gateway_limits()
                    .await;
            }
            let first = tokio::time::Instant::now() + FIRST_SWEEP_DELAY;
            let mut interval = tokio::time::interval_at(first, SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut consent_interval = tokio::time::interval_at(first, CONSENT_SWEEP_INTERVAL);
            consent_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut listening = true;
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = consent_interval.tick() => {
                        if !crate::server::mode::is_standby() {
                            self.end_consents_logged().await;
                        }
                        continue;
                    }
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
        for ids in by_binding(ids).into_values() {
            if !keep_going() {
                break;
            }
            self.sweep_binding(ids, now, &mut providers, &mut report)
                .await;
        }
        report
    }

    async fn end_consents_logged(&self) {
        let report = self
            .end_consents_while(Utc::now(), || !crate::server::mode::is_standby())
            .await;
        if report == SweepReport::default() {
            return;
        }
        tracing::info!(
            target: "credential_delegation",
            ended_consent_tokens = report.ended_consent_tokens,
            ended_consent_grants = report.ended_consent_grants,
            skipped_consent_tokens = report.skipped_consent_tokens,
            skipped_bindings = report.skipped_bindings,
            consents_ahead_of_clock = report.consents_ahead_of_clock,
            "Removed the consents past their time limit"
        );
        if report.consents_ahead_of_clock > 0 {
            tracing::warn!(
                target: "credential_delegation",
                consents = report.consents_ahead_of_clock,
                "Stored consents were given ahead of this gateway's clock - they are kept and not used until the \
                 clocks agree; check the clocks of the gateway's nodes"
            );
        }
    }

    /// The stored consents that the gateway's own default or ceiling ends, as
    /// of `now`, and the limits of their providers and bindings would keep:
    /// those of every provider a person consents to. Nothing is changed.
    pub async fn gateway_limit_impact(
        &self,
        now: DateTime<Utc>,
    ) -> anyhow::Result<GatewayLimitImpact> {
        let tokens = self.vault.list_all().await?;
        let mut impact = GatewayLimitImpact::default();
        for provider in self.providers.list().await? {
            let change = LimitChange {
                before: &|binding_secs| {
                    ConsentLimits::without_gateway_limits(binding_secs, provider.max_consent_age_secs)
                },
                after: &|binding_secs| ConsentLimits::of(binding_secs, provider.max_consent_age_secs),
                ends_bound_consents: false,
            };
            let (of_tokens, of_grants) =
                impact_of(self.vault.as_ref(), Some(self.surfaces.as_ref()), &provider, &tokens, &change, now).await?;
            impact.tokens += of_tokens.ending_consents;
            impact.grants += of_grants.ending_consents;
        }
        Ok(impact)
    }

    /// While `[credential_policy]` sets a default or a ceiling on consents,
    /// logs how many stored consents those two settings end. They reach the
    /// consents already stored, no request previews them, and a grant revoked
    /// at the vendor cannot be given back, so the operator is told before the
    /// first pass.
    async fn warn_of_gateway_limits(&self) {
        let policy = crate::config::credential_policy::credential_policy();
        if policy
            .default_max_consent_age_secs
            .is_none()
            && policy
                .max_consent_age_ceiling_secs
                .is_none()
        {
            return;
        }
        match self
            .gateway_limit_impact(Utc::now())
            .await
        {
            Ok(impact) if impact == GatewayLimitImpact::default() => tracing::info!(
                target: "credential_delegation",
                default_max_consent_age_secs = ?policy.default_max_consent_age_secs,
                max_consent_age_ceiling_secs = ?policy.max_consent_age_ceiling_secs,
                "The gateway's consent time limits end no stored consent that its provider's own limit would keep"
            ),
            Ok(impact) => tracing::warn!(
                target: "credential_delegation",
                default_max_consent_age_secs = ?policy.default_max_consent_age_secs,
                max_consent_age_ceiling_secs = ?policy.max_consent_age_ceiling_secs,
                ending_tokens = impact.tokens,
                ending_grants = impact.grants,
                first_pass_in_secs = FIRST_SWEEP_DELAY.as_secs(),
                "The gateway's consent time limits end stored consents that their providers' own limits would \
                 keep: each the next time a request needs it, the rest at the first hourly pass, and the grants \
                 by binding among them are revoked at the vendor. To keep them, stop the gateway before that \
                 pass and raise or remove the limit"
            ),
            Err(error) => tracing::warn!(
                target: "credential_delegation",
                error = %error,
                "Failed to count the stored consents the gateway's consent time limits end"
            ),
        }
    }

    /// Remove the consents past their time limit, as of `now`.
    #[cfg(test)]
    pub async fn end_consents(
        &self,
        now: DateTime<Utc>,
    ) -> SweepReport {
        self.end_consents_while(now, || true)
            .await
    }

    /// Remove, as of `now`, the consents past their time limit that no
    /// request has needed since: agent-keyed tokens, then grants by binding,
    /// one binding at a time, stopping between them once `keep_going` says
    /// no. The grants removed are kept as pending revocations and revoked at
    /// their authorization servers in the background, so the pass never waits
    /// for a vendor. A consent given ahead of this gateway's clock is left
    /// where it is, which the report counts: a clock is wrong, and nothing is
    /// removed or revoked on that account. No grant is removed while this
    /// gateway does not derive the ids the grants stored were written under,
    /// which the daily sweep reports.
    pub async fn end_consents_while(
        &self,
        now: DateTime<Utc>,
        keep_going: impl Fn() -> bool,
    ) -> SweepReport {
        let mut report = SweepReport::default();
        let mut providers = HashMap::new();
        self.end_token_consents(now, &mut providers, &keep_going, &mut report)
            .await;
        let derives_ids = self
            .vault
            .derives_stored_grant_ids()
            .await;
        if !keep_going() || !matches!(derives_ids, Ok(true)) {
            return report;
        }
        let ids = match self.vault.grant_ids().await {
            Ok(ids) => ids,
            Err(error) => {
                tracing::warn!(
                    target: "credential_delegation",
                    error = %error,
                    "Failed to list grants to end their consents"
                );
                return report;
            }
        };
        let mut expired = ExpiredGrants::default();
        for ids in by_binding(ids).into_values() {
            if !keep_going() {
                break;
            }
            self.end_binding_consents(ids, now, &mut providers, &mut report, &mut expired)
                .await;
        }
        super::revocation::revoke_kept_expired(expired.kept, self.revoker(expired.providers));
        report
    }

    /// Remove the agent-keyed tokens whose consent is past the time limit of
    /// their provider and the gateway, as of `now`, and audit each as
    /// `consent_expired`. A binding's own shorter limit only asks its callers
    /// for consent again, so it removes nothing here. The tokens of a
    /// provider that cannot be read are left for the next pass, which
    /// `report` counts; the provider is read once.
    async fn end_token_consents(
        &self,
        now: DateTime<Utc>,
        providers: &mut HashMap<String, Option<CredentialProvider>>,
        keep_going: &impl Fn() -> bool,
        report: &mut SweepReport,
    ) {
        let tokens = match self.vault.list_all().await {
            Ok(tokens) => tokens,
            Err(error) => {
                tracing::warn!(
                    target: "credential_delegation",
                    error = %error,
                    "Failed to list delegation tokens to end their consents"
                );
                return;
            }
        };
        let mut unreadable = std::collections::HashSet::new();
        for token in tokens {
            if !keep_going() {
                break;
            }
            if unreadable.contains(&token.credential_provider_id) {
                report.skipped_consent_tokens += 1;
                continue;
            }
            let provider = match self
                .provider(&token.credential_provider_id, providers)
                .await
            {
                Ok(provider) => provider,
                Err(error) => {
                    tracing::warn!(
                        target: "credential_delegation",
                        provider_id = %token.credential_provider_id,
                        error = %error,
                        "Failed to read a provider to end its consents; its tokens wait for the next pass"
                    );
                    unreadable.insert(token.credential_provider_id);
                    report.skipped_consent_tokens += 1;
                    continue;
                }
            };
            let limits = ConsentLimits::of_provider(provider.as_ref());
            if consent_ahead_of_clock(limits, token.consent_granted_at, token.consent_expires_at, now) {
                report.consents_ahead_of_clock += 1;
                continue;
            }
            if !token_consent_ended(limits, &token, now) {
                continue;
            }
            let ended_at = limits.ends_at(token.consent_granted_at, token.consent_expires_at);
            let removed = consent_age::end_consent(self.vault.as_ref(), &token, ended_at, "sweep", None, |event| {
                event.provider_name = provider
                    .as_ref()
                    .map(|provider| provider.name.clone());
            })
            .await;
            report.ended_consent_tokens += usize::from(removed);
        }
    }

    /// Remove the grants of one binding whose consent is past the time limit
    /// of the binding, their provider and the gateway, as of `now`: each is
    /// deleted under its surface's lock while it is still the connection
    /// read, audited as `consent_expired` and kept in `expired` as a pending
    /// revocation. A grant the surface no longer serves, or written under an
    /// earlier pepper, is the daily sweep's to remove.
    async fn end_binding_consents(
        &self,
        ids: Vec<String>,
        now: DateTime<Utc>,
        providers: &mut HashMap<String, Option<CredentialProvider>>,
        report: &mut SweepReport,
        expired: &mut ExpiredGrants,
    ) {
        let Some(BindingGrants { lock, surface, grants }) = self
            .read_binding(ids, report)
            .await
        else {
            return;
        };
        let Some(surface) = surface else {
            return;
        };
        let mut ended = Vec::new();
        let mut revocation_providers = HashMap::new();
        for grant in grants {
            let Some(provider) = self
                .binding_provider(&grant, providers, report)
                .await
            else {
                return;
            };
            let default_scopes = provider
                .as_ref()
                .map_or(&[][..], |provider| &provider.default_scopes);
            if !grant_is_served(&surface, &grant, default_scopes) {
                continue;
            }
            let limits = grant_limits(
                &surface,
                &grant,
                provider
                    .as_ref()
                    .and_then(|provider| provider.max_consent_age_secs),
            );
            if consent_ahead_of_clock(limits, grant.created_at, grant.consent_expires_at, now) {
                report.consents_ahead_of_clock += 1;
                continue;
            }
            if !grant_consent_ended(limits, &grant, now) {
                continue;
            }
            let ended_at = limits.ends_for_binding_at(grant.created_at, grant.consent_expires_at);
            if let Some(provider) = provider {
                revocation_providers.insert(provider.id.clone(), provider);
            }
            ended.push((grant, ended_at));
        }
        let mut removed = Vec::with_capacity(ended.len());
        for (grant, ended_at) in ended {
            match self
                .vault
                .delete_grant_of_connection(&grant.id, grant.created_at)
                .await
            {
                Ok(Some(grant)) => {
                    let provider_name = revocation_providers
                        .get(&grant.credential_provider_id)
                        .map(|provider| provider.name.as_str());
                    consent_age::record_grant_expiry(&grant, provider_name, ended_at, "sweep");
                    removed.push(grant);
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    target: "credential_delegation",
                    grant_id = %grant.id,
                    error = %error,
                    "Failed to remove a delegated grant whose consent ended at its time limit"
                ),
            }
        }
        drop(lock);
        report.ended_consent_grants += removed.len();
        let revoker = self.revoker(revocation_providers);
        expired
            .kept
            .extend(super::revocation::keep_expired(removed, &revoker).await);
        expired
            .providers
            .extend(revoker.providers);
    }

    /// The revoker of grants the sweep removed, made with `providers`, on no
    /// management caller's behalf.
    fn revoker(
        &self,
        providers: HashMap<String, CredentialProvider>,
    ) -> super::revocation::Revoker {
        super::revocation::Revoker {
            providers,
            secrets: self.secrets.clone(),
            exact_allowlist: self.exact_allowlist.clone(),
            actor: None,
            vault: Some(self.vault.clone()),
        }
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
                Ok(None) => {
                    if let Some(kept) = &deferral.provider {
                        known.insert(id.clone(), kept.clone());
                    }
                }
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
        Some((self.revoker(known), decidable))
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

    /// The provider of `grant`, read once per sweep. `None` when it cannot be
    /// read: the binding is then left as it is, which `report` counts.
    async fn binding_provider(
        &self,
        grant: &DelegatedGrant,
        providers: &mut HashMap<String, Option<CredentialProvider>>,
        report: &mut SweepReport,
    ) -> Option<Option<CredentialProvider>> {
        match self
            .provider(&grant.credential_provider_id, providers)
            .await
        {
            Ok(provider) => Some(provider),
            Err(error) => {
                tracing::warn!(
                    target: "credential_delegation",
                    provider_id = %grant.credential_provider_id,
                    error = %error,
                    "Failed to read the provider of a binding's grants; the binding is left until the next pass"
                );
                report.skipped_bindings += 1;
                None
            }
        }
    }

    /// Read the grants of one binding under its surface's lock. One grant is
    /// read first to learn the surface. `None` when no grant of the binding
    /// can be read, or its surface cannot, which `report` counts.
    async fn read_binding(
        &self,
        ids: Vec<String>,
        report: &mut SweepReport,
    ) -> Option<BindingGrants> {
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
            return None;
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
                return None;
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
        Some(BindingGrants { lock, surface, grants })
    }

    /// Sweep the grants of one binding, read and decided on under its
    /// surface's lock.
    async fn sweep_binding(
        &self,
        ids: Vec<String>,
        now: DateTime<Utc>,
        providers: &mut HashMap<String, Option<CredentialProvider>>,
        report: &mut SweepReport,
    ) {
        let Some(BindingGrants { lock, surface, grants }) = self
            .read_binding(ids, report)
            .await
        else {
            return;
        };
        let mut removals = Vec::new();
        let mut revocation_providers = HashMap::new();
        for grant in grants {
            let Some(provider) = self
                .binding_provider(&grant, providers, report)
                .await
            else {
                return;
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
        let revoker = self.revoker(revocation_providers);
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

/// The record ids of grants, by the binding each is kept for.
fn by_binding(ids: Vec<String>) -> BTreeMap<String, Vec<String>> {
    let mut bindings: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in ids {
        if let Some(prefix) = binding_prefix(&id) {
            bindings
                .entry(prefix.to_string())
                .or_default()
                .push(id);
        }
    }
    bindings
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
    use crate::delegation_vault::consent_age::stamp;
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
                .defer_revocation(removed, None)
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
            .defer_revocation(removed, None)
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
                ended_consent_tokens: 0,
                skipped_consent_tokens: 0,
                ended_consent_grants: 0,
                consents_ahead_of_clock: 0,
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

    async fn keep_pending_of_a_deleted_provider(
        sweeper: &Sweeper,
        server: &RecordingServer,
        snapshot: bool,
    ) {
        let key = GrantKey::owner(Some("tenant-a"), "surface", "hop", "gone");
        let mut provider = crate::delegation_vault::revocation::tests::provider(Some(&server.url), "none", None);
        provider.id = "gone".into();
        let mut grant = crate::delegation_vault::grants::tests::grant(&key, "orphan");
        grant.id = key.record_id();
        grant.refresh_token = None;
        let record = crate::delegation_vault::storage::DeferredRevocation::new(
            grant,
            Utc::now(),
            crate::delegation_vault::storage::Deferral::Pending,
        )
        .with_provider(snapshot.then_some(provider));
        sweeper
            .vault
            .keep_revocation(&record)
            .await
            .unwrap();
    }

    /// A revocation kept for a provider that has since been deleted is decided
    /// with the provider it kept, not forgotten unrevoked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sweep_revokes_a_kept_revocation_of_a_deleted_provider_with_the_provider_it_kept() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, false).await;
        keep_pending_of_a_deleted_provider(&sweeper, &server, true).await;

        let report = sweeper
            .sweep(Utc::now())
            .await;

        assert_eq!(report.deferred_revocations, 1);
        assert_eq!(server.revoked_tokens(), ["orphan"]);
        assert!(
            sweeper
                .vault
                .deferred_revocations()
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Without a provider to decide it with, a kept revocation of a deleted
    /// provider is forgotten, as before providers were kept with it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_sweep_forgets_a_kept_revocation_of_a_deleted_provider_that_kept_none() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, false).await;
        keep_pending_of_a_deleted_provider(&sweeper, &server, false).await;

        let report = sweeper
            .sweep(Utc::now())
            .await;

        assert_eq!(report.deferred_revocations, 1);
        assert!(server.requests().is_empty());
        assert!(
            sweeper
                .vault
                .deferred_revocations()
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Set the consent time limit of the sweeper's provider `vendor`.
    async fn limit_provider(
        sweeper: &Sweeper,
        secs: u64,
    ) {
        let mut provider = sweeper
            .providers
            .get("vendor")
            .await
            .unwrap()
            .unwrap();
        provider.max_consent_age_secs = Some(secs);
        sweeper
            .providers
            .update(provider)
            .await
            .unwrap();
    }

    /// Set the consent time limit of the binding the sweeper's surface serves.
    async fn limit_binding(
        sweeper: &Sweeper,
        secs: u64,
    ) {
        let surface = sweeper
            .surfaces
            .get_checked("surface")
            .await
            .unwrap()
            .unwrap();
        let mut surface = serde_json::to_value(surface).unwrap();
        surface["transit"]["points"][0]["transit_credentials"]["max_consent_age_secs"] = json!(secs);
        sweeper
            .surfaces
            .save(&serde_json::from_value(surface).unwrap())
            .await
            .unwrap();
    }

    /// The `consent_expired` records among `events`, as the token or grant
    /// id and the detail of each.
    fn expiries(events: &[crate::delegation_vault::audit::DelegationAuditEvent]) -> Vec<(String, String)> {
        events
            .iter()
            .filter(|event| {
                matches!(event.event, crate::delegation_vault::audit::DelegationAuditAction::ConsentExpired)
            })
            .map(|event| {
                (
                    event
                        .token_id
                        .clone()
                        .unwrap(),
                    event.detail.clone().unwrap(),
                )
            })
            .collect()
    }

    /// The hourly pass removes a grant whose consent is past its provider's
    /// time limit though no request needed it, audits it as `consent_expired`
    /// found by the sweep, and revokes it. A grant within the limit is kept,
    /// and so is one the surface no longer serves, which the daily sweep
    /// removes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_hourly_pass_removes_and_revokes_a_grant_whose_consent_ended() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        limit_provider(&sweeper, 3_600).await;
        let now = Utc::now();
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        let connected = |key: &GrantKey, access: &str, minutes_ago: i64| {
            let mut grant = crate::delegation_vault::grants::tests::grant(key, access);
            grant.created_at = now - chrono::Duration::minutes(minutes_ago);
            grant.consent_expires_at = Some(grant.created_at + chrono::Duration::hours(1));
            grant
        };
        let unbound = GrantKey::owner(Some("tenant-a"), "surface", "removed-hop", "vendor");
        for grant in [connected(&key, "current", 30), connected(&unbound, "unbound", 120)] {
            sweeper
                .vault
                .store_grant(grant)
                .await
                .unwrap();
        }

        let (report, events) = crate::audit::producer::capture(sweeper.end_consents(now)).await;
        assert_eq!(report, SweepReport::default(), "nothing has ended that the surface serves");
        assert!(expiries(&events).is_empty());
        assert!(server.requests().is_empty());

        let ended = connected(&key, "ended", 120);
        sweeper
            .vault
            .store_grant(ended.clone())
            .await
            .unwrap();
        let (report, events) = crate::audit::producer::capture(sweeper.end_consents(now)).await;

        assert_eq!(report.ended_consent_grants, 1, "{report:?}");
        assert_eq!(report.ended_consent_tokens, 0, "{report:?}");
        assert!(
            sweeper
                .vault
                .grant(&key)
                .await
                .unwrap()
                .is_none(),
            "the grant is removed"
        );
        assert_eq!(
            expiries(&events),
            vec![(
                key.record_id(),
                format!(
                    "consent_granted_at:{},consent_expired_at:{},source:sweep",
                    stamp(ended.created_at),
                    stamp(ended.created_at + chrono::Duration::hours(1))
                )
            )]
        );
        revoked(&server, &["ended", "ended-refresh"]).await;
        assert!(
            sweeper
                .vault
                .grant(&unbound)
                .await
                .unwrap()
                .is_some(),
            "a grant the surface no longer serves is the daily sweep's"
        );
    }

    /// A binding's own limit, set after a grant was connected, ends it at
    /// that limit, which the record names as its end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_hourly_pass_ends_a_grant_older_than_its_bindings_limit() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        let now = Utc::now();
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        let mut grant = crate::delegation_vault::grants::tests::grant(&key, "older");
        grant.created_at = now - chrono::Duration::minutes(20);
        sweeper
            .vault
            .store_grant(grant.clone())
            .await
            .unwrap();

        let report = sweeper
            .end_consents(now)
            .await;
        assert_eq!(report, SweepReport::default(), "no limit applies yet");

        limit_binding(&sweeper, 600).await;
        let (report, events) = crate::audit::producer::capture(sweeper.end_consents(now)).await;

        assert_eq!(report.ended_consent_grants, 1, "{report:?}");
        assert_eq!(
            expiries(&events),
            vec![(
                key.record_id(),
                format!(
                    "consent_granted_at:{},consent_expired_at:{},source:sweep",
                    stamp(grant.created_at),
                    stamp(grant.created_at + chrono::Duration::minutes(10))
                )
            )]
        );
        revoked(&server, &["older", "older-refresh"]).await;
    }

    /// A tried limit is counted against the consents that have not ended: the
    /// provider's agent-keyed tokens, and its grants their surface serves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tried_limit_counts_the_active_consents_the_hourly_pass_would_end() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        limit_provider(&sweeper, 6 * 3_600).await;
        let now = Utc::now();
        for token in [
            token("recent", "vendor", now, 30, false),
            token("older", "vendor", now, 180, false),
            token("ended", "vendor", now, 420, false),
            token("another-provider", "elsewhere", now, 180, false),
        ] {
            sweeper
                .vault
                .store(token)
                .await
                .unwrap();
        }
        let connected = |hop: &str| {
            let key = GrantKey::owner(Some("tenant-a"), "surface", hop, "vendor");
            let mut grant = crate::delegation_vault::grants::tests::grant(&key, hop);
            grant.created_at = now - chrono::Duration::hours(3);
            grant.consent_expires_at = Some(grant.created_at + chrono::Duration::hours(6));
            grant
        };
        for grant in [connected("served"), connected("removed-hop")] {
            sweeper
                .vault
                .store_grant(grant)
                .await
                .unwrap();
        }
        let provider = sweeper
            .providers
            .get("vendor")
            .await
            .unwrap()
            .unwrap();
        let impact = |tried_secs: Option<u64>| {
            consent_impact(sweeper.vault.as_ref(), Some(sweeper.surfaces.as_ref()), &provider, tried_secs, now)
        };

        let two_hours = impact(Some(2 * 3_600))
            .await
            .unwrap();
        let five_hours = impact(Some(5 * 3_600))
            .await
            .unwrap();
        let unlimited = impact(None).await.unwrap();
        limit_binding(&sweeper, 3_600).await;
        let past_its_binding = impact(Some(2 * 3_600))
            .await
            .unwrap();

        assert_eq!(
            two_hours,
            ConsentImpact {
                active_consents: 3,
                ending_consents: 2
            },
            "the token and the served grant given three hours ago end"
        );
        assert_eq!(
            five_hours,
            ConsentImpact {
                active_consents: 3,
                ending_consents: 0
            }
        );
        assert_eq!(
            unlimited,
            ConsentImpact {
                active_consents: 3,
                ending_consents: 0
            }
        );
        assert_eq!(
            past_its_binding,
            ConsentImpact {
                active_consents: 2,
                ending_consents: 1
            },
            "a grant older than its binding allows has already ended"
        );
        assert_eq!(
            stored_token_ids(&sweeper)
                .await
                .len(),
            4,
            "counting removes nothing"
        );
    }

    /// A provider nobody consents to has no consents to count.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_nobody_consents_to_has_no_consents_to_end() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        let now = Utc::now();
        sweeper
            .vault
            .store(token("service", "service-account", now, 600, false))
            .await
            .unwrap();
        let provider = crate::delegation_vault::test_support::provider("service-account", None);

        let impact = consent_impact(sweeper.vault.as_ref(), None, &provider, Some(3_600), now)
            .await
            .unwrap();

        assert_eq!(impact, ConsentImpact::default(), "its token is a service token, which nobody consented to");
    }

    /// An agent-keyed token with the consent given `minutes_ago` to
    /// `credential_provider_id`, ending an hour after it when `with_end`.
    fn token(
        id: &str,
        credential_provider_id: &str,
        now: DateTime<Utc>,
        minutes_ago: i64,
        with_end: bool,
    ) -> crate::delegation_vault::DelegationToken {
        let mut token = crate::delegation_vault::tests::make_token(Some(3_600), true);
        token.id = id.to_string();
        token.user_identity_hash = format!("sha256:{id}");
        token.credential_provider_id = credential_provider_id.to_string();
        token.access_token = format!("{id}-access");
        token.consent_granted_at = now - chrono::Duration::minutes(minutes_ago);
        token.consent_expires_at = with_end.then(|| token.consent_granted_at + chrono::Duration::hours(1));
        token
    }

    async fn stored_token_ids(sweeper: &Sweeper) -> Vec<String> {
        let mut ids: Vec<String> = sweeper
            .vault
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .map(|token| token.id)
            .collect();
        ids.sort();
        ids
    }

    /// The hourly pass removes an agent-keyed token whose consent is past
    /// the end stored with it, or older than the limit its provider sets
    /// now, and audits each as `consent_expired` found by the sweep. It keeps
    /// a consent within its limit, a service token, which nobody consented
    /// to, and a token of a deleted provider that has no stored end. No
    /// vendor is called.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_hourly_pass_removes_agent_keyed_tokens_whose_consent_ended() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        limit_provider(&sweeper, 3_600).await;
        let mut service = crate::delegation_vault::revocation::tests::provider(None, "none", None);
        service.id = "service".into();
        service.provider_id = "service-0123456789ab".into();
        service.provider_type = crate::credential_providers::CredentialProviderType::OAuth2ClientCredentials;
        sweeper
            .providers
            .create(service)
            .await
            .unwrap();
        let now = Utc::now();
        let ended = token("ended", "vendor", now, 120, true);
        let stored = [
            ended.clone(),
            token("current", "vendor", now, 30, true),
            token("limited-since", "vendor", now, 120, false),
            token("service", "service", now, 60 * 24 * 400, false),
            token("gone-ended", "gone", now, 120, true),
            token("gone-unlimited", "gone", now, 120, false),
        ];
        for token in stored {
            sweeper
                .vault
                .store(token)
                .await
                .unwrap();
        }

        let (report, events) = crate::audit::producer::capture(sweeper.end_consents(now)).await;

        assert_eq!(report.ended_consent_tokens, 3, "{report:?}");
        assert_eq!(stored_token_ids(&sweeper).await, vec!["current", "gone-unlimited", "service"]);
        let mut expired = expiries(&events);
        expired.sort();
        let granted = stamp(ended.consent_granted_at);
        let end = stamp(ended.consent_granted_at + chrono::Duration::hours(1));
        assert_eq!(
            expired,
            ["ended", "gone-ended", "limited-since"].map(|id| (
                id.to_string(),
                format!("consent_granted_at:{granted},consent_expired_at:{end},source:sweep")
            ))
        );
        let record = events
            .iter()
            .find(|event| event.token_id.as_deref() == Some("ended"))
            .unwrap();
        assert_eq!(record.agent_did.as_deref(), Some(ended.agent_did.as_str()));
        assert_eq!(
            record
                .user_identity_hash
                .as_deref(),
            Some("sha256:ended")
        );
        assert_eq!(record.provider_id.as_deref(), Some("vendor"));
        assert_eq!(
            record
                .provider_name
                .as_deref(),
            Some("Vendor")
        );
        assert!(server.requests().is_empty(), "an agent-keyed token is revoked at no vendor");
    }

    /// A consent time further ahead of this gateway's clock than clocks may
    /// differ says a clock is wrong, not that the consent ended. The hourly
    /// pass keeps such a token and such a grant, counts them, records no
    /// expiry and revokes nothing at the vendor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_hourly_pass_keeps_a_consent_given_ahead_of_the_clock() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        limit_provider(&sweeper, 3_600).await;
        let now = Utc::now();
        sweeper
            .vault
            .store(token("ahead", "vendor", now, -10, true))
            .await
            .unwrap();
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        let mut grant = crate::delegation_vault::grants::tests::grant(&key, "ahead");
        grant.created_at = now + chrono::Duration::minutes(10);
        grant.consent_expires_at = Some(grant.created_at + chrono::Duration::hours(1));
        sweeper
            .vault
            .store_grant(grant)
            .await
            .unwrap();

        let (report, events) = crate::audit::producer::capture(sweeper.end_consents(now)).await;

        assert_eq!(
            report,
            SweepReport {
                consents_ahead_of_clock: 2,
                ..SweepReport::default()
            }
        );
        assert_eq!(stored_token_ids(&sweeper).await, vec!["ahead"]);
        assert!(
            sweeper
                .vault
                .grant(&key)
                .await
                .unwrap()
                .is_some(),
            "the grant is kept"
        );
        assert!(expiries(&events).is_empty(), "{events:?}");
        assert!(server.requests().is_empty(), "nothing is revoked at the vendor");
    }

    /// The gateway's own default or ceiling is counted against the stored
    /// consents it alone ends. A consent that the end stored with it or its
    /// provider's own limit already ends is not the gateway's to end, and
    /// neither is a grant its surface no longer serves or a token of a
    /// provider that is gone. Counting changes nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_gateways_own_limit_counts_the_stored_consents_it_alone_ends() {
        use crate::config::credential_policy::{CredentialPolicyConfig, TEST_CREDENTIAL_POLICY};
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        let now = Utc::now();
        for token in [
            token("recent", "vendor", now, 30, false),
            token("older", "vendor", now, 180, false),
            token("ended", "vendor", now, 180, true),
            token("another-provider", "elsewhere", now, 180, false),
        ] {
            sweeper
                .vault
                .store(token)
                .await
                .unwrap();
        }
        for hop in ["served", "removed-hop"] {
            let key = GrantKey::owner(Some("tenant-a"), "surface", hop, "vendor");
            let mut grant = crate::delegation_vault::grants::tests::grant(&key, hop);
            grant.created_at = now - chrono::Duration::hours(3);
            sweeper
                .vault
                .store_grant(grant)
                .await
                .unwrap();
        }
        let under = |default: Option<u64>, ceiling: Option<u64>| {
            let policy: &'static CredentialPolicyConfig = Box::leak(Box::new(CredentialPolicyConfig {
                default_max_consent_age_secs: default,
                max_consent_age_ceiling_secs: ceiling,
                ..CredentialPolicyConfig::default()
            }));
            TEST_CREDENTIAL_POLICY.scope(policy, sweeper.gateway_limit_impact(now))
        };
        let both = GatewayLimitImpact { tokens: 1, grants: 1 };

        assert_eq!(
            under(None, None)
                .await
                .unwrap(),
            GatewayLimitImpact::default(),
            "no gateway limit"
        );
        assert_eq!(
            under(None, Some(2 * 3_600))
                .await
                .unwrap(),
            both,
            "a ceiling is also the limit of a provider that sets none"
        );
        assert_eq!(
            under(Some(2 * 3_600), None)
                .await
                .unwrap(),
            both
        );
        assert_eq!(
            under(Some(4 * 3_600), None)
                .await
                .unwrap(),
            GatewayLimitImpact::default(),
            "a limit longer than the oldest consent"
        );
        limit_provider(&sweeper, 3_600).await;
        assert_eq!(
            under(None, Some(2 * 3_600))
                .await
                .unwrap(),
            GatewayLimitImpact::default(),
            "the provider's own shorter limit already ends them"
        );
        assert_eq!(stored_token_ids(&sweeper).await, vec!["another-provider", "ended", "older", "recent"]);
        assert!(server.requests().is_empty(), "nothing is revoked");
    }

    /// A pass told to stop, as when the node is demoted, removes nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_consent_pass_told_to_stop_removes_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        limit_provider(&sweeper, 3_600).await;
        let now = Utc::now();
        sweeper
            .vault
            .store(token("ended", "vendor", now, 120, true))
            .await
            .unwrap();
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        let mut grant = crate::delegation_vault::grants::tests::grant(&key, "ended");
        grant.created_at = now - chrono::Duration::hours(2);
        sweeper
            .vault
            .store_grant(grant)
            .await
            .unwrap();

        let report = sweeper
            .end_consents_while(now, || false)
            .await;

        assert_eq!(report, SweepReport::default());
        assert_eq!(stored_token_ids(&sweeper).await, vec!["ended"]);
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

    /// A `2026-07-28` consent is bound to its provider's record, so any save
    /// of the provider ends it: a tried limit counts it as ending, however
    /// long the limit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tried_limit_counts_a_consent_bound_to_the_providers_record_as_ending() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        let now = Utc::now();
        let mut bound = token("bound", "vendor", now, 30, false);
        bound.consent_identity = Some(
            serde_json::from_value(json!({
                "principal": "verified-user", "provider_digest": ([1; 32]), "strategy_digest": ([2; 32])
            }))
            .unwrap(),
        );
        for token in [bound, token("unbound", "vendor", now, 30, false)] {
            sweeper
                .vault
                .store(token)
                .await
                .unwrap();
        }
        let provider = sweeper
            .providers
            .get("vendor")
            .await
            .unwrap()
            .unwrap();

        let impact = consent_impact(sweeper.vault.as_ref(), None, &provider, Some(30 * 86_400), now)
            .await
            .unwrap();

        assert_eq!(
            impact,
            ConsentImpact {
                active_consents: 2,
                ending_consents: 1
            }
        );
    }

    /// The end of a consent removes only the consent that was judged. One
    /// given again since is kept, though the vendor handed back the same
    /// access token, and no expiry is recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_end_of_a_consent_keeps_a_consent_given_again_since() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        let now = Utc::now();
        let judged = sweeper
            .vault
            .store(token("again", "vendor", now, 120, true))
            .await
            .unwrap();
        let mut given_again = judged.clone();
        given_again.consent_granted_at = now;
        given_again.consent_expires_at = Some(now + chrono::Duration::hours(1));
        sweeper
            .vault
            .store(given_again)
            .await
            .unwrap();

        let (removed, events) = crate::audit::producer::capture(consent_age::end_consent(
            sweeper.vault.as_ref(),
            &judged,
            judged.consent_expires_at,
            "sweep",
            None,
            |_| {},
        ))
        .await;

        assert!(!removed);
        assert_eq!(stored_token_ids(&sweeper).await, vec!["again"]);
        assert!(expiries(&events).is_empty());
    }

    /// A consent refreshed since it was read has ended all the same, and is
    /// removed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_end_of_a_consent_removes_a_token_refreshed_since() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        let now = Utc::now();
        let judged = sweeper
            .vault
            .store(token("refreshed", "vendor", now, 120, true))
            .await
            .unwrap();
        let mut refreshed = judged.clone();
        refreshed.access_token = "refreshed-since".into();
        sweeper
            .vault
            .update(refreshed)
            .await
            .unwrap();

        let removed =
            consent_age::end_consent(sweeper.vault.as_ref(), &judged, judged.consent_expires_at, "sweep", None, |_| {})
                .await;

        assert!(removed);
        assert!(
            stored_token_ids(&sweeper)
                .await
                .is_empty()
        );
    }

    /// A consent that ended is logged as that, never as a token its Target
    /// refused.
    #[tokio::test]
    async fn the_end_of_a_consent_is_not_logged_as_a_token_its_target_refused() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let sweeper = sweeper(&directory, &server, true).await;
        let ended = sweeper
            .vault
            .store(token("ended", "vendor", Utc::now(), 120, true))
            .await
            .unwrap();

        let removed =
            consent_age::end_consent(sweeper.vault.as_ref(), &ended, ended.consent_expires_at, "sweep", None, |_| {})
                .await;

        assert!(removed);
        let text = logs.text();
        assert!(text.contains("Consent ended at its time limit"), "{text}");
        assert!(!text.contains("Target refused"), "{text}");
    }

    /// A provider that cannot be read holds up only its own tokens: the pass
    /// goes on to the tokens of every provider it can read, and counts the
    /// ones it left.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_hourly_pass_goes_on_past_a_provider_it_cannot_read() {
        let directory = tempfile::tempdir().unwrap();
        let server = RecordingServer::start(200).await;
        let mut sweeper = sweeper(&directory, &server, true).await;
        limit_provider(&sweeper, 3_600).await;
        let providers = directory
            .path()
            .join("providers");
        std::fs::write(providers.join("broken.json"), b"not a provider").unwrap();
        sweeper.providers = Arc::new(
            crate::credential_providers::storage::FileSystemCredentialProviderStore::new(providers)
                .await
                .unwrap(),
        );
        let now = Utc::now();
        let broken = ["broken-1", "broken-2", "broken-3", "broken-4"];
        let readable = ["ended-1", "ended-2", "ended-3", "ended-4"];
        for (ids, provider) in [(broken, "broken"), (readable, "vendor")] {
            for id in ids {
                sweeper
                    .vault
                    .store(token(id, provider, now, 120, true))
                    .await
                    .unwrap();
            }
        }

        let report = sweeper
            .end_consents(now)
            .await;

        assert_eq!(stored_token_ids(&sweeper).await, broken);
        assert_eq!(report.ended_consent_tokens, 4, "{report:?}");
        assert_eq!(report.skipped_consent_tokens, 4, "{report:?}");
    }

    /// The hourly pass does not wait for a vendor to answer a revocation: the
    /// grant is removed, kept as a pending revocation, and revoked once the
    /// vendor answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_hourly_pass_does_not_wait_for_a_vendor_to_answer_a_revocation() {
        use crate::delegation_vault::revocation::tests::Answer;
        let directory = tempfile::tempdir().unwrap();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let server = RecordingServer::start_answering(vec![Answer::status(200).held(&gate)]).await;
        let sweeper = sweeper(&directory, &server, true).await;
        limit_provider(&sweeper, 3_600).await;
        let now = Utc::now();
        let key = GrantKey::owner(Some("tenant-a"), "surface", "served", "vendor");
        let mut grant = crate::delegation_vault::grants::tests::grant(&key, "ended");
        grant.created_at = now - chrono::Duration::hours(2);
        sweeper
            .vault
            .store_grant(grant)
            .await
            .unwrap();

        let report = tokio::time::timeout(Duration::from_secs(10), sweeper.end_consents(now))
            .await
            .expect("the pass ends while the vendor has not answered");

        assert_eq!(report.ended_consent_grants, 1, "{report:?}");
        assert!(
            sweeper
                .vault
                .grant(&key)
                .await
                .unwrap()
                .is_none()
        );
        let kept: Vec<_> = sweeper
            .vault
            .deferred_revocations()
            .await
            .unwrap()
            .into_iter()
            .map(|kept| kept.grant.id)
            .collect();
        assert_eq!(kept, [key.record_id()], "the revocation is kept until the vendor answers");
        gate.add_permits(8);
        revoked(&server, &["ended", "ended-refresh"]).await;
    }
}
