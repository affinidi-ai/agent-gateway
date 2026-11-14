//! RFC 7009 revocation of a grant by binding at its authorization server.
//!
//! The grant's refresh token is revoked, with `token_type_hint=refresh_token`,
//! then its access token, with `token_type_hint=access_token`, so a server that
//! does not cascade the first revocation still ends the second; a grant with no
//! refresh token has only its access token revoked. A server that does not
//! revoke access tokens answers that request with an error, which changes
//! nothing else. The client authenticates as its provider's
//! `token_endpoint_auth_method` says. The calls go through the pinned, Strict,
//! `https`-only egress client, with a short timeout, and no response body is
//! ever read, echoed or logged. Revocation is best effort: its outcome is
//! returned, logged and audited with the actor that caused it, and a failed
//! revocation never keeps a grant that is being removed. One grant's
//! revocation ends within [`VENDOR_REVOCATION_TIMEOUT`].
//! [`delete_then_revoke`] deletes many grants first, then revokes what the
//! vault deleted, at most [`REVOCATION_CONCURRENCY`] at a time, both on one
//! task of its own, so the change that removed them never waits on a vendor,
//! and a change dropped part way never leaves a deleted grant unrevoked. Each
//! removed grant is kept as a pending revocation until its revocation reached
//! the vendor, so one in flight when the gateway stops, or that could not
//! reach the vendor, is tried again ([`revoke_pending`]).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures::StreamExt as _;

use super::audit::AuditCallerContext;
use super::grants::{DelegatedGrant, GrantBinding};
use super::storage::{Deferral, DeferredRevocation, DelegationVaultStorage};
use crate::credential_providers::{CredentialProvider, TokenEndpointAuthMethod};
use crate::secrets::SecretsStore;

const REVOCATION_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest the revocation of one grant at its vendor may take, its client
/// credential, the endpoint's resolution and both requests included; one
/// that takes longer is `unreachable`.
const VENDOR_REVOCATION_TIMEOUT: Duration = Duration::from_secs(30);

/// The most grants [`revoke_removed`] revokes at once.
pub const REVOCATION_CONCURRENCY: usize = 8;

/// What became of one revocation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationOutcome {
    /// The authorization server answered 2xx.
    Revoked,
    /// The authorization server answered another status.
    Refused,
    /// The authorization server answered 429 or 5xx: it has not decided, so
    /// the revocation is tried again. Audited as `refused`.
    RefusedForNow,
    /// The endpoint could not be reached, or the egress policy refused it.
    Unreachable,
    /// The provider names no revocation endpoint.
    NotSupported,
    /// The client's secret could not be resolved in the provider's tenant.
    ClientUnavailable,
    /// Revocation was not tried: the grant was removed without it, for the
    /// [`GrantRevocation::reason`] given.
    Skipped,
}

impl RevocationOutcome {
    /// The outcome's name in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Refused | Self::RefusedForNow => "refused",
            Self::Unreachable => "unreachable",
            Self::NotSupported => "not_supported",
            Self::ClientUnavailable => "client_unavailable",
            Self::Skipped => "skipped",
        }
    }
}

/// Why a removed grant was not revoked: no secrets store is configured, so a
/// confidential client cannot authenticate.
pub const SKIPPED_NO_SECRETS_STORE: &str = "no_secrets_store";
/// Why a removed grant was not revoked: its provider no longer exists.
pub const SKIPPED_PROVIDER_MISSING: &str = "provider_missing";
/// Why a removed grant was not revoked: an operator purged it without reading it.
pub const SKIPPED_PURGED: &str = "purged";
/// Why a removed grant was not revoked: its provider's revocation ends the
/// whole authorization of the vendor account that consented, which another
/// grant of that account still uses.
pub const SKIPPED_AUTHORIZATION_IN_USE: &str = "authorization_in_use";
/// Why a removed grant was not revoked yet: whether another grant of its
/// vendor account still uses the authorization could not be told, so the
/// daily sweep decides ([`revoke_deferred`]).
pub const SKIPPED_DEFERRED: &str = "deferred";

/// What the audit record of tokens that no grant keeps adds to its `detail`.
const UNKEPT_TOKENS: &str = "unkept_tokens";

/// How many days a deferred revocation waits for the vault to tell whether
/// the authorization is in use before it is revoked all the same.
pub const DEFERRED_REVOCATION_DAYS: i64 = 30;

/// What revoking one grant came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantRevocation {
    /// The refresh token's outcome, or the access token's for a grant with no
    /// refresh token.
    pub outcome: RevocationOutcome,
    /// The access token's outcome, for a grant whose refresh token was revoked
    /// first.
    pub access_token: Option<RevocationOutcome>,
    /// Why revocation was skipped, for [`RevocationOutcome::Skipped`].
    pub reason: Option<&'static str>,
}

impl GrantRevocation {
    fn failed(outcome: RevocationOutcome) -> Self {
        Self {
            outcome,
            access_token: None,
            reason: None,
        }
    }

    /// Whether a token could not be revoked for a reason that may pass: the
    /// endpoint was unreachable or answered 429 or 5xx.
    fn should_retry(&self) -> bool {
        let passing = |outcome: RevocationOutcome| {
            matches!(outcome, RevocationOutcome::Unreachable | RevocationOutcome::RefusedForNow)
        };
        passing(self.outcome)
            || self
                .access_token
                .is_some_and(passing)
    }

    fn skipped(reason: &'static str) -> Self {
        Self {
            outcome: RevocationOutcome::Skipped,
            access_token: None,
            reason: Some(reason),
        }
    }

    /// The audit record's `detail`: `vendor_revocation:<outcome>`, then
    /// `,access_token:<outcome>` when the access token was revoked as well, or
    /// `,reason:<reason>` when revocation was skipped.
    pub fn detail(self) -> String {
        let mut detail = format!("vendor_revocation:{}", self.outcome.as_str());
        if let Some(access_token) = self.access_token {
            detail.push_str(&format!(",access_token:{}", access_token.as_str()));
        }
        if let Some(reason) = self.reason {
            detail.push_str(&format!(",reason:{reason}"));
        }
        detail
    }
}

/// Revoke `grant` at `provider`'s revocation endpoint, then log and audit the
/// outcome, naming `actor`, the management caller whose change removed it.
/// Without a secrets store, a client that authenticates with a secret is not
/// revoked: the outcome is `skipped`, with the reason `no_secrets_store`.
#[cfg(test)]
pub async fn revoke_grant(
    provider: &CredentialProvider,
    grant: &DelegatedGrant,
    secrets: Option<&Arc<dyn SecretsStore>>,
    exact_allowlist: Option<&str>,
    actor: Option<&AuditCallerContext>,
) -> GrantRevocation {
    let revocation = revoke(provider, grant, secrets, exact_allowlist).await;
    record_revocation(&provider.id, Some(&provider.name), grant, revocation, actor, &[]);
    revocation
}

/// Log and audit what became of `grant`'s revocation, the audit record's
/// `detail` ending with each of `notes`.
fn record_revocation(
    credential_provider_id: &str,
    provider_name: Option<&str>,
    grant: &DelegatedGrant,
    revocation: GrantRevocation,
    actor: Option<&AuditCallerContext>,
    notes: &[&'static str],
) {
    let outcome = revocation.outcome.as_str();
    let access_token = revocation
        .access_token
        .map(RevocationOutcome::as_str);
    match revocation.outcome {
        RevocationOutcome::Revoked => tracing::info!(
            target: "credential_delegation",
            surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
            grant_id = %grant.id,
            credential_provider_id = %credential_provider_id,
            outcome,
            access_token,
            "Revoked a delegated grant at its authorization server"
        ),
        RevocationOutcome::NotSupported => tracing::info!(
            target: "credential_delegation",
            surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
            grant_id = %grant.id,
            credential_provider_id = %credential_provider_id,
            outcome,
            "A delegated grant's provider names no revocation endpoint, so the grant is removed without revoking it"
        ),
        RevocationOutcome::Skipped if revocation.reason == Some(SKIPPED_DEFERRED) => tracing::info!(
            target: "credential_delegation",
            surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
            grant_id = %grant.id,
            credential_provider_id = %credential_provider_id,
            outcome,
            reason = revocation.reason,
            "A removed delegated grant is revoked by the daily sweep, once the vault can tell whether its \
             authorization is in use"
        ),
        RevocationOutcome::Skipped => tracing::warn!(
            target: "credential_delegation",
            surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
            grant_id = %grant.id,
            credential_provider_id = %credential_provider_id,
            outcome,
            reason = revocation.reason,
            "A delegated grant is removed without revoking it at its authorization server"
        ),
        RevocationOutcome::Refused
        | RevocationOutcome::RefusedForNow
        | RevocationOutcome::Unreachable
        | RevocationOutcome::ClientUnavailable => {
            tracing::warn!(
                target: "credential_delegation",
                surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
                grant_id = %grant.id,
                credential_provider_id = %credential_provider_id,
                outcome,
                "A delegated grant could not be revoked at its authorization server; it is removed all the same"
            )
        }
    }
    super::audit::emit("token_revoked", || {
        let mut event = super::audit::audit_event(
            super::audit::DelegationAuditAction::TokenRevoked,
            None,
            None,
            Some(credential_provider_id),
            Some(&grant.surface_id),
        );
        event.token_id = Some(grant.id.clone());
        event.provider_name = provider_name.map(str::to_string);
        let mut detail = revocation.detail();
        for note in notes {
            detail.push_str(&format!(",{note}"));
        }
        event.detail = Some(detail);
        event.caller = actor.cloned();
        event
    });
}

/// What revoking removed grants on a task of their own needs: each grant's
/// provider by its record id, the secrets store, the test allow-list of
/// fixtures (`None` in production), and the management caller whose change
/// removed them.
#[derive(Clone)]
pub struct Revoker {
    pub providers: HashMap<String, CredentialProvider>,
    pub secrets: Option<Arc<dyn SecretsStore>>,
    pub exact_allowlist: Option<String>,
    pub actor: Option<AuditCallerContext>,
    /// The vault, to tell whether another grant of the vendor account uses
    /// the authorization a provider whose revocation ends it
    /// ([`CredentialProvider::revocation_ends_authorization`]) would end, and
    /// to keep the grants it cannot tell about for the daily sweep. Without
    /// it, such a grant whose account is known is revoked.
    pub vault: Option<Arc<dyn DelegationVaultStorage>>,
}

/// The outcome of the change that removes grants, as [`delete_then_revoke`]
/// waits for it.
pub struct ChangeOutcome {
    /// Whether the change was saved, sent by its caller once it knows.
    pub saved: tokio::sync::oneshot::Receiver<bool>,
    /// Whether the change is stored, read again when the caller was dropped
    /// before it sent `saved`: a save can finish after its caller is gone.
    /// It runs while the task still holds its `hold`, so the lock that
    /// serialises the change covers the read.
    pub stored: futures::future::BoxFuture<'static, bool>,
    /// The revocations kept for the earlier removals of the grants' provider,
    /// read before the change, which a provider's delete decides once it was
    /// saved ([`decide_kept`]).
    pub kept: Vec<DeferredRevocation>,
    /// The change deletes the grants' provider: once it is saved, no other
    /// grant of it is stored, so none is kept to be told apart from them.
    pub provider_gone: bool,
}

/// Delete each of `grants`, as read, from the vault, which ends its release at
/// once, while it is still the connection read, and then revoke what the
/// vault deleted at its authorization server, at most
/// [`REVOCATION_CONCURRENCY`] at a time, auditing each outcome. A grant
/// refreshed since it was read has its current tokens revoked; one the person
/// connected again since is kept; one already gone was removed, and is
/// revoked, by whoever removed it.
///
/// The deletions and the revocations run on one task of their own, in the
/// request being served when there is one, so their audit records and log
/// lines name its id and surface variant. The caller waits only until every
/// deletion has ended, never on a vendor, and dropping the caller, as a
/// request whose client disconnects is dropped, stops nothing. With
/// `outcome`, that of the change that removes the grants, the task then waits
/// for it: the grants are revoked once the change was saved, and put back,
/// unrevoked, when it was not, so a change that fails never costs a grant.
/// When the caller was dropped first, the task reads whether the change is
/// stored ([`ChangeOutcome::stored`]) and decides by that. Without an outcome
/// they are revoked at once. `hold` is dropped once every deletion has ended,
/// or with `outcome` once it is known and every grant put back, so a lock it
/// carries covers them even when the caller is gone, and never waits on a
/// vendor. Every grant is tried; the call fails if any could not be deleted,
/// and the change is then refused, which puts back the ones that were. The
/// returned task ends when every revocation has.
pub async fn delete_then_revoke<Hold: Send + 'static>(
    vault: &Arc<dyn DelegationVaultStorage>,
    grants: Vec<DelegatedGrant>,
    revoker: Revoker,
    hold: Hold,
    mut outcome: Option<ChangeOutcome>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let vault = Arc::clone(vault);
    let (report, deletions) = tokio::sync::oneshot::channel();
    let earlier = outcome
        .as_mut()
        .map(|outcome| std::mem::take(&mut outcome.kept))
        .unwrap_or_default();
    let provider_gone = outcome
        .as_ref()
        .is_some_and(|outcome| outcome.provider_gone);
    let task = crate::audit::producer::spawn_audited(async move {
        let mut deleted = Vec::with_capacity(grants.len());
        let mut failure = None;
        for grant in grants {
            match vault
                .delete_grant_of_connection(&grant.id, grant.created_at)
                .await
            {
                Ok(Some(grant)) => deleted.push(grant),
                Ok(None) => {}
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        let refused = failure.is_some();
        // The caller may be gone; what follows goes ahead all the same.
        let _ = report.send(failure);
        let kept = keep_pending(revoker.vault.as_ref(), &revoker.providers, deleted).await;
        let revoke = match outcome {
            Some(_) if refused => false,
            Some(ChangeOutcome { saved, stored, .. }) => match saved.await {
                Ok(saved) => saved,
                Err(_) => stored.await,
            },
            None => true,
        };
        if !revoke {
            let lost = put_back(&vault, kept, &revoker).await;
            drop(hold);
            decide_each(lost, &revoker, None, false).await;
            return;
        }
        drop(hold);
        decide_each(kept, &revoker, None, provider_gone).await;
        if !earlier.is_empty() {
            decide_kept(&vault, earlier, &revoker, chrono::Utc::now(), true).await;
        }
    });
    match deletions.await {
        Ok(None) => Ok(task),
        Ok(Some(error)) => Err(error.context("Failed to delete a delegated grant")),
        Err(_) => Err(anyhow::anyhow!("The task deleting delegated grants ended before it reported")),
    }
}

/// Store again grants deleted for a change that was not saved, forgetting
/// the pending revocation of each put back. Returns those that could not be
/// stored, each logged, for the caller to revoke: no copy of them is kept, so
/// they must not stay valid at the vendor.
async fn put_back(
    vault: &Arc<dyn DelegationVaultStorage>,
    grants: Vec<ToRevoke>,
    revoker: &Revoker,
) -> Vec<ToRevoke> {
    let mut lost = Vec::new();
    for item in grants {
        match vault
            .store_grant(item.grant.clone())
            .await
        {
            Ok(_) => {
                revoker
                    .forget(item.kept)
                    .await;
            }
            Err(error) => {
                tracing::error!(
                    target: "credential_delegation",
                    grant_id = %item.grant.id,
                    error = ?format!("{error:#}"),
                    "A delegated grant deleted for a change that was not saved could not be put back, so it is \
                     revoked; its person must connect again"
                );
                lost.push(item);
            }
        }
    }
    lost
}

/// One stored grant's vendor account, as the in-use check needs it: no token.
struct HeldAccount {
    tenant_id: Option<String>,
    subject: String,
    id: String,
    connected_at: chrono::DateTime<chrono::Utc>,
}

/// The vendor accounts that hold grants of each provider whose revocation
/// ends whole authorizations, read once for a batch of grants to revoke, so
/// removing many grants reads each such provider's grants once: `None` for a
/// provider whose grants could not all be read.
struct AuthorizationsInUse(HashMap<String, Option<Vec<HeldAccount>>>);

impl AuthorizationsInUse {
    /// Read what deciding on `grants` needs: the grants of each provider that
    /// ends whole authorizations and that one of them, with a known vendor
    /// account, was made with.
    async fn read(
        vault: Option<&Arc<dyn DelegationVaultStorage>>,
        providers: &HashMap<String, CredentialProvider>,
        grants: &[DelegatedGrant],
    ) -> Self {
        let mut read = HashMap::new();
        for grant in grants {
            let Some(provider) = providers.get(&grant.credential_provider_id) else {
                continue;
            };
            if !provider.revocation_ends_authorization
                || grant.vendor_subject.is_none()
                || read.contains_key(&provider.id)
            {
                continue;
            }
            let held = match vault {
                Some(vault) => match vault
                    .provider_grants(&provider.id)
                    .await
                {
                    Ok(held) => Some(
                        held.into_iter()
                            .filter_map(|other| {
                                Some(HeldAccount {
                                    subject: other.vendor_subject?,
                                    tenant_id: other.tenant_id,
                                    id: other.id,
                                    connected_at: other.created_at,
                                })
                            })
                            .collect(),
                    ),
                    Err(error) => {
                        tracing::warn!(
                            target: "credential_delegation",
                            credential_provider_id = %provider.id,
                            error = %error,
                            "Cannot tell whether the vendor accounts of removed grants hold other grants of a \
                             provider whose revocation ends whole authorizations; their revocations are left to \
                             the daily sweep"
                        );
                        None
                    }
                },
                None => None,
            };
            read.insert(provider.id.clone(), held);
        }
        Self(read)
    }

    /// Whether another stored grant, of the same tenant, holds the
    /// authorization of `grant`'s vendor account: `Some(false)` for a grant
    /// whose account is not known, revoked as the safe default; `None` when
    /// it cannot be told.
    fn holds_another(
        &self,
        grant: &DelegatedGrant,
    ) -> Option<bool> {
        let Some(subject) = grant
            .vendor_subject
            .as_deref()
        else {
            return Some(false);
        };
        let held = self
            .0
            .get(&grant.credential_provider_id)?
            .as_ref()?;
        Some(held.iter().any(|other| {
            other.subject == subject
                && other.tenant_id == grant.tenant_id
                && (other.id != grant.id || other.connected_at != grant.created_at)
        }))
    }
}

/// The most times a pending revocation is tried while it cannot reach its
/// vendor: when its grant is removed, then when the gateway starts and at
/// each daily sweep ([`revoke_pending`]).
pub const PENDING_REVOCATION_ATTEMPTS: u32 = 5;

/// What the audit record of a revocation that could not reach its vendor,
/// and is kept to be tried again, adds to its `detail`.
const RETRY_PENDING: &str = "retry:pending";
/// What the audit record of a revocation that could not reach its vendor for
/// the last of its [`PENDING_REVOCATION_ATTEMPTS`] adds to its `detail`.
const RETRY_EXHAUSTED: &str = "retry:exhausted";

/// A removed grant to revoke, with the pending revocation the vault keeps
/// for it, when it could keep one.
struct ToRevoke {
    grant: DelegatedGrant,
    kept: Option<DeferredRevocation>,
}

/// Keep each of `grants` as a pending revocation
/// ([`Deferral::Pending`]), before any is revoked, or, for grants a change
/// removes, as soon as they are deleted, while the change is saved, so a
/// gateway that stops before one ends tries it again when it starts. One the
/// vault cannot keep, as while at-rest encryption is off, is revoked all the
/// same, and logged.
async fn keep_pending(
    vault: Option<&Arc<dyn DelegationVaultStorage>>,
    providers: &HashMap<String, CredentialProvider>,
    grants: Vec<DelegatedGrant>,
) -> Vec<ToRevoke> {
    let now = chrono::Utc::now();
    let mut kept = Vec::with_capacity(grants.len());
    for grant in grants {
        let record = match vault {
            Some(vault) => {
                let record = DeferredRevocation::new(grant.clone(), now, Deferral::Pending).with_provider(
                    providers
                        .get(&grant.credential_provider_id)
                        .cloned(),
                );
                match vault
                    .keep_revocation(&record)
                    .await
                {
                    Ok(()) => Some(record),
                    Err(error) => {
                        tracing::warn!(
                            target: "credential_delegation",
                            grant_id = %grant.id,
                            error = %error,
                            "A removed delegated grant's revocation could not be kept; it is revoked all the same, \
                             but a gateway that stops before it ends does not try it again"
                        );
                        None
                    }
                }
            }
            None => None,
        };
        kept.push(ToRevoke { grant, kept: record });
    }
    kept
}

/// Revoke `grants`, already removed from the vault, at most
/// [`REVOCATION_CONCURRENCY`] at a time, logging and auditing each outcome,
/// each audit record's `detail` ending with `note` when there is one. Each is
/// kept as a pending revocation first ([`keep_pending`]). At a provider whose
/// revocation ends the whole authorization of the vendor account that
/// consented, a grant is not revoked while another grant of that account is
/// stored (`skipped`, [`SKIPPED_AUTHORIZATION_IN_USE`]); when the vault
/// cannot tell, the grant is kept for the daily sweep (`skipped`,
/// [`SKIPPED_DEFERRED`]), or, when it cannot keep it either, revoked.
async fn revoke_each(
    grants: Vec<DelegatedGrant>,
    revoker: &Revoker,
    note: Option<&'static str>,
) {
    let items = keep_pending(revoker.vault.as_ref(), &revoker.providers, grants).await;
    decide_each(items, revoker, note, false).await;
}

/// [`revoke_each`] for grants already kept as pending revocations, or that
/// could not be: each pending revocation is forgotten once its grant is
/// decided, and kept, its attempts counted, while its revocation cannot
/// reach the vendor ([`Revoker::revoke_kept`]).
async fn decide_each(
    items: Vec<ToRevoke>,
    revoker: &Revoker,
    note: Option<&'static str>,
    provider_gone: bool,
) {
    let grants: Vec<DelegatedGrant> = items
        .iter()
        .map(|item| item.grant.clone())
        .collect();
    let in_use = AuthorizationsInUse::read(revoker.vault.as_ref(), &revoker.providers, &grants).await;
    let in_use = &in_use;
    futures::stream::iter(items)
        .for_each_concurrent(REVOCATION_CONCURRENCY, |ToRevoke { grant, kept }| async move {
            let Some(provider) = revoker
                .providers
                .get(&grant.credential_provider_id)
            else {
                record_revocation(
                    &grant.credential_provider_id,
                    None,
                    &grant,
                    GrantRevocation::skipped(SKIPPED_PROVIDER_MISSING),
                    revoker.actor.as_ref(),
                    note.as_slice(),
                );
                revoker.forget(kept).await;
                return;
            };
            let holds_another = if provider.revocation_ends_authorization && !provider_gone {
                in_use.holds_another(&grant)
            } else {
                Some(false)
            };
            match holds_another {
                Some(true) => {
                    record_revocation(
                        &provider.id,
                        Some(&provider.name),
                        &grant,
                        GrantRevocation::skipped(SKIPPED_AUTHORIZATION_IN_USE),
                        revoker.actor.as_ref(),
                        note.as_slice(),
                    );
                    revoker.forget(kept).await;
                }
                Some(false) => {
                    revoker
                        .revoke_kept(provider, &grant, kept, note)
                        .await;
                }
                None => {
                    let deferred = match revoker.vault.as_ref() {
                        Some(vault) => {
                            vault
                                .defer_revocation(grant.clone(), Some(provider.clone()))
                                .await
                        }
                        None => Err(anyhow::anyhow!("No vault keeps the revocation for later")),
                    };
                    match deferred {
                        Ok(()) => {
                            record_revocation(
                                &provider.id,
                                Some(&provider.name),
                                &grant,
                                GrantRevocation::skipped(SKIPPED_DEFERRED),
                                revoker.actor.as_ref(),
                                note.as_slice(),
                            );
                            revoker.forget(kept).await;
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: "credential_delegation",
                                grant_id = %grant.id,
                                error = %error,
                                "A removed delegated grant's revocation could not be left to the daily sweep; it is \
                                 revoked now"
                            );
                            revoker
                                .revoke_kept(provider, &grant, kept, note)
                                .await;
                        }
                    }
                }
            }
        })
        .await;
}

impl Revoker {
    /// Revoke `grant` at `provider`, then settle `kept`, its pending
    /// revocation, and audit the outcome: `kept` is forgotten once the
    /// revocation reached the vendor, whatever it answered; while it could not
    /// (`unreachable`, or refused for now with a `429` or `5xx`), it is kept, its attempts counted, and tried again
    /// ([`RETRY_PENDING`]), until the last of [`PENDING_REVOCATION_ATTEMPTS`]
    /// ([`RETRY_EXHAUSTED`]).
    async fn revoke_kept(
        &self,
        provider: &CredentialProvider,
        grant: &DelegatedGrant,
        kept: Option<DeferredRevocation>,
        note: Option<&'static str>,
    ) {
        let revocation = revoke(
            provider,
            grant,
            self.secrets.as_ref(),
            self.exact_allowlist
                .as_deref(),
        )
        .await;
        let retry = match kept {
            Some(mut kept) if revocation.should_retry() => {
                kept.attempts += 1;
                kept.provider
                    .get_or_insert_with(|| provider.clone());
                if kept.attempts >= PENDING_REVOCATION_ATTEMPTS {
                    tracing::warn!(
                        target: "credential_delegation",
                        grant_id = %grant.id,
                        attempts = kept.attempts,
                        "A removed delegated grant's revocation could not reach its vendor and is not tried again; its \
                         tokens stay valid at the vendor until they expire or the person removes the app there"
                    );
                    self.forget(Some(kept)).await;
                    Some(RETRY_EXHAUSTED)
                } else {
                    self.keep_for_retry(&kept)
                        .await
                }
            }
            kept => {
                self.forget(kept).await;
                None
            }
        };
        let notes: Vec<&'static str> = note
            .into_iter()
            .chain(retry)
            .collect();
        record_revocation(&provider.id, Some(&provider.name), grant, revocation, self.actor.as_ref(), &notes);
    }

    /// Store `kept` again, its attempts counted, to be tried again:
    /// [`RETRY_PENDING`] when it is, `None` when the vault refuses.
    async fn keep_for_retry(
        &self,
        kept: &DeferredRevocation,
    ) -> Option<&'static str> {
        let vault = self.vault.as_ref()?;
        match vault
            .keep_revocation(kept)
            .await
        {
            Ok(()) => Some(RETRY_PENDING),
            Err(error) => {
                tracing::warn!(
                    target: "credential_delegation",
                    grant_id = %kept.grant.id,
                    error = %error,
                    "A removed delegated grant's revocation could not reach its vendor, nor be kept to be tried again"
                );
                None
            }
        }
    }

    /// Forget `kept`, a pending revocation now decided. One that cannot be
    /// forgotten is tried again later, and its grant then revoked again, which
    /// a vendor answers as it answers any token it no longer knows.
    async fn forget(
        &self,
        kept: Option<DeferredRevocation>,
    ) {
        let (Some(kept), Some(vault)) = (kept, self.vault.as_ref()) else {
            return;
        };
        if let Err(error) = vault
            .forget_deferred_revocation(&kept.id)
            .await
        {
            tracing::warn!(
                target: "credential_delegation",
                deferred_revocation_id = %kept.id,
                error = %error,
                "Failed to forget a decided revocation; it is tried again later"
            );
        }
    }
}

/// Decide the revocations kept, as of `now`: the pending ones are tried
/// again ([`revoke_pending`]); those a removal left to the daily sweep
/// ([`SKIPPED_DEFERRED`]) are each revoked once no other grant of its vendor
/// account is stored, as a pending revocation is, so one that cannot reach its
/// vendor is kept and tried again; or recorded `skipped`
/// ([`SKIPPED_AUTHORIZATION_IN_USE`]) when one is, and forgotten. One the vault still cannot tell
/// about is kept, until it has waited [`DEFERRED_REVOCATION_DAYS`] days, when
/// it is revoked all the same: a revocation is delayed, never lost.
/// `revoker.providers` must hold the provider of each kept grant that still
/// exists. Returns how many were decided or tried.
#[cfg(test)]
pub async fn revoke_deferred(
    revoker: Revoker,
    now: chrono::DateTime<chrono::Utc>,
) -> usize {
    let Some(vault) = revoker.vault.clone() else {
        return 0;
    };
    let Some(kept) = kept_revocations(&vault).await else {
        return 0;
    };
    revoke_deferred_of(revoker, kept, now).await
}

/// [`revoke_deferred`] for `kept`, read already: the sweep leaves out those
/// whose provider cannot be read now.
pub async fn revoke_deferred_of(
    revoker: Revoker,
    kept: Vec<DeferredRevocation>,
    now: chrono::DateTime<chrono::Utc>,
) -> usize {
    let Some(vault) = revoker.vault.clone() else {
        return 0;
    };
    decide_kept(&vault, kept, &revoker, now, false).await
}

/// The revocations the vault keeps for grants of provider `provider_id`, read
/// before the provider is deleted, so a provider's delete ([`ChangeOutcome::kept`]) can
/// decide them with it. An error when they cannot be read: the provider must
/// then be kept, or they could only be forgotten unrevoked.
pub async fn kept_revocations_of(
    vault: &Arc<dyn DelegationVaultStorage>,
    provider_id: &str,
) -> anyhow::Result<Vec<DeferredRevocation>> {
    Ok(vault
        .every_deferred_revocation()
        .await?
        .into_iter()
        .filter(|revocation| {
            revocation
                .grant
                .credential_provider_id
                == provider_id
        })
        .collect())
}

/// [`revoke_deferred`] for `kept`, read already. `provider_gone` says each
/// grant's provider was deleted with all its grants, so no other grant holds
/// a kept one's vendor account and each is revoked.
async fn decide_kept(
    vault: &Arc<dyn DelegationVaultStorage>,
    kept: Vec<DeferredRevocation>,
    revoker: &Revoker,
    now: chrono::DateTime<chrono::Utc>,
    provider_gone: bool,
) -> usize {
    let (pending, deferred): (Vec<_>, Vec<_>) = kept
        .into_iter()
        .partition(|revocation| revocation.deferral == Deferral::Pending);
    let mut decided = retry_pending(vault, pending, revoker).await;
    if deferred.is_empty() {
        return decided;
    }
    let grants: Vec<DelegatedGrant> = deferred
        .iter()
        .map(|deferral| deferral.grant.clone())
        .collect();
    let in_use = AuthorizationsInUse::read(Some(vault), &revoker.providers, &grants).await;
    for deferral in deferred {
        let grant = &deferral.grant;
        match revoker
            .providers
            .get(&grant.credential_provider_id)
        {
            None => record_revocation(
                &grant.credential_provider_id,
                None,
                grant,
                GrantRevocation::skipped(SKIPPED_PROVIDER_MISSING),
                revoker.actor.as_ref(),
                &[],
            ),
            Some(provider) => {
                let holds_another = if provider.revocation_ends_authorization && !provider_gone {
                    in_use.holds_another(grant)
                } else {
                    Some(false)
                };
                let overdue = now
                    .signed_duration_since(deferral.deferred_at)
                    .num_days()
                    >= DEFERRED_REVOCATION_DAYS;
                match (holds_another, overdue) {
                    (Some(true), _) => record_revocation(
                        &provider.id,
                        Some(&provider.name),
                        grant,
                        GrantRevocation::skipped(SKIPPED_AUTHORIZATION_IN_USE),
                        revoker.actor.as_ref(),
                        &[],
                    ),
                    (Some(false), _) | (None, true) => {
                        let grant = grant.clone();
                        let pending = DeferredRevocation {
                            deferral: Deferral::Pending,
                            ..deferral
                        };
                        revoker
                            .revoke_kept(provider, &grant, Some(pending), None)
                            .await;
                        decided += 1;
                        continue;
                    }
                    (None, false) => continue,
                }
            }
        }
        match vault
            .forget_deferred_revocation(&deferral.id)
            .await
        {
            Ok(()) => decided += 1,
            Err(error) => tracing::warn!(
                target: "credential_delegation",
                deferred_revocation_id = %deferral.id,
                error = %error,
                "Failed to forget a decided revocation; the next sweep decides it again"
            ),
        }
    }
    decided
}

/// Try again the pending revocations kept ([`Deferral::Pending`]): those in
/// flight when the gateway stopped, and those that could not reach their
/// vendor. Run when the gateway starts and by the daily sweep. Each is
/// revoked as a removal revokes it, and forgotten once it reached the vendor,
/// or after the last of [`PENDING_REVOCATION_ATTEMPTS`]. One whose grant the
/// vault holds again, with any of its tokens, is forgotten unrevoked; one
/// whose stored grant cannot be read, and so cannot be released, is revoked.
/// `revoker.providers` must hold the provider of each kept grant that still
/// exists. Returns how many were decided or tried.
#[cfg(test)]
pub async fn revoke_pending(revoker: Revoker) -> usize {
    let Some(vault) = revoker.vault.clone() else {
        return 0;
    };
    let Some(kept) = kept_revocations(&vault).await else {
        return 0;
    };
    revoke_pending_of(revoker, kept).await
}

/// [`revoke_pending`] for the pending ones of `kept`, read already: the sweep
/// leaves out those whose provider cannot be read now.
pub async fn revoke_pending_of(
    revoker: Revoker,
    kept: Vec<DeferredRevocation>,
) -> usize {
    let Some(vault) = revoker.vault.clone() else {
        return 0;
    };
    let pending = kept
        .into_iter()
        .filter(|revocation| revocation.deferral == Deferral::Pending)
        .collect();
    retry_pending(&vault, pending, &revoker).await
}

/// Every revocation the vault keeps, `None` when they cannot be read.
#[cfg(test)]
async fn kept_revocations(vault: &Arc<dyn DelegationVaultStorage>) -> Option<Vec<DeferredRevocation>> {
    match vault
        .deferred_revocations()
        .await
    {
        Ok(kept) => Some(kept),
        Err(error) => {
            tracing::warn!(target: "credential_delegation", error = %error, "Failed to read kept revocations");
            None
        }
    }
}

/// [`revoke_pending`] for `pending`, read already.
async fn retry_pending(
    vault: &Arc<dyn DelegationVaultStorage>,
    pending: Vec<DeferredRevocation>,
    revoker: &Revoker,
) -> usize {
    let mut tried = 0;
    let mut items = Vec::with_capacity(pending.len());
    for kept in pending {
        match vault
            .grant_by_id(&kept.grant.id)
            .await
        {
            Ok(Some(held)) if holds_a_token_of(&held, &kept.grant) => {
                tracing::info!(
                    target: "credential_delegation",
                    grant_id = %kept.grant.id,
                    "A pending revocation's grant is held again, so it is not revoked"
                );
                revoker
                    .forget(Some(kept))
                    .await;
                tried += 1;
            }
            Ok(_) => items.push(ToRevoke {
                grant: kept.grant.clone(),
                kept: Some(kept),
            }),
            Err(error) if error.is::<super::grants::UnreadableGrant>() => items.push(ToRevoke {
                grant: kept.grant.clone(),
                kept: Some(kept),
            }),
            Err(error) => tracing::warn!(
                target: "credential_delegation",
                deferred_revocation_id = %kept.id,
                error = %error,
                "Cannot tell whether a pending revocation's grant is held again; it is tried later"
            ),
        }
    }
    tried += items.len();
    decide_each(items, revoker, None, false).await;
    tried
}

/// Whether `held`, a grant stored now, holds a token of `removed`: then the
/// connection is in use, and revoking `removed` would end it.
fn holds_a_token_of(
    held: &DelegatedGrant,
    removed: &DelegatedGrant,
) -> bool {
    held.access_token == removed.access_token
        || held.refresh_token.is_some() && held.refresh_token == removed.refresh_token
}

/// Revoke tokens a connect or a refresh obtained but no grant keeps, as
/// [`revoke_removed`] revokes removed grants, their audit records ending
/// `,unkept_tokens`: they name the record id of a grant that may still be
/// connected, which must not read as a disconnect.
pub async fn revoke_unkept(
    grants: Vec<DelegatedGrant>,
    revoker: Revoker,
) {
    revoke_each(grants, &revoker, Some(UNKEPT_TOKENS)).await;
}

/// Revoke grants removed because their consent ended at its time limit, as
/// [`revoke_removed`] revokes removed grants, their audit records ending
/// `,consent_expired`: the outcome of an expiry, which nobody revoked.
pub async fn revoke_expired(
    grants: Vec<DelegatedGrant>,
    revoker: Revoker,
) {
    revoke_each(grants, &revoker, Some(super::consent_age::CONSENT_EXPIRED)).await;
}

/// Revoke grants already removed from the vault, at most
/// [`REVOCATION_CONCURRENCY`] at a time, logging and auditing each outcome.
/// At a provider whose revocation ends the whole authorization of the vendor
/// account that consented, a grant is not revoked while another grant of that
/// account is stored (`skipped`, [`SKIPPED_AUTHORIZATION_IN_USE`]), and is
/// left to the daily sweep while the vault cannot tell (`skipped`,
/// [`SKIPPED_DEFERRED`]).
pub async fn revoke_removed(
    grants: Vec<DelegatedGrant>,
    revoker: Revoker,
) {
    revoke_each(grants, &revoker, None).await;
}

/// Audit that an operator purged the grant with this record id without
/// reading it, so it was not revoked at its authorization server. `binding`
/// is the binding the purge named, when it named one: the record then carries
/// its surface and provider, and its `detail` its tenant and Transit Point,
/// each a JSON string, after the reason.
pub fn record_purge(
    grant_id: &str,
    binding: Option<&GrantBinding>,
    actor: Option<&AuditCallerContext>,
) {
    tracing::warn!(
        target: "credential_delegation",
        grant_id = %grant_id,
        surface_id = ?binding.map(|binding| binding.surface_id.as_str()),
        transit_point_id = ?binding.map(|binding| binding.hop.as_str()),
        credential_provider_id = ?binding.map(|binding| binding.credential_provider_id.as_str()),
        tenant_id = ?binding.and_then(|binding| binding.tenant_id.as_deref()),
        "A delegated grant was purged without reading it, so it is not revoked at its authorization server"
    );
    super::audit::emit("token_revoked", || {
        let mut event = super::audit::audit_event(
            super::audit::DelegationAuditAction::TokenRevoked,
            None,
            None,
            binding.map(|binding| {
                binding
                    .credential_provider_id
                    .as_str()
            }),
            binding.map(|binding| binding.surface_id.as_str()),
        );
        event.token_id = Some(grant_id.to_string());
        let mut detail = GrantRevocation::skipped(SKIPPED_PURGED).detail();
        if let Some(binding) = binding {
            let quoted = |value: &str| serde_json::Value::String(value.to_string()).to_string();
            if let Some(tenant_id) = binding.tenant_id.as_deref() {
                detail.push_str(&format!(",tenant:{}", quoted(tenant_id)));
            }
            detail.push_str(&format!(",transit_point:{}", quoted(&binding.hop)));
        }
        event.detail = Some(detail);
        event.caller = actor.cloned();
        event
    });
}

/// Revoke `grant` at `provider`'s revocation endpoint, giving up after
/// [`VENDOR_REVOCATION_TIMEOUT`] wherever it waits.
async fn revoke(
    provider: &CredentialProvider,
    grant: &DelegatedGrant,
    secrets: Option<&Arc<dyn SecretsStore>>,
    exact_allowlist: Option<&str>,
) -> GrantRevocation {
    tokio::time::timeout(VENDOR_REVOCATION_TIMEOUT, revoke_at_vendor(provider, grant, secrets, exact_allowlist))
        .await
        .unwrap_or(GrantRevocation::failed(RevocationOutcome::Unreachable))
}

async fn revoke_at_vendor(
    provider: &CredentialProvider,
    grant: &DelegatedGrant,
    secrets: Option<&Arc<dyn SecretsStore>>,
    exact_allowlist: Option<&str>,
) -> GrantRevocation {
    let client = match RevocationClient::new(provider, secrets, exact_allowlist).await {
        Ok(client) => client,
        Err(revocation) => return revocation,
    };
    match grant.refresh_token.as_deref() {
        Some(refresh_token) => GrantRevocation {
            outcome: client
                .revoke(refresh_token, "refresh_token")
                .await,
            access_token: Some(
                client
                    .revoke(&grant.access_token, "access_token")
                    .await,
            ),
            reason: None,
        },
        None => GrantRevocation::failed(
            client
                .revoke(&grant.access_token, "access_token")
                .await,
        ),
    }
}

/// A provider's client at its revocation endpoint, reached through one pinned
/// connection policy for every token of a grant.
struct RevocationClient<'a> {
    endpoint: &'a str,
    provider: &'a CredentialProvider,
    credential: ClientCredential,
    http: reqwest::Client,
}

impl<'a> RevocationClient<'a> {
    async fn new(
        provider: &'a CredentialProvider,
        secrets: Option<&Arc<dyn SecretsStore>>,
        exact_allowlist: Option<&str>,
    ) -> Result<Self, GrantRevocation> {
        let endpoint = provider
            .revocation_endpoint
            .as_deref()
            .ok_or(GrantRevocation::failed(RevocationOutcome::NotSupported))?;
        let credential = match ClientCredential::resolve(provider, secrets).await {
            Ok(credential) => credential,
            Err(ClientUnresolved::NoSecretsStore) => return Err(GrantRevocation::skipped(SKIPPED_NO_SECRETS_STORE)),
            Err(ClientUnresolved::Unavailable) => {
                return Err(GrantRevocation::failed(RevocationOutcome::ClientUnavailable));
            }
        };
        let http = crate::egress::pinned_vendor_client(endpoint, REVOCATION_TIMEOUT, exact_allowlist)
            .await
            .map_err(|error| {
                tracing::warn!(
                    target: "credential_delegation",
                    surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
                    error = ?error.to_string(),
                    "Revocation endpoint refused by egress policy"
                );
                GrantRevocation::failed(RevocationOutcome::Unreachable)
            })?;
        Ok(Self {
            endpoint,
            provider,
            credential,
            http,
        })
    }

    /// The request that revokes `token`, or `None` when the client's credential does not fit its
    /// method. Its `Authorization` header, when the method sends one, is marked sensitive.
    fn request(
        &self,
        token: &str,
        hint: &str,
    ) -> Option<reqwest::RequestBuilder> {
        let authentication = self
            .credential
            .authenticate(self.provider)?;
        let mut form: Vec<(&str, &str)> = vec![("token", token), ("token_type_hint", hint)];
        form.extend(
            authentication
                .form
                .iter()
                .map(|(name, value)| (*name, value.as_str())),
        );
        let request = self
            .http
            .post(self.endpoint)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&form);
        Some(match authentication.authorization {
            Some(authorization) => super::oauth::with_sensitive_authorization(request, &authorization),
            None => request,
        })
    }

    async fn revoke(
        &self,
        token: &str,
        hint: &str,
    ) -> RevocationOutcome {
        let Some(request) = self.request(token, hint) else {
            return RevocationOutcome::ClientUnavailable;
        };
        match request.send().await {
            Ok(response) if response.status().is_success() => RevocationOutcome::Revoked,
            Ok(response)
                if response
                    .status()
                    .is_server_error()
                    || response.status().as_u16() == 429 =>
            {
                RevocationOutcome::RefusedForNow
            }
            Ok(_) => RevocationOutcome::Refused,
            Err(_) => RevocationOutcome::Unreachable,
        }
    }
}

/// What an external consent provider's client authenticates with at its token
/// and revocation endpoints, as its `token_endpoint_auth_method` says.
pub(super) enum ClientCredential {
    /// A public client: `client_id` in the body.
    Public,
    /// The client secret of `client_secret_basic` or `client_secret_post`.
    Secret(zeroize::Zeroizing<String>),
    /// The PEM signing key, and certificate if any, of a `private_key_jwt`
    /// client, which signs a fresh assertion for each request.
    SigningKey { key: zeroize::Zeroizing<String>, certificate: Option<zeroize::Zeroizing<String>> },
}

/// Why a client's credential could not be resolved.
pub(super) enum ClientUnresolved {
    /// The method needs a secret, and there is no secrets store.
    NoSecretsStore,
    /// The provider names no client, or a secret it names is missing or of
    /// another tenant.
    Unavailable,
}

/// The form fields and `Authorization` header that authenticate a client on
/// one request.
pub(super) struct ClientAuthentication {
    pub form: Vec<(&'static str, zeroize::Zeroizing<String>)>,
    pub authorization: Option<zeroize::Zeroizing<String>>,
}

impl ClientCredential {
    /// The credential `provider`'s method needs. A provider with an issuer uses
    /// its own tenant's secrets only (an untenanted one, untenanted secrets); any
    /// other provider its own tenant's or an untenanted one.
    pub(super) async fn resolve(
        provider: &CredentialProvider,
        secrets: Option<&Arc<dyn SecretsStore>>,
    ) -> Result<Self, ClientUnresolved> {
        let (Some(_), Some(method)) = (provider.client_id.as_deref(), provider.token_endpoint_auth_method) else {
            return Err(ClientUnresolved::Unavailable);
        };
        if method == TokenEndpointAuthMethod::None {
            return Ok(Self::Public);
        }
        let secrets = secrets.ok_or(ClientUnresolved::NoSecretsStore)?;
        let resolve = |reference: Option<&str>| {
            let reference = reference.map(str::to_string);
            async move {
                match reference {
                    Some(reference) => provider_secret(provider, secrets, &reference)
                        .await
                        .map(Some)
                        .ok_or(ClientUnresolved::Unavailable),
                    None => Ok(None),
                }
            }
        };
        match method {
            TokenEndpointAuthMethod::None => Ok(Self::Public),
            TokenEndpointAuthMethod::ClientSecretBasic | TokenEndpointAuthMethod::ClientSecretPost => resolve(
                provider
                    .client_secret_secret_ref
                    .as_deref(),
            )
            .await?
            .map(Self::Secret)
            .ok_or(ClientUnresolved::Unavailable),
            TokenEndpointAuthMethod::PrivateKeyJwt => Ok(Self::SigningKey {
                key: resolve(
                    provider
                        .jwt
                        .jwt_signing_key_secret_ref
                        .as_deref(),
                )
                .await?
                .ok_or(ClientUnresolved::Unavailable)?,
                certificate: resolve(
                    provider
                        .jwt
                        .jwt_certificate_secret_ref
                        .as_deref(),
                )
                .await?,
            }),
        }
    }

    /// The authentication of `provider`'s client on one request. A
    /// `private_key_jwt` client signs a new assertion
    /// ([`super::jwt_assertion::client_auth_assertion_claims`]), so each
    /// request has its own `jti`, addressed to the provider's issuer, the
    /// audience RFC 7523bis requires, never to an endpoint its tenant wrote.
    /// `None` when the credential does not fit the method or the assertion
    /// cannot be signed.
    pub(super) fn authenticate(
        &self,
        provider: &CredentialProvider,
    ) -> Option<ClientAuthentication> {
        let client_id = provider
            .client_id
            .as_deref()?;
        let owned = |value: &str| zeroize::Zeroizing::new(value.to_string());
        let (form, authorization) = match (provider.token_endpoint_auth_method?, self) {
            (TokenEndpointAuthMethod::None, Self::Public) => (vec![("client_id", owned(client_id))], None),
            (TokenEndpointAuthMethod::ClientSecretPost, Self::Secret(secret)) => {
                (vec![("client_id", owned(client_id)), ("client_secret", secret.clone())], None)
            }
            (TokenEndpointAuthMethod::ClientSecretBasic, Self::Secret(secret)) => {
                (Vec::new(), Some(basic_authorization(client_id, secret)))
            }
            (TokenEndpointAuthMethod::PrivateKeyJwt, Self::SigningKey { key, certificate }) => {
                let mut claims = super::jwt_assertion::client_auth_assertion_claims(
                    provider,
                    client_id,
                    chrono::Utc::now().timestamp(),
                )
                .ok()?;
                claims.aud = provider.issuer.clone()?;
                let assertion = super::jwt_assertion::sign_assertion(
                    key,
                    provider.jwt_signing_algorithm()?,
                    super::jwt_assertion::AssertionHeader {
                        key_id: provider
                            .jwt
                            .jwt_key_id
                            .as_deref(),
                        certificate_pem: certificate
                            .as_ref()
                            .map(|certificate| certificate.as_str()),
                    },
                    &claims,
                )
                .ok()?;
                (
                    vec![
                        ("client_id", owned(client_id)),
                        ("client_assertion_type", owned(CLIENT_ASSERTION_TYPE)),
                        ("client_assertion", zeroize::Zeroizing::new(assertion)),
                    ],
                    None,
                )
            }
            _ => return None,
        };
        Some(ClientAuthentication { form, authorization })
    }
}

/// The `client_assertion_type` of a JWT client assertion (RFC 7523 section 2.2).
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The value of the secret `reference`, when `provider` may use it
/// ([`CredentialProvider::may_use_secret`]): an external consent provider's
/// own tenant's only.
async fn provider_secret(
    provider: &CredentialProvider,
    secrets: &Arc<dyn SecretsStore>,
    reference: &str,
) -> Option<zeroize::Zeroizing<String>> {
    let secret = secrets
        .get_by_secret_id(reference)
        .await
        .ok()
        .flatten()?;
    provider
        .may_use_secret(secret.tenant_id.as_deref())
        .then(|| zeroize::Zeroizing::new(secret.value))
}

/// `Basic` credentials as RFC 6749 section 2.3.1 builds them: the client id
/// and secret each form-urlencoded, then joined and base64-encoded.
pub(super) fn basic_authorization(
    client_id: &str,
    secret: &str,
) -> zeroize::Zeroizing<String> {
    let encode = |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    let pair = zeroize::Zeroizing::new(format!("{}:{}", encode(client_id), encode(secret)));
    zeroize::Zeroizing::new(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::delegation_vault::grants::GrantKey;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An authorization server that records each request's head and body and
    /// answers every one with `status`, after `delay`, serving connections at
    /// once, or with the answers it was started with, in turn, the last one
    /// repeated.
    pub(crate) struct RecordingServer {
        pub(crate) url: String,
        requests: Arc<Mutex<Vec<(String, String)>>>,
    }

    /// One answer of a [`RecordingServer`].
    #[derive(Clone, Debug)]
    pub(crate) struct Answer {
        pub(crate) status: u16,
        pub(crate) headers: Vec<(String, String)>,
        pub(crate) body: String,
        /// Sent only once the gate has a permit, after the request is
        /// recorded, so a test can act while a request waits for its answer.
        pub(crate) gate: Option<Arc<tokio::sync::Semaphore>>,
        /// The request is recorded, then the connection is closed without a response.
        pub(crate) hang_up: bool,
    }

    impl Answer {
        pub(crate) fn json(
            status: u16,
            body: serde_json::Value,
        ) -> Self {
            Self {
                status,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: body.to_string(),
                gate: None,
                hang_up: false,
            }
        }

        pub(crate) fn status(status: u16) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: String::new(),
                gate: None,
                hang_up: false,
            }
        }

        /// No answer: the connection is closed once the request is recorded.
        pub(crate) fn hung_up() -> Self {
            Self {
                hang_up: true,
                ..Self::status(0)
            }
        }

        /// This answer, held until `gate` has a permit.
        pub(crate) fn held(
            mut self,
            gate: &Arc<tokio::sync::Semaphore>,
        ) -> Self {
            self.gate = Some(gate.clone());
            self
        }

        pub(crate) fn with_header(
            mut self,
            name: &str,
            value: &str,
        ) -> Self {
            self.headers
                .push((name.into(), value.into()));
            self
        }
    }

    impl RecordingServer {
        pub(crate) async fn start(status: u16) -> Self {
            Self::start_with_delay(status, Duration::ZERO).await
        }

        pub(crate) async fn start_with_delay(
            status: u16,
            delay: Duration,
        ) -> Self {
            Self::start_with(|_| vec![Answer::status(status)], delay).await
        }

        pub(crate) async fn start_answering(answers: Vec<Answer>) -> Self {
            Self::start_with(|_| answers, Duration::ZERO).await
        }

        /// A server answering with `answers`, built from its own origin, as an
        /// ID token naming it as its issuer needs.
        pub(crate) async fn start_answering_for(answers: impl FnOnce(&str) -> Vec<Answer>) -> Self {
            Self::start_with(answers, Duration::ZERO).await
        }

        async fn start_with(
            answers: impl FnOnce(&str) -> Vec<Answer>,
            delay: Duration,
        ) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let answers = Arc::new(Mutex::new(std::collections::VecDeque::from(answers(&format!("http://{address}")))));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let recorded = requests.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let recorded = recorded.clone();
                    let answers = answers.clone();
                    tokio::spawn(async move {
                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 4096];
                        let (head, body) = loop {
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => break (String::new(), String::new()),
                                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                            }
                            let text = String::from_utf8_lossy(&buffer).into_owned();
                            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                                let length = head
                                    .lines()
                                    .find_map(|line| {
                                        line.to_ascii_lowercase()
                                            .strip_prefix("content-length:")
                                            .map(|value| {
                                                value
                                                    .trim()
                                                    .parse::<usize>()
                                                    .unwrap_or(0)
                                            })
                                    })
                                    .unwrap_or(0);
                                if body.len() >= length {
                                    break (head.to_string(), body.to_string());
                                }
                            }
                        };
                        let answer = {
                            let mut recorded = recorded.lock().unwrap();
                            recorded.push((head, body));
                            let mut answers = answers.lock().unwrap();
                            if answers.len() > 1 {
                                answers.pop_front()
                            } else {
                                answers.front().cloned()
                            }
                            .expect("a recording server has an answer")
                        };
                        if let Some(gate) = &answer.gate {
                            gate.acquire()
                                .await
                                .expect("an open gate")
                                .forget();
                        }
                        if answer.hang_up {
                            return;
                        }
                        tokio::time::sleep(delay).await;
                        let mut response = format!("HTTP/1.1 {} Status\r\n", answer.status);
                        for (name, value) in &answer.headers {
                            response.push_str(&format!("{name}: {value}\r\n"));
                        }
                        response.push_str(&format!(
                            "Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            answer.body.len(),
                            answer.body
                        ));
                        let _ = stream
                            .write_all(response.as_bytes())
                            .await;
                    });
                }
            });
            Self {
                url: format!("http://{address}/revoke"),
                requests,
            }
        }

        pub(crate) fn origin(&self) -> String {
            self.url
                .trim_end_matches("/revoke")
                .to_string()
        }

        pub(crate) fn requests(&self) -> Vec<(String, String)> {
            self.requests
                .lock()
                .unwrap()
                .clone()
        }

        /// The `token` field of every request received.
        pub(crate) fn revoked_tokens(&self) -> Vec<String> {
            let mut tokens: Vec<String> = self
                .requests()
                .iter()
                .filter_map(|(_, body)| {
                    url::form_urlencoded::parse(body.as_bytes())
                        .find(|(name, _)| name == "token")
                        .map(|(_, token)| token.into_owned())
                })
                .collect();
            tokens.sort();
            tokens
        }
    }

    pub(crate) fn provider(
        revocation_endpoint: Option<&str>,
        method: &str,
        secret_ref: Option<&str>,
    ) -> CredentialProvider {
        serde_json::from_value(serde_json::json!({
            "id": "provider", "tenant_id": "tenant-a", "name": "Vendor", "provider_id": "boris-0123456789ab",
            "issuer": "https://203.0.113.10", "revocation_endpoint": revocation_endpoint, "default_scopes": ["read"],
            "token_endpoint_auth_method": method, "client_id": "client id",
            "client_secret_secret_ref": secret_ref,
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap()
    }

    async fn secrets_with(
        directory: &tempfile::TempDir,
        tenant_id: Option<&str>,
    ) -> Arc<dyn SecretsStore> {
        let store = crate::secrets::FilesystemSecretsStore::new(
            directory
                .path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .unwrap();
        store
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: tenant_id.map(str::to_string),
                name: "Client secret".to_string(),
                secret_id: "client-secret".to_string(),
                description: None,
                value: "s3cret:&=".to_string(),
                secret_type: "ApiKey".to_string(),
                tags: vec![],
            })
            .await
            .unwrap();
        Arc::new(store)
    }

    fn grant(refresh: bool) -> DelegatedGrant {
        let key = GrantKey::owner(Some("tenant-a"), "surface", "hop", "provider");
        let mut grant = crate::delegation_vault::grants::tests::grant(&key, "access-token");
        grant.id = key.record_id();
        if !refresh {
            grant.refresh_token = None;
        }
        grant
    }

    fn form(body: &str) -> Vec<(String, String)> {
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect()
    }

    fn actor() -> AuditCallerContext {
        super::super::audit::management_caller_context(Some("operator"), Some("pat-1")).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_public_client_revokes_the_refresh_token_then_the_access_token_with_its_client_id() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let revocation =
            revoke(&provider(Some(&server.url), "none", None), &grant(true), Some(&secrets), Some(&server.origin()))
                .await;
        assert_eq!(
            revocation,
            GrantRevocation {
                outcome: RevocationOutcome::Revoked,
                access_token: Some(RevocationOutcome::Revoked),
                reason: None,
            }
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        for (head, _) in &requests {
            assert!(head.starts_with("POST /revoke "), "{head}");
            assert!(
                !head
                    .to_ascii_lowercase()
                    .contains("authorization:"),
                "{head}"
            );
        }
        assert_eq!(
            form(&requests[0].1),
            vec![
                ("token".to_string(), "access-token-refresh".to_string()),
                ("token_type_hint".to_string(), "refresh_token".to_string()),
                ("client_id".to_string(), "client id".to_string()),
            ]
        );
        assert_eq!(
            form(&requests[1].1),
            vec![
                ("token".to_string(), "access-token".to_string()),
                ("token_type_hint".to_string(), "access_token".to_string()),
                ("client_id".to_string(), "client id".to_string()),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_confidential_client_authenticates_as_its_method_says() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let basic = provider(Some(&server.url), "client_secret_basic", Some("client-secret"));
        assert_eq!(
            revoke(&basic, &grant(false), Some(&secrets), Some(&server.origin()))
                .await
                .outcome,
            RevocationOutcome::Revoked
        );
        let post = provider(Some(&server.url), "client_secret_post", Some("client-secret"));
        assert_eq!(
            revoke(&post, &grant(false), Some(&secrets), Some(&server.origin()))
                .await
                .outcome,
            RevocationOutcome::Revoked
        );

        let requests = server.requests();
        let expected = base64::engine::general_purpose::STANDARD.encode("client+id:s3cret%3A%26%3D");
        assert!(
            requests[0]
                .0
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&format!("authorization: Basic {expected}"))),
            "{}",
            requests[0].0
        );
        assert!(
            !requests[0]
                .1
                .contains("client_secret"),
            "{}",
            requests[0].1
        );
        assert!(
            form(&requests[1].1).contains(&("client_secret".to_string(), "s3cret:&=".to_string())),
            "{}",
            requests[1].1
        );
        assert!(
            !requests[1]
                .0
                .to_ascii_lowercase()
                .contains("authorization:"),
            "{}",
            requests[1].0
        );
    }

    #[test]
    fn a_revocation_request_marks_a_basic_authorization_header_sensitive() {
        let basic = provider(Some("http://127.0.0.1/revoke"), "client_secret_basic", Some("client-secret"));
        let post = provider(Some("http://127.0.0.1/revoke"), "client_secret_post", Some("client-secret"));
        let request = |provider: &CredentialProvider| {
            RevocationClient {
                endpoint: "http://127.0.0.1/revoke",
                provider,
                credential: ClientCredential::Secret(zeroize::Zeroizing::new("s3cret:&=".to_string())),
                http: reqwest::Client::new(),
            }
            .request("access-token", "access_token")
            .expect("the client's credential fits its method")
            .build()
            .unwrap()
        };

        let request_with_basic = request(&basic);
        let authorization = &request_with_basic.headers()[reqwest::header::AUTHORIZATION];
        let expected = base64::engine::general_purpose::STANDARD.encode("client+id:s3cret%3A%26%3D");
        assert_eq!(authorization, format!("Basic {expected}").as_str());
        assert!(authorization.is_sensitive(), "the Authorization header of a revocation request is not sensitive");
        assert_eq!(
            request_with_basic
                .body()
                .and_then(reqwest::Body::as_bytes),
            Some(b"token=access-token&token_type_hint=access_token".as_slice())
        );

        let request_with_post = request(&post);
        assert!(
            request_with_post
                .headers()
                .get(reqwest::header::AUTHORIZATION)
                .is_none(),
            "a form body client sends no Authorization header"
        );
    }

    /// A `private_key_jwt` client signs a new assertion for each request with
    /// the shared assertion code: issuer and subject its client id, audience
    /// its issuer, never a `jwt_audience` nor the token endpoint, and a `jti`
    /// of its own, its key read only from the provider's own tenant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_private_key_jwt_client_signs_a_new_assertion_for_each_request() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let key = crate::delegation_vault::jwt_assertion::test_keys::rsa_pkcs8();
        for (secret_id, tenant) in
            [("signing-key", Some("tenant-a")), ("other-tenant-key", Some("tenant-b")), ("untenanted-key", None)]
        {
            secrets
                .create(crate::secrets::CreateSecretRequest {
                    tenant_id: tenant.map(str::to_string),
                    name: secret_id.to_string(),
                    secret_id: secret_id.to_string(),
                    description: None,
                    value: key.private_pem.clone(),
                    secret_type: "General".to_string(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        let server = RecordingServer::start(200).await;
        let mut signing = provider(Some(&server.url), "private_key_jwt", None);
        signing.token_endpoint = Some("https://203.0.113.10/token".to_string());
        signing.jwt.jwt_audience = Some("https://honest.example/token".to_string());
        signing
            .jwt
            .jwt_signing_key_secret_ref = Some("signing-key".to_string());
        assert_eq!(
            revoke(&signing, &grant(true), Some(&secrets), Some(&server.origin()))
                .await
                .outcome,
            RevocationOutcome::Revoked
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        let mut ids = std::collections::HashSet::new();
        for (head, body) in &requests {
            assert!(
                !head
                    .to_ascii_lowercase()
                    .contains("authorization:"),
                "{head}"
            );
            let fields = form(body);
            assert!(fields.contains(&("client_id".to_string(), "client id".to_string())), "{body}");
            assert!(fields.contains(&(
                "client_assertion_type".to_string(),
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string()
            )));
            let assertion = fields
                .iter()
                .find(|(name, _)| name == "client_assertion")
                .map(|(_, value)| value.clone())
                .expect("a client assertion");
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::PS256);
            validation.set_audience(&["https://203.0.113.10"]);
            let claims = jsonwebtoken::decode::<serde_json::Value>(
                &assertion,
                &jsonwebtoken::DecodingKey::from_rsa_pem(key.public_pem.as_bytes()).unwrap(),
                &validation,
            )
            .expect("signed with the provider's key")
            .claims;
            assert_eq!(claims["iss"], "client id");
            assert_eq!(claims["sub"], "client id");
            ids.insert(
                claims["jti"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }
        assert_eq!(ids.len(), 2, "each request has an assertion of its own");

        for (other, case) in
            [("other-tenant-key", "another tenant's key is never used"), ("untenanted-key", "nor an untenanted one")]
        {
            signing
                .jwt
                .jwt_signing_key_secret_ref = Some(other.to_string());
            assert_eq!(
                revoke(&signing, &grant(false), Some(&secrets), Some(&server.origin()))
                    .await
                    .outcome,
                RevocationOutcome::ClientUnavailable,
                "{case}"
            );
        }
        assert_eq!(server.requests().len(), 2);
    }

    /// An external consent provider's client secret is read only from the
    /// provider's own tenant: an untenanted operator secret is never sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_untenanted_client_secret_is_never_sent_for_a_tenants_provider() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, None).await;
        let server = RecordingServer::start(200).await;
        let tenants = provider(Some(&server.url), "client_secret_post", Some("client-secret"));
        assert_eq!(
            revoke(&tenants, &grant(false), Some(&secrets), Some(&server.origin()))
                .await
                .outcome,
            RevocationOutcome::ClientUnavailable
        );
        assert!(server.requests().is_empty());

        let mut operators = tenants;
        operators.tenant_id = None;
        assert_eq!(
            revoke(&operators, &grant(false), Some(&secrets), Some(&server.origin()))
                .await
                .outcome,
            RevocationOutcome::Revoked,
            "an untenanted provider uses an untenanted secret"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_without_a_refresh_token_revokes_its_access_token() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let revocation =
            revoke(&provider(Some(&server.url), "none", None), &grant(false), Some(&secrets), Some(&server.origin()))
                .await;
        assert_eq!(revocation, GrantRevocation::failed(RevocationOutcome::Revoked));
        assert_eq!(server.requests().len(), 1);
        let fields = form(&server.requests()[0].1);
        assert!(fields.contains(&("token".to_string(), "access-token".to_string())));
        assert!(fields.contains(&("token_type_hint".to_string(), "access_token".to_string())));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_failure_is_an_outcome_and_none_leaves_the_gateway_unguarded() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-b")).await;
        let refusing = RecordingServer::start(400).await;
        assert_eq!(
            revoke(
                &provider(Some(&refusing.url), "none", None),
                &grant(true),
                Some(&secrets),
                Some(&refusing.origin())
            )
            .await,
            GrantRevocation {
                outcome: RevocationOutcome::Refused,
                access_token: Some(RevocationOutcome::Refused),
                reason: None,
            }
        );
        assert_eq!(
            revoke(&provider(None, "none", None), &grant(true), Some(&secrets), None).await,
            GrantRevocation::failed(RevocationOutcome::NotSupported)
        );
        let before = refusing.requests().len();
        assert_eq!(
            revoke(
                &provider(Some(&refusing.url), "client_secret_post", Some("client-secret")),
                &grant(true),
                Some(&secrets),
                Some(&refusing.origin())
            )
            .await
            .outcome,
            RevocationOutcome::ClientUnavailable,
            "another tenant's secret is never sent"
        );
        assert_eq!(
            revoke(&provider(Some(&refusing.url), "none", None), &grant(true), Some(&secrets), None)
                .await
                .outcome,
            RevocationOutcome::Unreachable,
            "a loopback http endpoint is refused without the test allowlist"
        );
        assert_eq!(refusing.requests().len(), before);
        assert_eq!(
            revoke(
                &provider(Some("http://127.0.0.1:1/revoke"), "none", None),
                &grant(true),
                Some(&secrets),
                Some("http://127.0.0.1:1")
            )
            .await
            .outcome,
            RevocationOutcome::Unreachable
        );
    }

    /// A secrets store whose reads never answer.
    struct HangingSecrets;

    #[async_trait::async_trait]
    impl SecretsStore for HangingSecrets {
        async fn create(
            &self,
            _request: crate::secrets::CreateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            unreachable!("no secret is created")
        }

        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<crate::secrets::Secret>> {
            std::future::pending().await
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            std::future::pending().await
        }

        async fn update(
            &self,
            _id: &str,
            _request: crate::secrets::UpdateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            unreachable!("no secret is updated")
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            unreachable!("no secret is deleted")
        }

        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            unreachable!("no secret is searched")
        }
    }

    /// A grant's revocation at its vendor ends within a fixed time wherever
    /// it hangs, here before any request, and is audited as unreachable.
    #[tokio::test(start_paused = true)]
    async fn a_revocation_that_hangs_ends_as_unreachable_after_a_fixed_time() {
        let secrets: Arc<dyn SecretsStore> = Arc::new(HangingSecrets);
        let confidential = provider(Some("https://203.0.113.10/revoke"), "client_secret_post", Some("client-secret"));
        let started = tokio::time::Instant::now();
        let (revocation, events) = crate::audit::producer::capture(async {
            tokio::time::timeout(
                Duration::from_secs(600),
                revoke_grant(&confidential, &grant(true), Some(&secrets), None, None),
            )
            .await
            .expect("the revocation ends")
        })
        .await;
        assert_eq!(revocation, GrantRevocation::failed(RevocationOutcome::Unreachable));
        assert!(started.elapsed() <= Duration::from_secs(60), "{:?}", started.elapsed());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:unreachable"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_is_audited_with_its_outcome_and_its_actor() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let provider = provider(Some(&server.url), "none", None);
        let grant = grant(true);
        let actor = actor();
        let (revocation, events) = crate::audit::producer::capture(async {
            revoke_grant(&provider, &grant, Some(&secrets), Some(&server.origin()), Some(&actor)).await
        })
        .await;
        assert_eq!(revocation.outcome, RevocationOutcome::Revoked);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].event, super::super::audit::DelegationAuditAction::TokenRevoked));
        assert_eq!(events[0].token_id.as_deref(), Some(grant.id.as_str()));
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:revoked,access_token:revoked"));
        let caller = events[0]
            .caller
            .as_ref()
            .expect("the audit names the actor");
        assert_eq!(caller.sub.as_deref(), Some("operator"));
        assert_eq!(caller.token_id.as_deref(), Some("pat-1"));
        assert!(!format!("{:?}", events[0]).contains("access-token"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_log_says_what_became_of_a_revocation() {
        use crate::component_tests::helpers::formatted_logs::FormattedLogs;
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let refusing = RecordingServer::start(400).await;
        let accepting = RecordingServer::start(200).await;

        let logs = FormattedLogs::capture();
        revoke_grant(
            &provider(Some(&refusing.url), "none", None),
            &grant(true),
            Some(&secrets),
            Some(&refusing.origin()),
            None,
        )
        .await;
        let refused = logs.text();
        assert!(refused.contains("WARN"), "{refused}");
        assert!(refused.contains("could not be revoked"), "{refused}");
        assert!(!refused.contains("Revoked a delegated grant"), "{refused}");

        let logs = FormattedLogs::capture();
        revoke_grant(
            &provider(Some(&accepting.url), "none", None),
            &grant(true),
            Some(&secrets),
            Some(&accepting.origin()),
            None,
        )
        .await;
        let revoked = logs.text();
        assert!(revoked.contains("INFO"), "{revoked}");
        assert!(revoked.contains("Revoked a delegated grant"), "{revoked}");
    }

    async fn vault_with(
        directory: &tempfile::TempDir,
        count: usize,
    ) -> (Arc<dyn DelegationVaultStorage>, Vec<DelegatedGrant>) {
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
            enabled: true,
            key_env_var: "AG_TEST_MASTER_KEY".to_string(),
            ..Default::default()
        })
        .unwrap();
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
            super::super::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let mut grants = Vec::new();
        for index in 0..count {
            let key =
                GrantKey::caller(Some("tenant-a"), "surface", "hop", "provider", &format!("{index:064x}")).unwrap();
            grants.push(
                vault
                    .store_grant(crate::delegation_vault::grants::tests::grant(&key, &format!("access-{index}")))
                    .await
                    .unwrap()
                    .grant,
            );
        }
        (vault, grants)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn removing_many_grants_revokes_them_at_once_and_deletes_each() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let server = RecordingServer::start_answering(vec![Answer::status(200).held(&gate)]).await;
        let (vault, grants) = vault_with(&directory, REVOCATION_CONCURRENCY).await;
        let revoker = Revoker {
            providers: HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]),
            secrets: Some(secrets),
            exact_allowlist: Some(server.origin()),
            actor: Some(actor()),
            vault: Some(vault.clone()),
        };

        let revocations = delete_then_revoke(&vault, grants, revoker, (), None)
            .await
            .unwrap();
        let _ = tokio::time::timeout(REVOCATION_TIMEOUT / 2, async {
            while server.requests().len() < REVOCATION_CONCURRENCY {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        let in_flight: Vec<String> = server
            .requests()
            .iter()
            .take(REVOCATION_CONCURRENCY)
            .filter_map(|(_, body)| {
                url::form_urlencoded::parse(body.as_bytes())
                    .find(|(name, _)| name == "token_type_hint")
                    .map(|(_, hint)| hint.into_owned())
            })
            .collect();
        assert_eq!(
            in_flight,
            vec!["refresh_token"; REVOCATION_CONCURRENCY],
            "every grant's first revocation is in flight before any is answered"
        );
        gate.add_permits(2 * REVOCATION_CONCURRENCY);
        tokio::time::timeout(Duration::from_secs(60), revocations)
            .await
            .expect("the revocations end")
            .unwrap();
        assert_eq!(server.revoked_tokens().len(), 2 * REVOCATION_CONCURRENCY);
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Removing grants deletes them first, which ends their release at once,
    /// and revokes them on a task of their own: the caller never waits on a
    /// vendor, however slow.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn removed_grants_are_deleted_at_once_and_revoked_in_the_background() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let delay = Duration::from_secs(2);
        let server = RecordingServer::start_with_delay(200, delay).await;
        let (vault, grants) = vault_with(&directory, 3).await;
        let revoker = Revoker {
            providers: HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]),
            secrets: Some(secrets),
            exact_allowlist: Some(server.origin()),
            actor: Some(actor()),
            vault: None,
        };

        let started = std::time::Instant::now();
        let revocations = delete_then_revoke(&vault, grants, revoker, (), None)
            .await
            .unwrap();
        assert!(started.elapsed() < delay / 2, "the removal waited on the vendor: {:?}", started.elapsed());
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap()
                .is_empty(),
            "the grants are deleted before any revocation ends"
        );
        tokio::time::timeout(delay * 4, revocations)
            .await
            .expect("the revocations end")
            .unwrap();
        assert_eq!(server.revoked_tokens().len(), 6);
    }

    /// Removal revokes the grant the vault deleted, not a copy read before
    /// it: a grant rotated in between, as a refresh that rotates its refresh
    /// token would, has its new tokens revoked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_rotated_after_it_was_read_has_its_new_tokens_revoked() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let (vault, read) = vault_with(&directory, 1).await;
        let mut rotated = read[0].clone();
        rotated.access_token = "rotated-access".to_string();
        rotated.refresh_token = Some("rotated-refresh".to_string());
        vault
            .store_grant(rotated)
            .await
            .unwrap();
        let revoker = Revoker {
            providers: HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]),
            secrets: Some(secrets),
            exact_allowlist: Some(server.origin()),
            actor: None,
            vault: None,
        };

        let revocations = delete_then_revoke(&vault, read, revoker, (), None)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), revocations)
            .await
            .expect("the revocations end")
            .unwrap();
        assert_eq!(server.revoked_tokens(), ["rotated-access", "rotated-refresh"]);
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Without a secrets store a client that authenticates with a secret cannot
    /// revoke, so the grant is removed unrevoked and the audit says why; a
    /// public client still revokes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn without_a_secrets_store_a_confidential_clients_revocation_is_skipped_and_audited() {
        let server = RecordingServer::start(200).await;
        let confidential = provider(Some(&server.url), "client_secret_post", Some("client-secret"));
        let grant = grant(true);
        let (revocation, events) = crate::audit::producer::capture(async {
            revoke_grant(&confidential, &grant, None, Some(&server.origin()), Some(&actor())).await
        })
        .await;
        assert_eq!(revocation.outcome, RevocationOutcome::Skipped);
        assert!(server.requests().is_empty());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:skipped,reason:no_secrets_store"));
        assert_eq!(
            events[0]
                .caller
                .as_ref()
                .and_then(|caller| caller.sub.as_deref()),
            Some("operator")
        );

        let public = provider(Some(&server.url), "none", None);
        assert_eq!(
            revoke_grant(&public, &grant, None, Some(&server.origin()), None)
                .await
                .outcome,
            RevocationOutcome::Revoked
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_removed_grant_whose_provider_is_gone_is_audited_as_skipped() {
        let revoker = Revoker {
            providers: HashMap::new(),
            secrets: None,
            exact_allowlist: None,
            actor: None,
            vault: None,
        };
        let ((), events) = crate::audit::producer::capture(revoke_removed(vec![grant(true)], revoker)).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:skipped,reason:provider_missing"));
        assert_eq!(events[0].token_id.as_deref(), Some(grant(true).id.as_str()));
    }

    /// A vault that forwards to another, counting how often a provider's
    /// grants are listed, and failing to list them while `outage` is set, as
    /// during a key service throttle.
    struct ListingVault {
        inner: Arc<dyn DelegationVaultStorage>,
        listings: std::sync::atomic::AtomicUsize,
        outage: std::sync::atomic::AtomicBool,
    }

    impl ListingVault {
        fn new(inner: Arc<dyn DelegationVaultStorage>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                listings: Default::default(),
                outage: Default::default(),
            })
        }
    }

    #[async_trait::async_trait]
    impl DelegationVaultStorage for ListingVault {
        async fn store(
            &self,
            token: crate::delegation_vault::DelegationToken,
        ) -> anyhow::Result<crate::delegation_vault::DelegationToken> {
            self.inner.store(token).await
        }

        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<crate::delegation_vault::DelegationToken>> {
            self.inner.get(id).await
        }

        async fn lookup(
            &self,
            agent_did: &str,
            user_identity_hash: &str,
            provider_id: &str,
        ) -> anyhow::Result<crate::delegation_vault::VaultLookupResult> {
            self.inner
                .lookup(agent_did, user_identity_hash, provider_id)
                .await
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::delegation_vault::DelegationToken>> {
            self.inner.list_all().await
        }

        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<bool> {
            self.inner.delete(id).await
        }

        async fn delete_by_user(
            &self,
            user_identity_hash: &str,
        ) -> anyhow::Result<usize> {
            self.inner
                .delete_by_user(user_identity_hash)
                .await
        }

        async fn update(
            &self,
            token: crate::delegation_vault::DelegationToken,
        ) -> anyhow::Result<crate::delegation_vault::DelegationToken> {
            self.inner.update(token).await
        }

        async fn mark_used(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.inner.mark_used(id).await
        }

        async fn provider_grants(
            &self,
            credential_provider_id: &str,
        ) -> anyhow::Result<Vec<DelegatedGrant>> {
            self.listings
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self
                .outage
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                anyhow::bail!("the key service is throttled");
            }
            self.inner
                .provider_grants(credential_provider_id)
                .await
        }

        async fn defer_revocation(
            &self,
            grant: DelegatedGrant,
            provider: Option<CredentialProvider>,
        ) -> anyhow::Result<()> {
            self.inner
                .defer_revocation(grant, provider)
                .await
        }

        async fn deferred_revocations(
            &self
        ) -> anyhow::Result<Vec<crate::delegation_vault::storage::DeferredRevocation>> {
            self.inner
                .deferred_revocations()
                .await
        }

        async fn every_deferred_revocation(
            &self
        ) -> anyhow::Result<Vec<crate::delegation_vault::storage::DeferredRevocation>> {
            self.inner
                .every_deferred_revocation()
                .await
        }

        async fn forget_deferred_revocation(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.inner
                .forget_deferred_revocation(id)
                .await
        }
    }

    /// A grant of `key`, holding `access`, for the vendor account `account`.
    fn account_grant(
        key: &GrantKey,
        access: &str,
        account: Option<&str>,
    ) -> DelegatedGrant {
        let mut grant = crate::delegation_vault::grants::tests::grant(key, access);
        grant.id = key.record_id();
        grant.vendor_subject = account.map(str::to_string);
        grant
    }

    /// At a provider whose revocation ends the whole authorization of the
    /// vendor account that consented, a removed grant is not revoked while
    /// another grant of that account, as its ID token named it, is stored,
    /// whoever holds it: the same account connected on another surface, or
    /// by another caller; the audit says why. A grant of an account no other
    /// grant shares is revoked, though its caller holds other grants, and so
    /// is one whose account is not known, the safe default. Without the
    /// flag, every removed grant is revoked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shared_authorization_is_not_revoked_while_another_grant_of_its_vendor_account_is_stored() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let (vault, _) = vault_with(&directory, 0).await;
        let person = "a".repeat(64);
        let other = "b".repeat(64);
        let key = |surface: &str, principal: &str| {
            GrantKey::caller(Some("tenant-a"), surface, "hop", "provider", principal).unwrap()
        };
        let store = |surface: &'static str, principal: String, token: &'static str, account: Option<&'static str>| {
            let vault = vault.clone();
            async move {
                vault
                    .store_grant(account_grant(&key(surface, &principal), token, account))
                    .await
                    .unwrap();
            }
        };
        store("surface", person.clone(), "here", Some("account-1")).await;
        store("other-surface", other.clone(), "there", Some("account-1")).await;
        store("surface", other.clone(), "theirs", Some("account-2")).await;
        store("other-surface", person.clone(), "unknown", None).await;
        let mut flagged = provider(Some(&server.url), "none", None);
        flagged.revocation_ends_authorization = true;
        let unflagged = provider(Some(&server.url), "none", None);
        let revoked = |tokens: &[&str]| {
            let mut expected: Vec<String> = tokens
                .iter()
                .flat_map(|token| [token.to_string(), format!("{token}-refresh")])
                .collect();
            expected.sort();
            expected
        };
        let remove = |surface: &'static str, principal: String, provider: CredentialProvider| {
            let vault = vault.clone();
            let revoker = Revoker {
                providers: HashMap::from([("provider".to_string(), provider)]),
                secrets: Some(secrets.clone()),
                exact_allowlist: Some(server.origin()),
                actor: None,
                vault: Some(vault.clone()),
            };
            async move {
                let deleted = vault
                    .delete_grant(&key(surface, &principal).record_id())
                    .await
                    .unwrap()
                    .unwrap();
                crate::audit::producer::capture(revoke_removed(vec![deleted], revoker))
                    .await
                    .1
            }
        };

        let events = remove("surface", person.clone(), flagged.clone()).await;
        assert!(
            server
                .revoked_tokens()
                .is_empty(),
            "{:?}",
            server.revoked_tokens()
        );
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:skipped,reason:authorization_in_use"));

        remove("surface", other.clone(), flagged.clone()).await;
        assert_eq!(
            server.revoked_tokens(),
            revoked(&["theirs"]),
            "a grant of an account no other grant shares is revoked, though its caller holds another grant"
        );

        remove("other-surface", person.clone(), flagged.clone()).await;
        assert_eq!(
            server.revoked_tokens(),
            revoked(&["theirs", "unknown"]),
            "so is a grant whose account is not known"
        );

        remove("other-surface", other.clone(), flagged).await;
        assert_eq!(server.revoked_tokens(), revoked(&["theirs", "unknown", "there"]), "and the account's last grant");

        store("surface", person.clone(), "again", Some("account-1")).await;
        store("other-surface", person.clone(), "again-too", Some("account-1")).await;
        remove("surface", person.clone(), unflagged).await;
        assert_eq!(
            server.revoked_tokens(),
            revoked(&["theirs", "unknown", "there", "again"]),
            "without the flag every grant is revoked"
        );
    }

    /// When the vault cannot tell whether another grant of the vendor account
    /// is stored, as during a key service outage, the removed grant is kept,
    /// encrypted, for the daily sweep, which revokes it once it can tell that
    /// none is: a revocation is delayed, never skipped for good.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_the_vault_cannot_decide_is_left_to_the_sweep() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let (inner, _) = vault_with(&directory, 0).await;
        let vault = ListingVault::new(inner);
        vault
            .outage
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut flagged = provider(Some(&server.url), "none", None);
        flagged.revocation_ends_authorization = true;
        let revoker = Revoker {
            providers: HashMap::from([("provider".to_string(), flagged)]),
            secrets: Some(secrets),
            exact_allowlist: Some(server.origin()),
            actor: None,
            vault: Some(vault.clone()),
        };
        let key = GrantKey::owner(Some("tenant-a"), "surface", "hop", "provider");
        let ((), events) = crate::audit::producer::capture(revoke_removed(
            vec![account_grant(&key, "removed", Some("account-1"))],
            revoker.clone(),
        ))
        .await;
        assert!(server.requests().is_empty());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:skipped,reason:deferred"));
        let deferred = vault
            .deferred_revocations()
            .await
            .unwrap();
        assert_eq!(deferred.len(), 1);
        assert!(!format!("{deferred:?}").contains("removed"), "a deferred revocation's Debug hides its tokens");

        let now = chrono::Utc::now();
        assert_eq!(revoke_deferred(revoker.clone(), now).await, 0, "the outage lasts");
        assert!(server.requests().is_empty());
        vault
            .outage
            .store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(revoke_deferred(revoker.clone(), now).await, 1);
        assert_eq!(server.revoked_tokens(), ["removed", "removed-refresh"]);

        vault
            .outage
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let key = GrantKey::owner(Some("tenant-a"), "surface", "other-hop", "provider");
        revoke_removed(vec![account_grant(&key, "overdue", Some("account-2"))], revoker.clone()).await;
        assert_eq!(revoke_deferred(revoker.clone(), chrono::Utc::now()).await, 0);
        let later = chrono::Utc::now() + chrono::Duration::days(DEFERRED_REVOCATION_DAYS);
        assert_eq!(
            revoke_deferred(revoker, later).await,
            1,
            "one the vault still cannot tell about after thirty days is revoked all the same"
        );
        assert_eq!(server.revoked_tokens(), ["overdue", "overdue-refresh", "removed", "removed-refresh"]);
        assert!(
            vault
                .deferred_revocations()
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A deleted provider's kept revocation is revoked even while the vault
    /// cannot tell whether another grant holds its vendor account: with the
    /// provider and all its grants deleted, none can.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deleted_providers_kept_revocation_is_revoked_while_the_vault_cannot_tell() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let (inner, _) = vault_with(&directory, 0).await;
        let vault = ListingVault::new(inner);
        vault
            .outage
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut flagged = provider(Some(&server.url), "none", None);
        flagged.revocation_ends_authorization = true;
        let revoker = Revoker {
            providers: HashMap::from([("provider".to_string(), flagged)]),
            secrets: Some(secrets),
            exact_allowlist: Some(server.origin()),
            actor: None,
            vault: Some(vault.clone()),
        };
        let key = GrantKey::owner(Some("tenant-a"), "surface", "hop", "provider");
        revoke_removed(vec![account_grant(&key, "removed", Some("account-1"))], revoker.clone()).await;
        let kept = kept_revocations_of(&(vault.clone() as Arc<dyn DelegationVaultStorage>), "provider")
            .await
            .unwrap();
        assert_eq!(kept.len(), 1);

        assert_eq!(
            decide_kept(&(vault.clone() as Arc<dyn DelegationVaultStorage>), kept, &revoker, chrono::Utc::now(), true)
                .await,
            1
        );

        assert_eq!(server.revoked_tokens(), ["removed", "removed-refresh"]);
        assert!(
            vault
                .deferred_revocations()
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// Whether the vendor accounts of a batch of removed grants hold another
    /// grant is read once for the batch, not once for each grant, so removing
    /// many grants never floods the key service.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_grants_in_use_are_read_once_for_a_batch_of_removals() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let (inner, _) = vault_with(&directory, 0).await;
        let vault = ListingVault::new(inner);
        let mut flagged = provider(Some(&server.url), "none", None);
        flagged.revocation_ends_authorization = true;
        let removed: Vec<DelegatedGrant> = (0..5)
            .map(|index| {
                let key =
                    GrantKey::caller(Some("tenant-a"), "surface", "hop", "provider", &format!("{index:064x}")).unwrap();
                account_grant(&key, &format!("removed-{index}"), Some(&format!("account-{index}")))
            })
            .collect();
        revoke_removed(
            removed,
            Revoker {
                providers: HashMap::from([("provider".to_string(), flagged)]),
                secrets: Some(secrets),
                exact_allowlist: Some(server.origin()),
                actor: None,
                vault: Some(vault.clone()),
            },
        )
        .await;
        assert_eq!(
            vault
                .listings
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(server.revoked_tokens().len(), 10);
    }

    /// Tokens a connect or a refresh obtained but no grant keeps are revoked,
    /// and audited as such (`unkept_tokens`): the record names the id of a
    /// grant that may still be connected, which must not read as a
    /// disconnect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unkept_tokens_are_audited_as_such() {
        let server = RecordingServer::start(200).await;
        let revoker = Revoker {
            providers: HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]),
            secrets: None,
            exact_allowlist: Some(server.origin()),
            actor: None,
            vault: None,
        };
        let ((), events) = crate::audit::producer::capture(revoke_unkept(vec![grant(true)], revoker)).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:revoked,access_token:revoked,unkept_tokens"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_whose_provider_is_gone_is_deleted_without_revocation() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let (vault, grants) = vault_with(&directory, 2).await;
        let revoker = Revoker {
            providers: HashMap::new(),
            secrets: Some(secrets),
            exact_allowlist: Some(server.origin()),
            actor: None,
            vault: Some(vault.clone()),
        };
        delete_then_revoke(&vault, grants, revoker, (), None)
            .await
            .unwrap()
            .await
            .unwrap();
        assert!(server.requests().is_empty());
        assert!(
            vault
                .provider_grants("provider")
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// The pending revocations a vault keeps, in a vault opened again on the
    /// same directory, as a restarted gateway opens it.
    async fn pending_after_restart(directory: &tempfile::TempDir) -> Vec<super::super::storage::DeferredRevocation> {
        let reopened = super::super::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
            .await
            .unwrap();
        reopened
            .deferred_revocations()
            .await
            .unwrap()
            .into_iter()
            .filter(|revocation| revocation.deferral == super::super::storage::Deferral::Pending)
            .collect()
    }

    /// A revocation in flight when the gateway stops is kept, encrypted, so
    /// the gateway tries it again when it starts, and forgets it once it
    /// reached the vendor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_revocation_in_flight_when_the_gateway_stops_is_tried_again_when_it_starts() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let hanging = RecordingServer::start_with_delay(200, Duration::from_secs(60)).await;
        let (vault, grants) = vault_with(&directory, 1).await;
        let revoker = |server: &RecordingServer, vault: Arc<dyn DelegationVaultStorage>| Revoker {
            providers: HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]),
            secrets: Some(secrets.clone()),
            exact_allowlist: Some(server.origin()),
            actor: None,
            vault: Some(vault),
        };
        let revocations = delete_then_revoke(&vault, grants, revoker(&hanging, vault.clone()), (), None)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while hanging.requests().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the revocation reaches the vendor");
        revocations.abort();
        let _ = revocations.await;

        let kept = pending_after_restart(&directory).await;
        assert_eq!(kept.len(), 1, "the revocation in flight is kept");
        let file = std::fs::read_dir(
            directory
                .path()
                .join("vault")
                .join(super::super::storage::DEFERRED_REVOCATIONS_DIRECTORY),
        )
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.to_string_lossy()
                .contains(&kept[0].id)
        })
        .expect("in a file of its own");
        assert!(!String::from_utf8_lossy(&std::fs::read(&file).unwrap()).contains("access-0"), "never in plaintext");

        let restarted: Arc<dyn DelegationVaultStorage> = Arc::new(
            super::super::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap(),
        );
        let answering = RecordingServer::start(200).await;
        let (decided, events) =
            crate::audit::producer::capture(revoke_pending(revoker(&answering, restarted.clone()))).await;
        assert_eq!(decided, 1);
        assert_eq!(answering.revoked_tokens(), ["access-0", "access-0-refresh"]);
        assert_eq!(events.len(), 1, "one audit record for the outcome");
        assert_eq!(events[0].detail.as_deref(), Some("vendor_revocation:revoked,access_token:revoked"));
        assert!(
            pending_after_restart(&directory)
                .await
                .is_empty(),
            "and it is forgotten"
        );
    }

    /// A grant deleted for a change still being saved when the gateway stops
    /// is kept as a pending revocation already, so it is revoked when the
    /// gateway starts; one the change puts back is forgotten unrevoked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_grant_deleted_while_its_change_is_saved_is_kept_until_the_outcome() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let (vault, grants) = vault_with(&directory, 2).await;
        let revoker = Revoker {
            providers: HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]),
            secrets: Some(secrets),
            exact_allowlist: Some(server.origin()),
            actor: None,
            vault: Some(vault.clone()),
        };
        let (saved, outcome) = tokio::sync::oneshot::channel::<bool>();
        let removal = delete_then_revoke(
            &vault,
            vec![grants[0].clone()],
            revoker.clone(),
            (),
            Some(ChangeOutcome {
                saved: outcome,
                stored: Box::pin(std::future::pending()),
                kept: Vec::new(),
                provider_gone: false,
            }),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while pending_after_restart(&directory)
                .await
                .is_empty()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the deleted grant is kept while the change is saved");
        removal.abort();
        let _ = removal.await;
        drop(saved);
        assert_eq!(revoke_pending(revoker.clone()).await, 1);
        assert_eq!(server.revoked_tokens(), ["access-0", "access-0-refresh"]);

        let (saved, outcome) = tokio::sync::oneshot::channel::<bool>();
        let removal = delete_then_revoke(
            &vault,
            vec![grants[1].clone()],
            revoker.clone(),
            (),
            Some(ChangeOutcome {
                saved: outcome,
                stored: Box::pin(std::future::pending()),
                kept: Vec::new(),
                provider_gone: false,
            }),
        )
        .await
        .unwrap();
        saved.send(false).unwrap();
        removal.await.unwrap();
        assert!(
            vault
                .grant_by_id(&grants[1].id)
                .await
                .unwrap()
                .is_some(),
            "a change not saved puts its grant back"
        );
        assert!(
            pending_after_restart(&directory)
                .await
                .is_empty(),
            "and forgets its pending revocation"
        );
        assert_eq!(server.revoked_tokens().len(), 2, "unrevoked");
    }

    /// A pending revocation that cannot reach its vendor is kept and tried
    /// again, each attempt audited, until it has been tried
    /// [`PENDING_REVOCATION_ATTEMPTS`] times; then it is forgotten.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pending_revocation_that_cannot_reach_its_vendor_is_tried_a_bounded_number_of_times() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let (vault, grants) = vault_with(&directory, 1).await;
        let revoker = Revoker {
            providers: HashMap::from([(
                "provider".to_string(),
                provider(Some("http://127.0.0.1:1/revoke"), "none", None),
            )]),
            secrets: Some(secrets),
            exact_allowlist: Some("http://127.0.0.1:1".to_string()),
            actor: None,
            vault: Some(vault.clone()),
        };
        let ((), first) = crate::audit::producer::capture(async {
            delete_then_revoke(&vault, grants, revoker.clone(), (), None)
                .await
                .unwrap()
                .await
                .unwrap();
        })
        .await;
        assert_eq!(
            first
                .iter()
                .filter_map(|event| event.detail.as_deref())
                .collect::<Vec<_>>(),
            ["vendor_revocation:unreachable,access_token:unreachable,retry:pending"]
        );
        let kept = pending_after_restart(&directory).await;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].attempts, 1);

        for attempt in 2..=PENDING_REVOCATION_ATTEMPTS {
            let (decided, events) = crate::audit::producer::capture(revoke_pending(revoker.clone())).await;
            assert_eq!(decided, 1, "attempt {attempt}");
            let expected = if attempt == PENDING_REVOCATION_ATTEMPTS {
                "vendor_revocation:unreachable,access_token:unreachable,retry:exhausted"
            } else {
                "vendor_revocation:unreachable,access_token:unreachable,retry:pending"
            };
            assert_eq!(events[0].detail.as_deref(), Some(expected), "attempt {attempt}");
        }
        assert!(
            pending_after_restart(&directory)
                .await
                .is_empty(),
            "it is tried no more"
        );
        let (decided, events) = crate::audit::producer::capture(revoke_pending(revoker)).await;
        assert_eq!((decided, events.len()), (0, 0));
    }

    /// A revocation the sweep decides that cannot reach its vendor is kept as
    /// a pending one, its attempt counted, rather than forgotten: a deferred
    /// revocation is delayed, never lost.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_decided_revocation_that_cannot_reach_its_vendor_is_kept_pending() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let (vault, _) = vault_with(&directory, 0).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "hop", "provider");
        vault
            .defer_revocation(account_grant(&key, "deferred", Some("account-1")), None)
            .await
            .unwrap();
        let revoker = Revoker {
            providers: HashMap::from([(
                "provider".to_string(),
                provider(Some("http://127.0.0.1:1/revoke"), "none", None),
            )]),
            secrets: Some(secrets),
            exact_allowlist: Some("http://127.0.0.1:1".to_string()),
            actor: None,
            vault: Some(vault.clone()),
        };
        let (decided, events) = crate::audit::producer::capture(revoke_deferred(revoker, chrono::Utc::now())).await;
        assert_eq!(decided, 1);
        assert_eq!(
            events
                .iter()
                .filter_map(|event| event.detail.as_deref())
                .collect::<Vec<_>>(),
            ["vendor_revocation:unreachable,access_token:unreachable,retry:pending"]
        );
        let kept = pending_after_restart(&directory).await;
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].attempts, 1);
        assert_eq!(kept[0].grant.access_token, "deferred");
        assert_eq!(
            vault
                .deferred_revocations()
                .await
                .unwrap()
                .len(),
            1,
            "the deferred record became the pending one"
        );
    }

    /// A pending revocation whose grant the vault holds again, as one put
    /// back or kept, is forgotten without revoking it: a revocation never ends
    /// a connection in use.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pending_revocation_of_a_grant_held_again_is_forgotten_unrevoked() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let server = RecordingServer::start(200).await;
        let (vault, grants) = vault_with(&directory, 1).await;
        let kept = super::super::storage::DeferredRevocation::new(
            grants[0].clone(),
            chrono::Utc::now(),
            super::super::storage::Deferral::Pending,
        );
        vault
            .keep_revocation(&kept)
            .await
            .unwrap();
        let revoker = Revoker {
            providers: HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]),
            secrets: Some(secrets),
            exact_allowlist: Some(server.origin()),
            actor: None,
            vault: Some(vault.clone()),
        };
        assert_eq!(revoke_pending(revoker).await, 1);
        assert!(server.requests().is_empty(), "the grant is in use");
        assert!(
            pending_after_restart(&directory)
                .await
                .is_empty()
        );
    }

    /// Without at-rest encryption the vault keeps no revocation, so no token
    /// is ever written in plaintext; the grant is revoked all the same.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn without_encryption_no_revocation_is_kept() {
        let directory = tempfile::tempdir().unwrap();
        let (_, grants) = vault_with(&directory, 1).await;
        crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig::default()).unwrap();
        let plain = super::super::storage::FileSystemDelegationVaultStore::new(directory.path().join("plain"))
            .await
            .unwrap();
        let refused = plain
            .keep_revocation(&super::super::storage::DeferredRevocation::new(
                grants[0].clone(),
                chrono::Utc::now(),
                super::super::storage::Deferral::Pending,
            ))
            .await;
        assert!(refused.is_err());
        let directory = directory
            .path()
            .join("plain")
            .join(super::super::storage::DEFERRED_REVOCATIONS_DIRECTORY);
        let written = std::fs::read_dir(&directory).map_or(0, |entries| entries.count());
        assert_eq!(written, 0, "nothing is written");
    }

    /// A vendor that answers 429 or 5xx has not decided, so its revocation is
    /// kept and tried again, audited as `refused` all the same; any other
    /// refusal is final.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_vendor_that_answers_busy_keeps_the_revocation_pending_and_another_refusal_does_not() {
        for (status, retried) in [(429u16, true), (503, true), (400, false)] {
            let directory = tempfile::tempdir().unwrap();
            let secrets = secrets_with(&directory, Some("tenant-a")).await;
            let server = RecordingServer::start(status).await;
            let (vault, grants) = vault_with(&directory, 1).await;
            let revoker = Revoker {
                providers: HashMap::from([("provider".to_string(), provider(Some(&server.url), "none", None))]),
                secrets: Some(secrets),
                exact_allowlist: Some(server.origin()),
                actor: None,
                vault: Some(vault.clone()),
            };
            let ((), events) = crate::audit::producer::capture(async {
                delete_then_revoke(&vault, grants, revoker, (), None)
                    .await
                    .unwrap()
                    .await
                    .unwrap();
            })
            .await;
            let expected = if retried {
                "vendor_revocation:refused,access_token:refused,retry:pending"
            } else {
                "vendor_revocation:refused,access_token:refused"
            };
            assert_eq!(
                events
                    .iter()
                    .filter_map(|event| event.detail.as_deref())
                    .collect::<Vec<_>>(),
                [expected],
                "{status}"
            );
            assert_eq!(
                pending_after_restart(&directory)
                    .await
                    .len(),
                usize::from(retried),
                "{status}"
            );
        }
    }

    #[test]
    fn only_a_failure_that_may_pass_is_tried_again() {
        for (outcome, retried) in [
            (RevocationOutcome::Unreachable, true),
            (RevocationOutcome::RefusedForNow, true),
            (RevocationOutcome::ClientUnavailable, false),
            (RevocationOutcome::Refused, false),
            (RevocationOutcome::Revoked, false),
        ] {
            assert_eq!(GrantRevocation::failed(outcome).should_retry(), retried, "{outcome:?}");
        }
    }

    /// A pending revocation keeps the provider it was made with, so it can be
    /// decided once the provider is deleted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_revocation_kept_pending_keeps_the_provider_it_was_made_with() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = secrets_with(&directory, Some("tenant-a")).await;
        let (vault, grants) = vault_with(&directory, 1).await;
        let revoker = Revoker {
            providers: HashMap::from([(
                "provider".to_string(),
                provider(Some("http://127.0.0.1:1/revoke"), "none", None),
            )]),
            secrets: Some(secrets),
            exact_allowlist: Some("http://127.0.0.1:1".to_string()),
            actor: None,
            vault: Some(vault.clone()),
        };
        delete_then_revoke(&vault, grants, revoker, (), None)
            .await
            .unwrap()
            .await
            .unwrap();

        let kept = pending_after_restart(&directory).await;
        assert_eq!(kept.len(), 1);
        assert_eq!(
            kept[0]
                .provider
                .as_ref()
                .map(|provider| provider.id.as_str()),
            Some("provider")
        );
        assert_eq!(
            kept[0]
                .provider
                .as_ref()
                .and_then(|provider| provider
                    .revocation_endpoint
                    .as_deref()),
            Some("http://127.0.0.1:1/revoke")
        );
    }

    /// When the change deletes the provider itself, no other grant of it
    /// remains to share the vendor account's authorization, so the grants it
    /// removes are revoked rather than left to the daily sweep, which could
    /// no longer find their provider.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_grants_of_a_deleted_provider_are_revoked_without_asking_whether_another_holds_the_account() {
        for (provider_gone, revoked) in [(false, false), (true, true)] {
            let directory = tempfile::tempdir().unwrap();
            let secrets = secrets_with(&directory, Some("tenant-a")).await;
            let server = RecordingServer::start(200).await;
            let (vault, _) = vault_with(&directory, 0).await;
            let held = GrantKey::owner(Some("tenant-a"), "surface", "hop", "provider");
            let removed = GrantKey::owner(Some("tenant-a"), "other-surface", "hop", "provider");
            vault
                .store_grant(account_grant(&held, "held", Some("account-1")))
                .await
                .unwrap();
            let grant = vault
                .store_grant(account_grant(&removed, "removed", Some("account-1")))
                .await
                .unwrap()
                .grant;
            let mut flagged = provider(Some(&server.url), "none", None);
            flagged.revocation_ends_authorization = true;
            let revoker = Revoker {
                providers: HashMap::from([("provider".to_string(), flagged)]),
                secrets: Some(secrets),
                exact_allowlist: Some(server.origin()),
                actor: None,
                vault: Some(vault.clone()),
            };
            let (saved, outcome) = tokio::sync::oneshot::channel();
            let task = delete_then_revoke(
                &vault,
                vec![grant],
                revoker,
                (),
                Some(ChangeOutcome {
                    saved: outcome,
                    stored: Box::pin(std::future::pending()),
                    kept: Vec::new(),
                    provider_gone,
                }),
            )
            .await
            .unwrap();
            saved.send(true).unwrap();
            task.await.unwrap();

            assert_eq!(
                !server
                    .revoked_tokens()
                    .is_empty(),
                revoked,
                "provider_gone: {provider_gone}"
            );
        }
    }
}
