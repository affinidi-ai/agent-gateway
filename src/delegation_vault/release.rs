//! Releasing a grant by binding for one call.
//!
//! A grant is used while its access token is fresh. It is refreshed ahead of
//! expiry, once a minute or a tenth of its life is left, through a refresh
//! claimed once across every node sharing the vault; a call that finds a
//! refresh running uses the current token while it lasts, and otherwise waits
//! a few seconds for the refreshed one. The refresh runs on a task of its own,
//! so a call dropped meanwhile never leaves it half done. The rotated tokens
//! are written before the new access token is used.
//!
//! What cannot be released is refused with a fixed reason, never a URL or the
//! authorization server's words:
//!
//! - `connect_required`: there is no grant, it expired and cannot be
//!   refreshed, its refresh token was refused (`invalid_grant`, which deletes
//!   and revokes it), the authorization server refused its refresh otherwise
//!   as often as gateway.json's `external_consent_refresh_refusals` allows
//!   since it last succeeded (the grant is kept), or a refresh died part way,
//!   which may have spent the refresh token. For a caller's grant it carries a
//!   hint of the caller, so the system that runs the connect can tell whether
//!   the person who signs in is that caller.
//! - `scope_insufficient`: the vendor answered that the token lacks a scope.
//! - `connector_unavailable`: the grant cannot be read or refreshed for a
//!   reason a new connect would not fix, such as an unreachable token
//!   endpoint or a client the authorization server refused; the grant is kept
//!   and its refresh retried after a wait.
//!
//! An outcome about a grant only ever changes that grant: a refusal deletes
//! it only while it is still the version refused, so a grant the person
//! reconnected meanwhile is kept, and tokens a refresh obtained but did not
//! write are revoked, never dropped. Tokens whose write cannot be confirmed
//! may be the grant's, and are never revoked.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Weak};
use std::time::Duration;

use base64::Engine as _;
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::grants::{DelegatedGrant, FailedRefresh, GrantKey, ObtainedTokens};
use super::storage::{DelegationVaultStorage, RefreshError};
use super::token_endpoint::{TokenFailure, TokenRequest};
use crate::config::agent_surface::GrantSubject;
use crate::credential_providers::CredentialProvider;
use crate::secrets::SecretsStore;

/// How long a call that needs a refresh another call is running waits for it.
const REFRESH_WAIT: Duration = Duration::from_secs(10);
/// How long a call waiting for a refresh waits, at first, before it reads the
/// grant again when no refresh on this node wakes it, as when another node
/// runs the refresh; the wait doubles up to [`REFRESH_POLL_MAX`].
const REFRESH_POLL: Duration = Duration::from_millis(250);
const REFRESH_POLL_MAX: Duration = Duration::from_secs(2);

/// One notice per grant whose refresh a call on this node runs, held only
/// while a call runs or waits for it.
static REFRESH_NOTICES: LazyLock<std::sync::Mutex<HashMap<String, Weak<tokio::sync::Notify>>>> =
    LazyLock::new(Default::default);

/// The notice of grant `id`'s refresh on this node.
fn refresh_notice(id: &str) -> Arc<tokio::sync::Notify> {
    let mut notices = REFRESH_NOTICES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    notices.retain(|_, notice| notice.strong_count() > 0);
    match notices
        .get(id)
        .and_then(Weak::upgrade)
    {
        Some(notice) => notice,
        None => {
            let notice = Arc::new(tokio::sync::Notify::new());
            notices.insert(id.to_string(), Arc::downgrade(&notice));
            notice
        }
    }
}

/// Wakes the calls waiting for a grant's refresh when the call that runs it
/// is done with it, however it ends, dropped part way included.
struct RefreshDone(Arc<tokio::sync::Notify>);

impl Drop for RefreshDone {
    fn drop(&mut self) {
        self.0.notify_waiters();
    }
}

/// The label hashed with a caller's principal into a connect hint.
const CONNECT_HINT_LABEL: &[u8] = b"agent-gateway-connect-hint\n";

/// The largest request body a call whose grant the vendor refused is sent
/// again with. A larger one, such as an upload, is not sent twice: its grant
/// is refreshed, and the call answered `connector_unavailable`, so the caller
/// tries again with the fresh token.
pub const RETRY_BODY_LIMIT: usize = 1024 * 1024;

/// Why a grant by binding was not released, as the caller is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRefusal {
    /// The binding has no usable grant: someone must connect.
    ConnectRequired {
        subject: GrantSubject,
        /// For a caller's grant, [`connect_hint`] of the caller.
        hint: Option<String>,
    },
    /// The vendor answered that the token lacks a scope, named when its
    /// challenge named a plain one.
    ScopeInsufficient { scope: Option<String> },
    /// The grant cannot be used now, for a reason a new connect would not fix.
    ConnectorUnavailable,
}

impl GrantRefusal {
    /// `connect_required` for the binding of `key`, whose subject is
    /// `subject`.
    pub fn connect_required(
        key: &GrantKey,
        subject: GrantSubject,
    ) -> Self {
        Self::ConnectRequired {
            subject,
            hint: (subject == GrantSubject::Caller).then(|| connect_hint(&key.principal)),
        }
    }

    /// The fixed reason.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::ConnectRequired { .. } => "connect_required",
            Self::ScopeInsufficient { .. } => "scope_insufficient",
            Self::ConnectorUnavailable => "connector_unavailable",
        }
    }

    /// `403` when someone must act (connect, or grant a wider scope), `503`
    /// otherwise.
    pub fn status(&self) -> axum::http::StatusCode {
        match self {
            Self::ConnectRequired { .. } | Self::ScopeInsufficient { .. } => axum::http::StatusCode::FORBIDDEN,
            Self::ConnectorUnavailable => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// A fixed message.
    pub fn message(&self) -> &'static str {
        match self {
            Self::ConnectRequired {
                subject: GrantSubject::Owner, ..
            } => "The owner of this agent has not connected this account",
            Self::ConnectRequired { .. } => "Connect your account to use this",
            Self::ScopeInsufficient { .. } => "The connected account has not granted a permission this call needs",
            Self::ConnectorUnavailable => "This connection is unavailable; try again later",
        }
    }

    /// The JSON-RPC error's `data`, and the problem's extension members:
    /// `reason`, then `subject` and `hint` or `scope` when there are any.
    pub fn data(&self) -> serde_json::Value {
        let mut data = serde_json::json!({ "reason": self.reason() });
        match self {
            Self::ConnectRequired { subject, hint } => {
                data["subject"] = serde_json::json!(match subject {
                    GrantSubject::Owner => "owner",
                    GrantSubject::Caller => "caller",
                });
                if let Some(hint) = hint {
                    data["hint"] = serde_json::json!(hint);
                }
            }
            Self::ScopeInsufficient { scope: Some(scope) } => data["scope"] = serde_json::json!(scope),
            Self::ScopeInsufficient { scope: None } | Self::ConnectorUnavailable => {}
        }
        data
    }

    /// The `application/problem+json` body (RFC 9457) that answers a call
    /// that is not MCP.
    pub fn problem(&self) -> serde_json::Value {
        let mut problem = self.data();
        problem["type"] = serde_json::json!(format!(
            "https://affinidi.com/atg/errors/{}",
            self.reason()
                .replace('_', "-")
        ));
        problem["title"] = serde_json::json!(self.message());
        problem["status"] = serde_json::json!(self.status().as_u16());
        problem
    }

    /// The answer to the call: for an MCP call, a JSON-RPC error for
    /// `mcp_request_id`, with the fixed reason in its `data`, as `-32001` when
    /// someone must act and `-32603` otherwise; for any other, the
    /// [`Self::problem`] JSON. `no-store` either way.
    pub fn response(
        &self,
        mcp_request_id: Option<serde_json::Value>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse as _;
        let mut response = match mcp_request_id {
            Some(id) => crate::mcp::request_validation::McpRequestValidationError {
                status: self.status(),
                id: Some(id),
                code: match self {
                    Self::ConnectorUnavailable => crate::mcp::errors::error_codes::INTERNAL_ERROR,
                    _ => -32001,
                },
                message: self.message().to_string(),
                data: Some(self.data()),
            }
            .into_response(),
            None => axum::response::Response::builder()
                .status(self.status())
                .header(axum::http::header::CONTENT_TYPE, "application/problem+json")
                .body(axum::body::Body::from(self.problem().to_string()))
                .unwrap_or_else(|_| self.status().into_response()),
        };
        response
            .headers_mut()
            .insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"));
        response
    }
}

/// A refused release, and why, for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub refusal: GrantRefusal,
    pub reason: &'static str,
}

fn refused(
    refusal: GrantRefusal,
    reason: &'static str,
) -> Refused {
    Refused { refusal, reason }
}

fn unavailable(reason: &'static str) -> Refused {
    refused(GrantRefusal::ConnectorUnavailable, reason)
}

/// The hint of a caller's principal in a `connect_required` refusal: 16
/// bytes, base64url without padding, of the SHA-256 of a fixed label and the
/// principal. It lets whoever runs the connect check that the person who signs
/// in is the caller, and reveals nothing else of the principal.
pub fn connect_hint(principal: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(CONNECT_HINT_LABEL);
    digest.update(principal.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest.finalize()[..16])
}

/// What releasing a grant needs.
pub struct ReleaseContext<'a> {
    pub vault: &'a Arc<dyn DelegationVaultStorage>,
    pub secrets: Option<&'a Arc<dyn SecretsStore>>,
    /// The test allow-list of fixtures; `None` in production.
    pub exact_allowlist: Option<&'a str>,
    /// How many refusals of a grant's refresh, other than `invalid_grant`,
    /// make a call that cannot use the grant answer `connect_required`.
    pub refusal_limit: u32,
}

static USES_IN_FLIGHT: std::sync::LazyLock<dashmap::DashSet<String>> = std::sync::LazyLock::new(dashmap::DashSet::new);

/// Held by the one task recording a grant's use, so concurrent requests
/// before its write lands do not each spawn one.
struct UseClaim(String);

impl UseClaim {
    fn take(grant_id: &str) -> Option<Self> {
        USES_IN_FLIGHT
            .insert(grant_id.to_string())
            .then(|| Self(grant_id.to_string()))
    }
}

impl Drop for UseClaim {
    fn drop(&mut self) {
        USES_IN_FLIGHT.remove(&self.0);
    }
}

/// Record, on a task of its own, that `grant` was released into the request
/// `request_id`, when its last recorded use is old enough
/// ([`DelegatedGrant::use_is_due`]), so a busy route does not rewrite its grant
/// on every call. A failure is logged with the request's surface variant.
pub fn record_use_in_background(
    vault: &Arc<dyn DelegationVaultStorage>,
    grant: &DelegatedGrant,
    request_id: Option<String>,
) {
    if !grant.use_is_due(Utc::now()) {
        return;
    }
    let Some(claim) = UseClaim::take(&grant.id) else {
        return;
    };
    let vault = Arc::clone(vault);
    let id = grant.id.clone();
    let surface_variant = crate::observability::policy_audit::current_request_variant();
    tokio::spawn(async move {
        let _claim = claim;
        if let Err(error) = vault
            .mark_grant_used(&id)
            .await
        {
            tracing::warn!(
                target: "credential_delegation",
                request_id = request_id.as_deref(),
                surface_variant = surface_variant.as_deref(),
                error = %error,
                "Failed to record a grant's use"
            );
        }
    });
}

/// The refusals of a grant's refresh that make a call answer
/// `connect_required`, as gateway.json's `external_consent_refresh_refusals`
/// sets them, from 1 to 20.
pub fn refusal_limit(configured: u32) -> u32 {
    configured.clamp(1, 20)
}

/// The vault's refusal of a read, by its cause, for the log.
fn vault_reason(error: &anyhow::Error) -> &'static str {
    if error.is::<super::grants::EncryptionRequired>() {
        "encryption_required"
    } else if error.is::<super::grants::EphemeralPepper>() {
        "identity_hash_pepper_ephemeral"
    } else if error.is::<super::grants::PepperMismatch>() {
        "identity_hash_pepper_mismatch"
    } else {
        "vault_unavailable"
    }
}

impl ReleaseContext<'_> {
    async fn read(
        &self,
        key: &GrantKey,
        subject: GrantSubject,
    ) -> Result<DelegatedGrant, Refused> {
        match self.vault.grant(key).await {
            Ok(Some(grant)) => Ok(grant),
            Ok(None) => Err(refused(GrantRefusal::connect_required(key, subject), "no_grant")),
            Err(error) => Err(unavailable(vault_reason(&error))),
        }
    }

    /// The revoker of grants made with `provider`, on no management caller's
    /// behalf: a call's own removals and unkept tokens.
    fn revoker(
        &self,
        provider: &CredentialProvider,
    ) -> super::revocation::Revoker {
        super::revocation::Revoker {
            providers: std::collections::HashMap::from([(provider.id.clone(), provider.clone())]),
            secrets: self.secrets.cloned(),
            exact_allowlist: self
                .exact_allowlist
                .map(str::to_string),
            actor: None,
            vault: Some(self.vault.clone()),
        }
    }

    /// Revoke, in the background, `grants` no longer in the vault.
    fn revoke_in_background(
        &self,
        provider: &CredentialProvider,
        grants: Vec<DelegatedGrant>,
    ) {
        crate::observability::policy_audit::spawn_in_request(super::revocation::revoke_removed(
            grants,
            self.revoker(provider),
        ));
    }

    /// The grant of `key` to send now: refreshed first when it is due.
    pub async fn release(
        &self,
        provider: &CredentialProvider,
        key: &GrantKey,
        subject: GrantSubject,
    ) -> Result<DelegatedGrant, Refused> {
        let grant = self
            .read(key, subject)
            .await?;
        if !grant.refresh_due_at(Utc::now()) {
            return Ok(grant);
        }
        self.refresh(provider, key, subject, grant, false)
            .await
    }

    /// The grant of `key` to retry a call with, after the vendor refused
    /// `rejected`, the grant it was sent, with a `Bearer` challenge: one
    /// another call refreshed or the person reconnected since, or one
    /// refreshed now whatever its expiry. A caller's grant that cannot be
    /// refreshed is removed, and revoked at the vendor in the background,
    /// while it still holds the token the vendor refused: someone must connect
    /// again. An owner's is kept: any caller of the binding can send a request
    /// the vendor refuses, so no such refusal ends the owner's grant. A
    /// refresh that fails for a reason a new connect would not fix keeps the
    /// grant, and so does one the authorization server keeps refusing, which
    /// asks for a new connect.
    pub async fn refresh_rejected(
        &self,
        provider: &CredentialProvider,
        key: &GrantKey,
        subject: GrantSubject,
        rejected: &DelegatedGrant,
    ) -> Result<DelegatedGrant, Refused> {
        let current = self
            .read(key, subject)
            .await?;
        if current.access_token != rejected.access_token {
            return Ok(current);
        }
        let outcome = self
            .refresh(provider, key, subject, current, true)
            .await;
        let Err(Refused {
            refusal: GrantRefusal::ConnectRequired { .. },
            reason,
        }) = &outcome
        else {
            return outcome;
        };
        if matches!(*reason, "no_grant" | "invalid_grant" | "refresh_refused") {
            return outcome;
        }
        if subject == GrantSubject::Caller
            && self
                .remove(provider, key, rejected, "rejected_by_the_vendor")
                .await
        {
            return outcome;
        }
        match self.vault.grant(key).await {
            Ok(Some(current)) if current.access_token != rejected.access_token && !current.is_expired() => Ok(current),
            _ => outcome,
        }
    }

    /// Remove the grant of `key` while it still holds the access token of
    /// `rejected`, which the vendor refused and which cannot be refreshed,
    /// and revoke it at the vendor in the background. Whether it was removed:
    /// a grant refreshed or reconnected since holds another token, and is
    /// kept.
    pub async fn remove(
        &self,
        provider: &CredentialProvider,
        key: &GrantKey,
        rejected: &DelegatedGrant,
        reason: &'static str,
    ) -> bool {
        let grant_id = key.record_id();
        match self
            .vault
            .delete_grant_holding(&grant_id, &rejected.access_token)
            .await
        {
            Ok(Some(removed)) => {
                tracing::info!(
                    target: "credential_delegation",
                    surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
                    grant_id = %grant_id,
                    reason,
                    "Removed a delegated grant the vendor refused; someone must connect again"
                );
                self.revoke_in_background(provider, vec![removed]);
                true
            }
            Ok(None) => {
                tracing::info!(
                    target: "credential_delegation",
                    surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
                    grant_id = %grant_id,
                    reason,
                    "Kept a delegated grant the vendor refused an earlier token of; it was refreshed or connected again"
                );
                false
            }
            Err(error) => {
                tracing::warn!(
                    target: "credential_delegation",
                    surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
                    grant_id = %grant_id,
                    error = %error,
                    "Failed to remove a delegated grant the vendor refused"
                );
                false
            }
        }
    }

    /// The grant to send a call once more with, after the vendor rejected the
    /// token of `rejected` ([`VendorAnswer::TokenRejected`]): refreshed,
    /// single-flight, or the one another call or a reconnect stored since
    /// ([`Self::refresh_rejected`]). A call whose body is too large to send
    /// again (`may_resend` false) is refused `connector_unavailable` once the
    /// grant is refreshed, so the next call uses the fresh token.
    pub async fn retry_grant(
        &self,
        provider: &CredentialProvider,
        key: &GrantKey,
        subject: GrantSubject,
        rejected: &DelegatedGrant,
        may_resend: bool,
    ) -> Result<DelegatedGrant, Refused> {
        let fresh = self
            .refresh_rejected(provider, key, subject, rejected)
            .await?;
        if !may_resend {
            return Err(unavailable("vendor_refused_a_large_body_refreshed_for_the_next_call"));
        }
        Ok(fresh)
    }

    /// Refresh `grant`, single-flight. `forced` refreshes a token the vendor
    /// refused, which is then never used again; otherwise a token that has not
    /// expired is used while no refresh can be had.
    async fn refresh(
        &self,
        provider: &CredentialProvider,
        key: &GrantKey,
        subject: GrantSubject,
        mut grant: DelegatedGrant,
        forced: bool,
    ) -> Result<DelegatedGrant, Refused> {
        let now = Utc::now();
        let usable = |grant: &DelegatedGrant| !forced && !grant.is_expired();
        let connect = || GrantRefusal::connect_required(key, subject);
        if !provider.token_refresh_enabled
            || grant
                .refresh_token
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return if usable(&grant) {
                Ok(grant)
            } else {
                Err(refused(connect(), "grant_not_refreshable"))
            };
        }
        if !grant.refresh_permitted_at(now) {
            return if usable(&grant) {
                Ok(grant)
            } else if grant.refresh_abandoned() {
                Err(refused(connect(), "refresh_abandoned"))
            } else if grant.refused_too_often(self.refusal_limit) {
                Err(refused(connect(), "refresh_refused"))
            } else {
                Err(unavailable("refresh_backing_off"))
            };
        }
        for _ in 0..2 {
            match self
                .vault
                .claim_grant_refresh(&grant, now)
                .await
            {
                Ok(claim) => {
                    return self
                        .spawn_refresh(provider, key, subject, claim, forced, grant)
                        .await;
                }
                Err(RefreshError::Changed) => {
                    let current = self
                        .read(key, subject)
                        .await?;
                    let renewed = current.access_token != grant.access_token;
                    if (renewed || !forced) && !current.refresh_due_at(now) && !current.is_expired() {
                        return Ok(current);
                    }
                    grant = current;
                }
                Err(RefreshError::InProgress) => {
                    if usable(&grant) {
                        return Ok(grant);
                    }
                    return self
                        .wait_for_refresh(key, subject, &grant)
                        .await;
                }
                Err(RefreshError::Uncertain) => {
                    if let Err(error) = self
                        .vault
                        .abandon_grant_refresh(&grant, now)
                        .await
                    {
                        tracing::debug!(
                            target: "credential_delegation",
                            surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
                            error = %error,
                            "Failed to mark a grant's refresh abandoned"
                        );
                    }
                    audit_refresh(key, provider, "refresh_failed:uncertain", false);
                    return if usable(&grant) {
                        Ok(grant)
                    } else {
                        Err(refused(connect(), "refresh_uncertain"))
                    };
                }
                Err(RefreshError::NotRefreshable) => {
                    return if usable(&grant) {
                        Ok(grant)
                    } else {
                        Err(refused(connect(), "grant_not_refreshable"))
                    };
                }
                Err(_) => {
                    return if usable(&grant) {
                        Ok(grant)
                    } else {
                        Err(unavailable("vault_unavailable"))
                    };
                }
            }
        }
        if usable(&grant) {
            Ok(grant)
        } else {
            Err(unavailable("refresh_contended"))
        }
    }

    /// The grant stored now, after a refresh's outcome found its claim taken
    /// over: one with another token, as a reconnect or another refresh left
    /// it, or the same token while it is valid and not refused by the vendor.
    async fn after_a_change(
        &self,
        key: &GrantKey,
        subject: GrantSubject,
        before: &DelegatedGrant,
        forced: bool,
    ) -> Result<DelegatedGrant, Refused> {
        let current = self
            .read(key, subject)
            .await?;
        let renewed = current.access_token != before.access_token;
        if (renewed || !forced) && !current.is_expired() {
            Ok(current)
        } else {
            Err(unavailable("refresh_lost_a_race"))
        }
    }

    /// Run the claimed refresh of `before` on a task of its own, in the
    /// request being served, and wait for it: a call dropped meanwhile, as
    /// when its client gives up, leaves the refresh to finish and write what
    /// it obtained, so no claim is left behind to abandon the grant. The calls
    /// waiting for it are woken when it ends, however it ends.
    async fn spawn_refresh(
        &self,
        provider: &CredentialProvider,
        key: &GrantKey,
        subject: GrantSubject,
        claim: super::storage::GrantRefreshClaim,
        forced: bool,
        before: DelegatedGrant,
    ) -> Result<DelegatedGrant, Refused> {
        let vault = Arc::clone(self.vault);
        let secrets = self.secrets.cloned();
        let exact_allowlist = self
            .exact_allowlist
            .map(str::to_string);
        let refusal_limit = self.refusal_limit;
        let provider = provider.clone();
        let key = key.clone();
        let done = RefreshDone(refresh_notice(&before.id));
        crate::observability::policy_audit::spawn_in_request(async move {
            let _done = done;
            ReleaseContext {
                vault: &vault,
                secrets: secrets.as_ref(),
                exact_allowlist: exact_allowlist.as_deref(),
                refusal_limit,
            }
            .run_refresh(&provider, &key, subject, claim, forced, &before)
            .await
        })
        .await
        .unwrap_or_else(|_| Err(unavailable("refresh_failed")))
    }

    /// Send the claimed refresh, and write what it obtained.
    async fn run_refresh(
        &self,
        provider: &CredentialProvider,
        key: &GrantKey,
        subject: GrantSubject,
        claim: super::storage::GrantRefreshClaim,
        forced: bool,
        before: &DelegatedGrant,
    ) -> Result<DelegatedGrant, Refused> {
        let usable = |grant: &DelegatedGrant| !forced && !grant.is_expired();
        let refresh_token = claim
            .grant()
            .refresh_token
            .clone()
            .unwrap_or_default();
        let requested = claim
            .grant()
            .scopes_asked_for()
            .to_vec();
        let held = provider
            .scope_comparison
            .held(&requested, &claim.grant().scopes);
        let answer = super::token_endpoint::request_token(
            provider,
            self.secrets,
            self.exact_allowlist,
            TokenRequest::Refresh {
                refresh_token: &refresh_token,
                scopes: &held,
            },
        )
        .await;
        let now = Utc::now();
        let failure = match answer {
            Ok(answer) => {
                let granted = answer
                    .scopes
                    .clone()
                    .unwrap_or_else(|| claim.grant().scopes.clone());
                let tokens = ObtainedTokens {
                    access_token: answer.access_token,
                    refresh_token: answer.refresh_token,
                    scopes: granted,
                    expires_at: answer
                        .expires_in
                        .map(|seconds| now + chrono::Duration::seconds(seconds)),
                };
                let (wider, widened) = {
                    let extra = provider
                        .scope_comparison
                        .widened(&requested, &tokens.scopes);
                    (!extra.is_empty(), crate::credential_providers::scope_comparison::named_scopes(&extra))
                };
                if wider {
                    tracing::warn!(
                        target: "credential_delegation",
                        grant_id = %before.id,
                        credential_provider_id = %provider.id,
                        widened_scopes = ?widened,
                        "A refresh was refused: the vendor granted scopes beyond those asked for"
                    );
                    let abandoned = self
                        .vault
                        .fail_grant_refresh(claim, FailedRefresh::Abandoned, now)
                        .await;
                    audit_refresh(key, provider, "refresh_failed:scope_widened", false);
                    self.revoke_unkept(
                        provider,
                        key,
                        tokens,
                        before
                            .refresh_token
                            .as_deref(),
                        before,
                        now,
                    );
                    if matches!(abandoned, Err(RefreshError::Changed)) {
                        // The person connected again, or the grant was
                        // removed, while the refresh ran: the grant stored now
                        // answers the call.
                        return self
                            .after_a_change(key, subject, before, forced)
                            .await;
                    }
                    return Err(refused(GrantRefusal::connect_required(key, subject), "refresh_widened_scopes"));
                }
                let kept_refresh_token = claim
                    .grant()
                    .refresh_token
                    .clone();
                let mut unkept = ObtainedTokens {
                    access_token: tokens.access_token.clone(),
                    refresh_token: tokens.refresh_token.clone(),
                    scopes: Vec::new(),
                    expires_at: None,
                };
                return match self
                    .vault
                    .complete_grant_refresh(claim, tokens, now)
                    .await
                {
                    Ok(grant) => {
                        audit_refresh(key, provider, "token_refreshed", true);
                        Ok(grant)
                    }
                    Err(RefreshError::Changed) => {
                        // The claim was taken over: the grant was replaced,
                        // removed, or its refresh abandoned. These tokens are
                        // the grant's no more; revoke them, keeping a refresh
                        // token the grant stored now holds, or may hold when
                        // it cannot be read, as an authorization server that
                        // does not rotate answers it again.
                        let stored_refresh_token = match self.vault.grant(key).await {
                            Ok(Some(current)) => current.refresh_token,
                            Ok(None) => None,
                            Err(_) => {
                                unkept.refresh_token = None;
                                None
                            }
                        };
                        audit_refresh(key, provider, "refresh_failed:lost_a_race", false);
                        self.revoke_unkept(provider, key, unkept, stored_refresh_token.as_deref(), before, now);
                        self.after_a_change(key, subject, before, forced)
                            .await
                    }
                    Err(RefreshError::Unconfirmed) => {
                        // The write failed part way: the tokens may be the
                        // grant's now, so they are never revoked.
                        match self.vault.grant(key).await {
                            Ok(Some(current)) if current.access_token == unkept.access_token => {
                                audit_refresh(key, provider, "token_refreshed", true);
                                Ok(current)
                            }
                            _ => {
                                audit_refresh(key, provider, "refresh_failed:unconfirmed", false);
                                if usable(before) {
                                    Ok(before.clone())
                                } else {
                                    Err(unavailable("vault_unavailable"))
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Refused before the write: the vault could not be
                        // locked or read, or the answer was unusable.
                        audit_refresh(key, provider, "refresh_failed:not_written", false);
                        self.revoke_unkept(provider, key, unkept, kept_refresh_token.as_deref(), before, now);
                        if usable(before) {
                            Ok(before.clone())
                        } else {
                            Err(unavailable("vault_unavailable"))
                        }
                    }
                };
            }
            Err(failure) => failure,
        };
        if failure == TokenFailure::InvalidGrant {
            audit_refresh(key, provider, "refresh_failed:invalid_grant", false);
            return match self
                .vault
                .discard_grant_refresh(claim)
                .await
            {
                Ok(discarded) => {
                    // The refresh token is dead; its access token may not be.
                    self.revoke_in_background(provider, vec![discarded]);
                    Err(refused(GrantRefusal::connect_required(key, subject), "invalid_grant"))
                }
                Err(RefreshError::Changed) => {
                    // A reconnect, or a removal, landed while the refresh ran:
                    // the refusal was about a grant that is gone.
                    self.after_a_change(key, subject, before, forced)
                        .await
                }
                Err(_) => {
                    tracing::warn!(
                        target: "credential_delegation",
                        surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
                        grant_id = %before.id,
                        "Failed to delete a grant whose refresh token was refused"
                    );
                    Err(unavailable("vault_unavailable"))
                }
            };
        }
        // Anything else, a local cause included (the client refused or its
        // secret unresolved, the endpoint unreachable), keeps the grant and
        // retries after a wait, whether or not the vendor refused the token:
        // a new connect would not fix it. A refusal (`invalid_client`, or
        // another 4xx) is counted: once the authorization server has refused
        // as often as the gateway allows, a call that cannot use the grant
        // asks for a new connect, though the grant is kept.
        let refusal = matches!(failure, TokenFailure::Refused | TokenFailure::InvalidClient);
        let failed = self
            .vault
            .fail_grant_refresh(
                claim,
                if refusal {
                    FailedRefresh::Refused
                } else {
                    FailedRefresh::Retried
                },
                now,
            )
            .await;
        audit_refresh(key, provider, &format!("refresh_failed:{}", failure.reason()), false);
        tracing::warn!(
            target: "credential_delegation",
            surface_variant = crate::observability::policy_audit::current_request_variant().as_deref(),
            grant_id = %before.id,
            reason = failure.reason(),
            "A delegated grant's refresh failed; it is retried after a wait"
        );
        match failed {
            Ok(grant) if usable(&grant) => Ok(grant),
            Ok(grant) if grant.refused_too_often(self.refusal_limit) => {
                Err(refused(GrantRefusal::connect_required(key, subject), "refresh_refused"))
            }
            Err(RefreshError::Changed) => {
                self.after_a_change(key, subject, before, forced)
                    .await
            }
            _ if usable(before) => Ok(before.clone()),
            _ => Err(unavailable(failure.reason())),
        }
    }

    /// Revoke, in the background, `tokens` a refresh of `before`, the grant of
    /// `key`, obtained but the grant does not keep, auditing them as such. A
    /// refresh token the grant still holds, as an authorization server that
    /// does not rotate answers it again, is not revoked, so the grant is not
    /// ended with them. They are of `before`'s vendor account.
    fn revoke_unkept(
        &self,
        provider: &CredentialProvider,
        key: &GrantKey,
        tokens: ObtainedTokens,
        held_refresh_token: Option<&str>,
        before: &DelegatedGrant,
        now: chrono::DateTime<Utc>,
    ) {
        let mut unkept = DelegatedGrant::new(key, tokens, now);
        unkept.id = key.record_id();
        unkept.vendor_subject = before.vendor_subject.clone();
        if unkept
            .refresh_token
            .as_deref()
            .is_some_and(|token| Some(token) == held_refresh_token)
        {
            unkept.refresh_token = None;
        }
        crate::observability::policy_audit::spawn_in_request(super::revocation::revoke_unkept(
            vec![unkept],
            self.revoker(provider),
        ));
    }

    /// Wait, up to [`REFRESH_WAIT`], for the refresh another call is running,
    /// and return the refreshed grant. A refresh on this node wakes the wait
    /// as soon as it ends; one on another node is seen when the grant is read
    /// again, after a wait that grows from [`REFRESH_POLL`] to
    /// [`REFRESH_POLL_MAX`], so a slow refresh costs a waiting call a few
    /// reads, not one every few milliseconds.
    async fn wait_for_refresh(
        &self,
        key: &GrantKey,
        subject: GrantSubject,
        stale: &DelegatedGrant,
    ) -> Result<DelegatedGrant, Refused> {
        let notice = refresh_notice(&stale.id);
        let deadline = tokio::time::Instant::now() + REFRESH_WAIT;
        let mut poll = REFRESH_POLL;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(unavailable("refresh_in_progress"));
            }
            let notified = notice.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let _ = tokio::time::timeout(poll.min(deadline - now), notified).await;
            poll = (poll * 2).min(REFRESH_POLL_MAX);
            let current = self
                .read(key, subject)
                .await?;
            if current.updated_at != stale.updated_at {
                return if current.access_token != stale.access_token && !current.is_expired() {
                    Ok(current)
                } else if current.refresh_abandoned() {
                    Err(refused(GrantRefusal::connect_required(key, subject), "refresh_abandoned"))
                } else if current.refused_too_often(self.refusal_limit) {
                    Err(refused(GrantRefusal::connect_required(key, subject), "refresh_refused"))
                } else {
                    Err(unavailable("refresh_failed"))
                };
            }
        }
    }
}

/// What a vendor's RFC 6750 `Bearer` challenge says, as far as the gateway
/// reads it: its `error`, and its `scope` when it is plain scope tokens.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BearerChallenge {
    pub error: Option<String>,
    pub scope: Option<String>,
}

impl BearerChallenge {
    /// Whether the vendor refused the token for lacking a scope.
    pub fn insufficient_scope(&self) -> bool {
        self.error.as_deref() == Some("insufficient_scope")
    }

    /// Whether the vendor refused the token itself: `invalid_token`, as a
    /// `401` for an expired or revoked token carries. A challenge that names
    /// no error is not a refusal of the token: RFC 6750 (section 3.1) keeps it
    /// for a request that carried no credentials.
    pub fn rejects_the_token(&self) -> bool {
        self.error.as_deref() == Some("invalid_token")
    }
}

/// How the vendor answered a call that carried a grant by binding, on a
/// Transit Point or the Access Point's Target alike.
#[derive(Debug)]
pub enum VendorAnswer {
    /// Pass the answer on.
    Pass,
    /// Refuse the call: a `403` whose `Bearer` challenge says
    /// `insufficient_scope` (`scope_insufficient`, naming the scope; a wider
    /// scope is never asked for silently), or a `401` without a challenge
    /// that rejects the token, as a front proxy or a firewall answers, which
    /// keeps the grant (`connector_unavailable`).
    Refuse(Refused),
    /// A `401` whose `Bearer` challenge rejects the token (`invalid_token`):
    /// the grant is refreshed, single-flight, and the call sent once more
    /// ([`ReleaseContext::retry_grant`]). A target checks the token before it
    /// acts, so a `401` means nothing ran.
    TokenRejected,
}

fn scope_refusal(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Option<Refused> {
    (status == reqwest::StatusCode::FORBIDDEN)
        .then(|| bearer_challenge(headers))
        .flatten()
        .filter(BearerChallenge::insufficient_scope)
        .map(|challenge| {
            refused(GrantRefusal::ScopeInsufficient { scope: challenge.scope }, "vendor_insufficient_scope")
        })
}

/// How the vendor answered a call that carried a grant by binding.
pub fn vendor_answer(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> VendorAnswer {
    if let Some(refusal) = scope_refusal(status, headers) {
        return VendorAnswer::Refuse(refusal);
    }
    if status != reqwest::StatusCode::UNAUTHORIZED {
        return VendorAnswer::Pass;
    }
    if bearer_challenge(headers).is_some_and(|challenge| challenge.rejects_the_token()) {
        VendorAnswer::TokenRejected
    } else {
        VendorAnswer::Refuse(unavailable("vendor_401_not_rejecting_the_token"))
    }
}

/// The vendor's answer to a call sent once more with a refreshed grant: a
/// `403` for a missing scope is refused as on the first answer, and a second
/// `401` refuses this call, `connector_unavailable`, and keeps the grant: the
/// authorization server has just issued, or another call or a reconnect has
/// just stored, the token refused again, so the vendor refuses this request,
/// not the connection, which a caller of an owner binding could otherwise end
/// for every caller. A dead authorization shows at the next refresh.
pub fn vendor_answer_to_a_retry(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<(), Refused> {
    if let Some(refusal) = scope_refusal(status, headers) {
        return Err(refusal);
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(unavailable("vendor_rejected_a_refreshed_grant"));
    }
    Ok(())
}

/// The first `Bearer` challenge of a vendor's `WWW-Authenticate` headers. A
/// `scope` that is not plain scope names ([`plain_scope`]) is left out, so no
/// other text of the vendor's ever reaches a caller or the model behind it.
pub fn bearer_challenge(headers: &reqwest::header::HeaderMap) -> Option<BearerChallenge> {
    headers
        .get_all(reqwest::header::WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            let value = value.trim_start();
            let (scheme, parameters) = value
                .split_once(char::is_whitespace)
                .unwrap_or((value, ""));
            if !scheme.eq_ignore_ascii_case("bearer") {
                return None;
            }
            let parameters = crate::mpp::payment_challenge::parse_auth_params(parameters);
            Some(BearerChallenge {
                error: parameters
                    .get("error")
                    .cloned(),
                scope: parameters
                    .get("scope")
                    .cloned()
                    .filter(|scope| plain_scope(scope)),
            })
        })
}

/// Scope names joined by single spaces, at most 512 characters, each of
/// letters, digits and `.`, `_`, `:`, `/`, `-`, `+`, `=` or `@` only: the
/// subset of RFC 6749 scope tokens that names a scope, such as `issues:write`
/// or `https://www.googleapis.com/auth/calendar`, and carries no markup or
/// prose.
fn plain_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 512
        && scope.split(' ').all(|token| {
            !token.is_empty()
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-+=@".contains(&byte))
        })
}

/// Audit what became of a grant's refresh.
fn audit_refresh(
    key: &GrantKey,
    provider: &CredentialProvider,
    detail: &str,
    refreshed: bool,
) {
    super::audit::emit(
        if refreshed {
            "token_refreshed"
        } else {
            "refresh_failed"
        },
        || {
            let mut event = super::audit::audit_event(
                if refreshed {
                    super::audit::DelegationAuditAction::TokenRefreshed
                } else {
                    super::audit::DelegationAuditAction::RefreshFailed
                },
                None,
                Some(&key.principal),
                Some(&provider.id),
                Some(&key.surface_id),
            );
            event.token_id = Some(key.record_id());
            event.provider_name = Some(provider.name.clone());
            event.detail = Some(format!("grant_by_binding,{detail}"));
            event
        },
    );
}

#[cfg(test)]
mod connect_hint_tests {
    use super::connect_hint;

    #[test]
    fn the_connect_hint_has_fixed_values_for_known_principals() {
        assert_eq!(
            connect_hint("42628a381c35947c51d560b24315c5590c6f3c217701fcabd95f9fd9697bcd3f"),
            "WXYw1wqFnUD93SdLiPtFyA"
        );
        assert_eq!(
            connect_hint("88710eb7ec7b0a9bd06ab2201d049690db79712dec6f0a41cd26deb1cd003738"),
            "YvFEO7T_9N80_y4j8sxMVA"
        );
    }

    #[test]
    fn the_connect_hint_is_sixteen_bytes_of_unpadded_base64url() {
        let hint = connect_hint("owner");
        assert_eq!(hint.len(), 22);
        assert!(
            hint.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_ne!(connect_hint("owner"), connect_hint("another"));
    }
}

#[cfg(test)]
mod use_claim_tests {
    use super::UseClaim;

    #[test]
    fn a_grant_has_one_use_claim_until_it_is_dropped() {
        let first = UseClaim::take("claim-grant").expect("first claim");
        assert!(UseClaim::take("claim-grant").is_none());
        assert!(UseClaim::take("another-claim-grant").is_some());
        drop(first);
        assert!(UseClaim::take("claim-grant").is_some());
    }
}
