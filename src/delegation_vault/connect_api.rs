//! The connect API: external consent for grants by binding.
//!
//! Server to server only, under a management session or access token, and
//! scoped to the surfaces the caller may manage: a tenant's token, its own
//! tenant's surfaces, within its resource pattern (`delegation-vault:<surface
//! id>`). Nothing here faces a browser, and no route returns a token.
//!
//! - `POST /api/v1/delegation-vault/connects` starts a connect for a binding
//!   and a principal, keeps the PKCE verifier, and answers only its S256
//!   challenge.
//! - `POST /api/v1/delegation-vault/connects/{id}/complete` claims the connect
//!   once, checks the authorization response's `iss`, redeems the code at the
//!   provider's pinned token endpoint with the verifier, and keeps the grant
//!   while its binding is saved.
//! - `GET /api/v1/delegation-vault/grants` reports a surface's bindings: whether
//!   the owner is connected, how many callers are, and one caller's own grant.
//! - `DELETE /api/v1/delegation-vault/grants/{id}` and
//!   `DELETE /api/v1/delegation-vault/grants?...` remove grants, revoking each
//!   at its authorization server (RFC 7009). An operator can also remove a
//!   grant that cannot be read, which cannot be revoked.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::Deserialize;
use tracing::{info, warn};

use super::audit::AuditCallerContext;
use super::connects::{ConnectClaim, PendingConnect, TooManyPendingConnects};
use super::consent_age::ConsentLimits;
use super::grants::{DelegatedGrant, GrantBinding, GrantKey, OWNER_PRINCIPAL, ObtainedTokens, UnreadableGrant};
use super::handlers::DelegationVaultState;
use super::token_endpoint::{TokenFailure, TokenRequest};
use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatDelegationContext, PatResourceScope};
use crate::config::agent_surface::{AgentSurface, GrantSubject};
use crate::credential_providers::CredentialProvider;
use crate::credential_providers::scope_comparison::named_scopes;
use crate::tenancy::{PatTenantContext, ResourceKind, can_mutate, scope_allows_resource};

/// The most scopes a connect may ask for.
const MAX_SCOPES: usize = 128;
/// The longest authorization code accepted.
const MAX_CODE_CHARS: usize = 4096;

fn error(
    status: StatusCode,
    code: &'static str,
    message: &str,
) -> Response {
    (status, Json(serde_json::json!({ "code": code, "error": message }))).into_response()
}

/// A connect that did not complete: `{status: "failed", reason}`.
fn failed(
    status: StatusCode,
    reason: &'static str,
) -> Response {
    (status, Json(serde_json::json!({ "status": "failed", "reason": reason }))).into_response()
}

/// Why a claimed connect was not kept: the answer's status and fixed reason,
/// and, for `scope_widened`, the scopes the vendor granted beyond those asked
/// for, as [`named_scopes`] lets them be named.
#[derive(Debug)]
struct Unkept {
    status: StatusCode,
    reason: &'static str,
    widened: Vec<String>,
}

impl From<(StatusCode, &'static str)> for Unkept {
    fn from((status, reason): (StatusCode, &'static str)) -> Self {
        Unkept {
            status,
            reason,
            widened: Vec::new(),
        }
    }
}

impl Unkept {
    /// The failed answer, naming the widened scopes when there are any: a
    /// hint for the operator of which scopes the vendor added, in the
    /// vendor's spelling, never its other words.
    fn response(self) -> Response {
        if self.widened.is_empty() {
            return failed(self.status, self.reason);
        }
        (
            self.status,
            Json(serde_json::json!({
                "status": "failed",
                "reason": self.reason,
                "widened_scopes": self.widened,
            })),
        )
            .into_response()
    }
}

/// Who calls the connect API, and what they may manage.
struct Manager {
    actor: AuditCallerContext,
    tenant: Option<PatTenantContext>,
    scope: Option<PatResourceScope>,
}

impl Manager {
    fn of(
        caller: Option<Extension<AuthGuardOk>>,
        delegation: Option<Extension<PatDelegationContext>>,
        tenant: Option<Extension<PatTenantContext>>,
        scope: Option<Extension<PatResourceScope>>,
    ) -> Result<Self, Box<Response>> {
        let user_id = caller
            .as_ref()
            .map(|Extension(AuthGuardOk(id))| id.as_str());
        let token_id = delegation
            .as_ref()
            .map(|Extension(context)| context.token_id.as_str());
        let Some(actor) = super::audit::management_caller_context(user_id, token_id) else {
            return Err(Box::new(error(StatusCode::UNAUTHORIZED, "unauthenticated", "no authenticated caller")));
        };
        Ok(Self {
            actor,
            tenant: tenant.map(|Extension(context)| context),
            scope: scope.map(|Extension(scope)| scope),
        })
    }

    /// Whether the caller may manage the grants of a surface of `tenant_id`
    /// whose id is `surface_id`: a tenant's token only its own tenant's, within
    /// its resource pattern.
    fn may_manage(
        &self,
        tenant_id: Option<&str>,
        surface_id: &str,
    ) -> bool {
        can_mutate(tenant_id, self.tenant.as_ref())
            && scope_allows_resource(
                self.scope.as_ref(),
                self.tenant.as_ref(),
                ResourceKind::DelegationVault,
                surface_id,
            )
    }

    /// An operator: neither a tenant's token nor one confined to a resource
    /// pattern. Only an operator purges a grant it cannot read, which is
    /// removed unrevoked whatever its surface.
    fn is_operator(&self) -> bool {
        self.tenant.is_none() && self.scope.is_none()
    }
}

fn surface_not_found() -> Response {
    error(StatusCode::NOT_FOUND, "surface_not_found", "Surface not found")
}

/// The surface `surface_id`, if the caller may manage its grants.
async fn managed_surface(
    state: &DelegationVaultState,
    manager: &Manager,
    surface_id: &str,
) -> Result<AgentSurface, Box<Response>> {
    let Some(surfaces) = state
        .agent_surface_store
        .as_ref()
    else {
        return Err(Box::new(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "surfaces_unavailable",
            "Surfaces are unavailable",
        )));
    };
    match surfaces.get(surface_id).await {
        Ok(Some(surface)) if manager.may_manage(surface.tenant_id.as_deref(), &surface.surface_id) => Ok(surface),
        Ok(_) => Err(Box::new(surface_not_found())),
        Err(error) => {
            warn!(target: "credential_delegation", error = %error, "Failed to read a surface for the connect API");
            Err(Box::new(self::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "surfaces_unavailable",
                "Surfaces are unavailable",
            )))
        }
    }
}

/// The external consent provider `id` of `tenant_id`, if it is one and the
/// operator's rules still permit it.
async fn permitted_provider(
    state: &DelegationVaultState,
    id: &str,
    tenant_id: Option<&str>,
) -> Result<CredentialProvider, (StatusCode, &'static str)> {
    let provider = state
        .provider_store
        .get(id)
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "provider_unavailable"))?
        .filter(|provider| provider.is_external_consent() && provider.tenant_id.as_deref() == tenant_id)
        .ok_or((StatusCode::CONFLICT, "provider_unavailable"))?;
    let issuers = state.issuers.rules();
    if crate::credential_providers::external::issuer_permitted(&provider, issuers).is_err() {
        warn!(
            target: "credential_delegation",
            credential_provider_id = %provider.id,
            "The gateway's external_consent_issuers and external_consent_issuer_patterns do not permit a provider's \
             issuer; its connect is refused"
        );
        return Err((StatusCode::FORBIDDEN, "issuer_not_permitted"));
    }
    if !crate::credential_providers::external::resource_permitted(&provider, &state.resource_origins, issuers) {
        return Err((StatusCode::FORBIDDEN, "resource_not_permitted"));
    }
    Ok(provider)
}

/// Whether the Transit Point `hop` of `surface` can be served as a call to it
/// would be, in every view of the surface that has it: a `proxy://` Transit
/// Point must meet the same rules
/// ([`crate::credential_providers::external::check_proxy_transit_point`]),
/// so no consent is run, and no refresh token kept, for a binding every call
/// would refuse. Its binding's `mcp_proxy_pin` when it can, which the
/// destination check compares with the proxy as it is now.
fn servable_transit_point(
    surface: &crate::config::agent_surface::AgentSurface,
    hop: &str,
) -> Result<Option<String>, &'static str> {
    let views = crate::identity::handlers::surface_tenancy::resolved_views(surface)
        .map_err(|_| "the surface's variants cannot be resolved")?;
    let mut pin = None;
    let mut found = false;
    for view in &views {
        for point in view
            .transit_points()
            .iter()
            .filter(|point| point.id == hop)
        {
            crate::credential_providers::external::check_proxy_transit_point(view, point)?;
            found = true;
            pin = point
                .transit_credentials
                .as_ref()
                .and_then(|binding| binding.mcp_proxy_pin.clone());
        }
    }
    if !found {
        return Err("the surface serves no Transit Point at this hop");
    }
    Ok(pin)
}

/// The revoker of grants made with `provider`, on behalf of `actor`.
fn revoker(
    state: &DelegationVaultState,
    providers: HashMap<String, CredentialProvider>,
    actor: Option<AuditCallerContext>,
) -> super::revocation::Revoker {
    super::revocation::Revoker {
        providers,
        secrets: Some(state.secrets_store.clone()),
        exact_allowlist: state.egress_allowlist.clone(),
        actor,
        vault: Some(state.vault_store.clone()),
    }
}

/// Revoke, in the background, tokens obtained for a grant that is not kept.
fn revoke_unkept(
    state: &DelegationVaultState,
    provider: &CredentialProvider,
    grant: DelegatedGrant,
    actor: &AuditCallerContext,
) {
    let revoker = revoker(state, HashMap::from([(provider.id.clone(), provider.clone())]), Some(actor.clone()));
    tokio::spawn(super::revocation::revoke_unkept(vec![grant], revoker));
}

/// `POST /api/v1/delegation-vault/connects`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartConnectRequest {
    pub surface_id: String,
    /// The Transit Point id whose binding the grant serves, or `target` for
    /// the Access Point Target's binding.
    pub hop: String,
    pub credential_provider_id: String,
    pub subject: GrantSubject,
    /// The caller's identity hash, for `subject: caller`; `owner` or absent
    /// for `subject: owner`.
    #[serde(default)]
    pub principal: Option<String>,
    /// The scopes to ask for, within the binding's; the binding's when empty.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The provider's `callback_url`, which the authorization request names.
    pub redirect_uri: String,
}

/// Start a connect for a binding and a principal. The binding must be a
/// `consent_mode: external` binding the surface serves at `hop`, of
/// `credential_provider_id` and `subject`; the scopes must lie within the
/// binding's; `redirect_uri` must be the provider's `callback_url`. Answers
/// `201` with the connect's id, the S256 challenge of a verifier only the
/// gateway holds, and when the connect expires.
pub async fn start_connect(
    State(state): State<DelegationVaultState>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    tenant: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<StartConnectRequest>,
) -> Response {
    let manager = match Manager::of(caller, delegation, tenant, scope) {
        Ok(manager) => manager,
        Err(response) => return *response,
    };
    let surface = match managed_surface(&state, &manager, &request.surface_id).await {
        Ok(surface) => surface,
        Err(response) => return *response,
    };
    let served = crate::identity::handlers::surface_grants::served_external_bindings(&surface);
    let Some(binding) = served
        .into_iter()
        .find(|binding| binding.hop == request.hop)
    else {
        return error(
            StatusCode::NOT_FOUND,
            "binding_not_found",
            "The surface serves no consent_mode external binding at this hop",
        );
    };
    if binding.credential_provider_id != request.credential_provider_id {
        return error(StatusCode::NOT_FOUND, "binding_not_found", "The binding at this hop binds another provider");
    }
    if binding.subject != Some(request.subject) {
        return error(StatusCode::BAD_REQUEST, "subject_mismatch", "The binding at this hop has another subject");
    }
    let tenant_id = surface.tenant_id.as_deref();
    let key = match (request.subject, request.principal.as_deref()) {
        (GrantSubject::Owner, None | Some(OWNER_PRINCIPAL)) => {
            GrantKey::owner(tenant_id, &surface.surface_id, binding.hop, binding.credential_provider_id)
        }
        (GrantSubject::Caller, Some(principal)) => {
            match GrantKey::caller(
                tenant_id,
                &surface.surface_id,
                binding.hop,
                binding.credential_provider_id,
                principal,
            ) {
                Some(key) => key,
                None => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "invalid_principal",
                        "A caller's principal is its identity hash: 64 lowercase hex digits",
                    );
                }
            }
        }
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_principal",
                "subject owner takes no principal, and subject caller needs one",
            );
        }
    };
    let provider = match permitted_provider(&state, binding.credential_provider_id, tenant_id).await {
        Ok(provider) => provider,
        Err((status, code)) => return error(status, code, "The binding's provider cannot be connected"),
    };
    let exact_allowlist = state
        .egress_allowlist
        .as_deref();
    let destination = if binding.hop == crate::delegation_vault::grants::ACCESS_POINT_TARGET_HOP {
        crate::credential_providers::external::check_grant_destination(
            &provider,
            &binding.target_endpoint,
            exact_allowlist,
        )
        .await
    } else {
        let proxies = state
            .mcp_proxy_store
            .as_deref()
            .map(|store| store as &dyn crate::mcp_proxies::McpProxyStore);
        match servable_transit_point(&surface, binding.hop) {
            Ok(proxy_pin) => match crate::credential_providers::external::check_transit_grant_destination(
                &provider,
                &binding.target_endpoint,
                proxy_pin.as_deref(),
                proxies,
                tenant_id,
                exact_allowlist,
            )
            .await
            {
                Ok(destination) => {
                    crate::credential_providers::external::check_transit_grant_spec(&binding.target_endpoint, proxies)
                        .await
                        .map(|()| destination)
                }
                Err(refused) => Err(refused),
            },
            Err(refused) => Err(refused),
        }
    };
    if let Err(reason) = destination {
        warn!(
            target: "credential_delegation",
            surface_id = %surface.surface_id,
            hop = %binding.hop,
            provider_id = %provider.id,
            proxy_id = ?crate::mcp_proxies::types::transit_proxy_id(&binding.target_endpoint),
            reason,
            "A connect was refused: the binding cannot send grants to its provider's resource"
        );
        let message = if reason == crate::credential_providers::external::PROXY_CHANGED {
            "The binding's MCP Proxy has changed since the surface was saved: save the surface with the proxy's \
             current grant_pin as mcp_proxy_pin to pin the binding to it"
        } else {
            "The binding's Transit Point or Target does not send grants to its provider's resource"
        };
        return error(StatusCode::CONFLICT, "binding_not_servable", message);
    }
    if provider
        .callback_url
        .as_deref()
        != Some(request.redirect_uri.as_str())
    {
        return error(
            StatusCode::BAD_REQUEST,
            "redirect_uri_mismatch",
            "redirect_uri is not the provider's callback_url",
        );
    }
    let permitted_scopes: &[String] = if binding.scopes.is_empty() {
        &provider.default_scopes
    } else {
        binding.scopes
    };
    let scopes = if request.scopes.is_empty() {
        permitted_scopes.to_vec()
    } else {
        request.scopes
    };
    if scopes.len() > MAX_SCOPES
        || scopes.iter().any(|scope| {
            scope.is_empty()
                || scope
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
                || !permitted_scopes.contains(scope)
        })
    {
        return error(StatusCode::BAD_REQUEST, "scope_not_permitted", "scopes must lie within the binding's scopes");
    }
    let (connect, code_challenge) = PendingConnect::start(&key, scopes, request.redirect_uri, Utc::now());
    let mut answer = serde_json::json!({
        "connect_id": connect.id,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "expires_at": connect.expires_at,
    });
    if let Some(secs) = ConsentLimits::of(binding.max_consent_age_secs, provider.max_consent_age_secs).lifetime_secs() {
        answer["max_consent_age_secs"] = serde_json::json!(secs);
    }
    match state
        .vault_store
        .start_connect(connect)
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(answer)).into_response(),
        Err(error) if error.is::<TooManyPendingConnects>() => self::error(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_pending_connects",
            "This binding already has as many connects waiting for consent as it may",
        ),
        Err(error) => {
            warn!(target: "credential_delegation", error = %error, "Failed to start an external consent connect");
            self::error(StatusCode::SERVICE_UNAVAILABLE, "grants_unavailable", "The vault cannot keep grants now")
        }
    }
}

/// `POST /api/v1/delegation-vault/connects/{id}/complete`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteConnectRequest {
    /// The authorization code the authorization server returned.
    pub code: String,
    /// The `iss` the authorization response carried (RFC 9207), if any.
    #[serde(default)]
    pub iss: Option<String>,
}

/// Complete a connect: claim it once, check `iss`, redeem the code with the
/// verifier at the provider's pinned token endpoint, and keep the grant while
/// its binding is saved, revoking a grant of the same key it replaces. Answers
/// `{status: "connected", grant_id, scopes, expires_at}`, or `{status:
/// "failed", reason}` with a fixed reason; the authorization server's words are
/// never echoed or logged.
pub async fn complete_connect(
    State(state): State<DelegationVaultState>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    tenant: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Path(connect_id): Path<String>,
    Json(request): Json<CompleteConnectRequest>,
) -> Response {
    let manager = match Manager::of(caller, delegation, tenant, scope) {
        Ok(manager) => manager,
        Err(response) => return *response,
    };
    let not_found = || error(StatusCode::NOT_FOUND, "connect_not_found", "Connect not found");
    let pending = match state
        .vault_store
        .pending_connect(&connect_id)
        .await
    {
        Ok(Some(pending)) if manager.may_manage(pending.tenant_id.as_deref(), &pending.surface_id) => pending,
        Ok(_) => return not_found(),
        Err(error) => {
            warn!(target: "credential_delegation", error = %error, "Failed to read a pending connect");
            return self::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "grants_unavailable",
                "The vault cannot keep grants now",
            );
        }
    };
    if request.code.is_empty()
        || request.code.chars().count() > MAX_CODE_CHARS
        || request
            .code
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return error(StatusCode::BAD_REQUEST, "invalid_code", "code must be a non-empty authorization code");
    }
    let provider = match permitted_provider(&state, &pending.credential_provider_id, pending.tenant_id.as_deref()).await
    {
        Ok(provider) => provider,
        Err((status, reason)) => return refused_before_claim(&pending, status, reason),
    };
    if let Err((status, reason)) = check_iss(&provider, request.iss.as_deref()) {
        return refused_before_claim(&pending, status, reason);
    }
    let claimed = match state
        .vault_store
        .claim_connect(&pending.id, Utc::now())
        .await
    {
        Ok(ConnectClaim::Claimed(claimed)) => claimed,
        Ok(ConnectClaim::AlreadyUsed) => return failed(StatusCode::CONFLICT, "already_used"),
        Ok(ConnectClaim::Expired) => return failed(StatusCode::GONE, "expired"),
        Ok(ConnectClaim::NotFound) => return not_found(),
        Err(error) => {
            warn!(target: "credential_delegation", error = %error, "Failed to claim a pending connect");
            return self::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "grants_unavailable",
                "The vault cannot keep grants now",
            );
        }
    };
    let outcome = redeem(&state, &manager, &claimed, &request, provider).await;
    let (status, reason, widened) = match &outcome {
        Ok(_) => (StatusCode::OK, "connected", &[][..]),
        Err(unkept) => (unkept.status, unkept.reason, unkept.widened.as_slice()),
    };
    info!(
        target: "credential_delegation",
        connect_id = %claimed.id,
        surface_id = ?claimed.surface_id,
        hop = ?claimed.hop,
        credential_provider_id = %claimed.credential_provider_id,
        outcome = reason,
        widened_scopes = ?widened,
        "External consent connect completed"
    );
    match outcome {
        Ok(grant) => {
            let mut answer = serde_json::json!({
                "status": "connected",
                "grant_id": grant.id,
                "scopes": grant.scopes,
                "expires_at": grant.expires_at,
            });
            if let Some(end) = grant.consent_expires_at {
                answer["consent_expires_at"] = serde_json::json!(end);
            }
            (status, Json(answer)).into_response()
        }
        Err(unkept) => unkept.response(),
    }
}

/// Check the authorization response's RFC 9207 `iss` against `provider`.
fn check_iss(
    provider: &CredentialProvider,
    iss: Option<&str>,
) -> Result<(), (StatusCode, &'static str)> {
    match iss {
        Some(iss) if Some(iss) != provider.issuer.as_deref() => Err((StatusCode::BAD_REQUEST, "iss_mismatch")),
        // Required unless the issuer's metadata said it sends none: a provider
        // created before that was recorded may be one whose issuer sends it.
        None if provider.authorization_response_iss_parameter_supported != Some(false) => {
            Err((StatusCode::BAD_REQUEST, "iss_missing"))
        }
        _ => Ok(()),
    }
}

/// Refuse a completion whose checks failed before the connect was claimed,
/// so the connect can still be completed.
fn refused_before_claim(
    pending: &PendingConnect,
    status: StatusCode,
    reason: &'static str,
) -> Response {
    info!(
        target: "credential_delegation",
        connect_id = %pending.id,
        surface_id = ?pending.surface_id,
        hop = ?pending.hop,
        credential_provider_id = %pending.credential_provider_id,
        outcome = reason,
        "External consent connect refused before it was claimed"
    );
    failed(status, reason)
}

/// Redeem a claimed connect's code with `provider`, checked before the claim,
/// and keep the grant.
async fn redeem(
    state: &DelegationVaultState,
    manager: &Manager,
    connect: &PendingConnect,
    request: &CompleteConnectRequest,
    provider: CredentialProvider,
) -> Result<DelegatedGrant, Unkept> {
    let verifier = connect
        .code_verifier
        .as_deref()
        .ok_or((StatusCode::CONFLICT, "already_used"))?;
    let answer = super::token_endpoint::request_token(
        &provider,
        Some(&state.secrets_store),
        state
            .egress_allowlist
            .as_deref(),
        TokenRequest::AuthorizationCode {
            code: &request.code,
            redirect_uri: &connect.redirect_uri,
            code_verifier: verifier,
        },
    )
    .await
    .map_err(|failure: TokenFailure| (StatusCode::BAD_GATEWAY, failure.reason()))?;
    let now = Utc::now();
    let scopes = answer
        .scopes
        .clone()
        .unwrap_or_else(|| connect.scopes.clone());
    let key = connect.key();
    let mut grant = DelegatedGrant::new(
        &key,
        ObtainedTokens {
            access_token: answer.access_token,
            refresh_token: answer.refresh_token,
            scopes,
            expires_at: answer
                .expires_in
                .map(|seconds| now + chrono::Duration::seconds(seconds)),
        },
        now,
    );
    grant.id = key.record_id();
    grant.requested_scopes = Some(connect.scopes.clone());
    grant.vendor_subject = answer.subject;
    let (wider, widened) = {
        let extra = provider
            .scope_comparison
            .widened(&connect.scopes, &grant.scopes);
        (!extra.is_empty(), named_scopes(&extra))
    };
    if wider {
        revoke_unkept(state, &provider, grant, &manager.actor);
        return Err(Unkept {
            status: StatusCode::BAD_GATEWAY,
            reason: "scope_widened",
            widened,
        });
    }
    let Some(surfaces) = state
        .agent_surface_store
        .as_ref()
    else {
        revoke_unkept(state, &provider, grant, &manager.actor);
        return Err((StatusCode::SERVICE_UNAVAILABLE, "grants_unavailable").into());
    };
    // The binding as saved now sets the end the person is told. One changed
    // before the grant is stored is still checked at every release.
    let binding_secs = match surfaces
        .get(&grant.surface_id)
        .await
    {
        Ok(Some(surface)) => crate::identity::handlers::surface_grants::binding_max_consent_age(&surface, &grant),
        Ok(None) => None,
        Err(error) => {
            warn!(target: "credential_delegation", error = %error, "Failed to read a surface to end a grant's consent");
            revoke_unkept(state, &provider, grant, &manager.actor);
            return Err((StatusCode::SERVICE_UNAVAILABLE, "grants_unavailable").into());
        }
    };
    grant.consent_expires_at = ConsentLimits::of(binding_secs, provider.max_consent_age_secs).expires_at(now);
    let stored = match crate::identity::handlers::surface_grants::store_grant_while_bound(
        &state.vault_store,
        surfaces.as_ref(),
        grant.clone(),
        &provider.default_scopes,
    )
    .await
    {
        Ok(stored) => stored,
        Err(error) => {
            use crate::identity::handlers::surface_grants::GrantNotStored;
            revoke_unkept(state, &provider, grant, &manager.actor);
            return Err(match error {
                GrantNotStored::BindingRemoved => (StatusCode::CONFLICT, "binding_removed"),
                GrantNotStored::BindingNarrowed => (StatusCode::CONFLICT, "binding_changed"),
                GrantNotStored::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "grants_unavailable"),
            }
            .into());
        }
    };
    if let Some(replaced) = stored.replaced {
        let revoker =
            revoker(state, HashMap::from([(provider.id.clone(), provider.clone())]), Some(manager.actor.clone()));
        tokio::spawn(super::revocation::revoke_removed(vec![replaced], revoker));
    }
    super::audit::emit("consent_granted", || {
        let mut event = super::audit::audit_event(
            super::audit::DelegationAuditAction::ConsentGranted,
            None,
            Some(&key.principal),
            Some(&provider.id),
            Some(&key.surface_id),
        );
        event.token_id = Some(stored.grant.id.clone());
        event.provider_name = Some(provider.name.clone());
        event.scopes = Some(stored.grant.scopes.clone());
        event.detail = Some("grant_by_binding:external_consent".to_string());
        event.caller = Some(manager.actor.clone());
        event
    });
    Ok(stored.grant)
}

/// What `GET /api/v1/delegation-vault/grants` reports.
#[derive(Debug, Deserialize)]
pub struct GrantsQuery {
    pub surface_id: String,
    /// Only the binding at this hop.
    #[serde(default)]
    pub hop: Option<String>,
    /// This caller's own grants as well: an identity hash, or `owner`.
    #[serde(default)]
    pub principal: Option<String>,
}

/// A grant's metadata; never a token. `consent_expires_at` is when its
/// consent ends, for one under a time limit.
fn grant_summary(
    grant: &DelegatedGrant,
    consent_expires_at: Option<chrono::DateTime<Utc>>,
) -> serde_json::Value {
    let mut summary = serde_json::json!({
        "grant_id": grant.id,
        "principal": grant.principal,
        "scopes": grant.scopes,
        "created_at": grant.created_at,
        "refreshed_at": grant.obtained_at(),
        "last_used_at": grant.last_used_at,
        "expires_at": grant.expires_at,
        "state": grant.state(),
    });
    if let Some(end) = consent_expires_at {
        summary["consent_expires_at"] = serde_json::json!(end);
    }
    summary
}

/// Report each `consent_mode: external` binding of a surface: its hop,
/// provider and subject; for an owner binding, whether it is connected and its
/// grant; for a caller binding, how many callers are connected, and, with
/// `principal`, that caller's own grant. Grants are found by name, so a count
/// reads nothing; a grant that cannot be read is reported as `unreadable`.
pub async fn list_grants(
    State(state): State<DelegationVaultState>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    tenant: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Query(query): Query<GrantsQuery>,
) -> Response {
    let manager = match Manager::of(caller, delegation, tenant, scope) {
        Ok(manager) => manager,
        Err(response) => return *response,
    };
    let surface = match managed_surface(&state, &manager, &query.surface_id).await {
        Ok(surface) => surface,
        Err(response) => return *response,
    };
    let mut bindings = Vec::new();
    for binding in crate::identity::handlers::surface_grants::served_external_bindings(&surface) {
        if query
            .hop
            .as_deref()
            .is_some_and(|hop| hop != binding.hop)
        {
            continue;
        }
        let Some(subject) = binding.subject else {
            continue;
        };
        let grant_binding = GrantBinding::new(
            surface.tenant_id.as_deref(),
            &surface.surface_id,
            binding.hop,
            binding.credential_provider_id,
        );
        let mut entry = serde_json::json!({
            "hop": binding.hop,
            "credential_provider_id": binding.credential_provider_id,
            "subject": match subject { GrantSubject::Owner => "owner", GrantSubject::Caller => "caller" },
        });
        let key = match subject {
            GrantSubject::Owner => {
                entry["connected"] = serde_json::json!(false);
                Some(GrantKey::owner(
                    surface.tenant_id.as_deref(),
                    &surface.surface_id,
                    binding.hop,
                    binding.credential_provider_id,
                ))
            }
            GrantSubject::Caller => {
                let key = match query
                    .principal
                    .as_deref()
                    .filter(|principal| *principal != OWNER_PRINCIPAL)
                {
                    None => None,
                    Some(principal) => match GrantKey::caller(
                        surface.tenant_id.as_deref(),
                        &surface.surface_id,
                        binding.hop,
                        binding.credential_provider_id,
                        principal,
                    ) {
                        Some(key) => Some(key),
                        None => {
                            return error(
                                StatusCode::BAD_REQUEST,
                                "invalid_principal",
                                "principal is owner or an identity hash",
                            );
                        }
                    },
                };
                let ids = match state
                    .vault_store
                    .binding_grant_ids(&grant_binding)
                    .await
                {
                    Ok(ids) => ids,
                    Err(error) => {
                        warn!(target: "credential_delegation", error = %error, "Failed to count a binding's grants");
                        return self::error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "grants_unavailable",
                            "The vault cannot read grants now",
                        );
                    }
                };
                let owner = grant_binding.owner_record_id();
                entry["callers"] = serde_json::json!(
                    ids.iter()
                        .filter(|id| **id != owner)
                        .count()
                );
                key
            }
        };
        if let Some(key) = key {
            match state
                .vault_store
                .grant(&key)
                .await
            {
                Ok(Some(grant)) => {
                    if subject == GrantSubject::Owner {
                        entry["connected"] = serde_json::json!(true);
                    }
                    let provider_limit = match state
                        .provider_store
                        .get(binding.credential_provider_id)
                        .await
                    {
                        Ok(provider) => provider.and_then(|provider| provider.max_consent_age_secs),
                        Err(error) => {
                            warn!(target: "credential_delegation", error = %error, "Failed to read a binding's provider");
                            return self::error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "grants_unavailable",
                                "The vault cannot read grants now",
                            );
                        }
                    };
                    let consent_end = ConsentLimits::of(binding.max_consent_age_secs, provider_limit)
                        .ends_for_binding_at(grant.created_at, grant.consent_expires_at);
                    entry["grant"] = grant_summary(&grant, consent_end);
                }
                Ok(None) => {}
                Err(error)
                    if error
                        .downcast_ref::<UnreadableGrant>()
                        .is_some()
                        || error.is::<super::grants::PepperMismatch>() =>
                {
                    entry["grant"] = serde_json::json!({ "state": "unreadable" });
                }
                Err(error) => {
                    warn!(target: "credential_delegation", error = %error, "Failed to read a binding's grant");
                    return self::error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "grants_unavailable",
                        "The vault cannot read grants now",
                    );
                }
            }
        }
        bindings.push(entry);
    }
    (StatusCode::OK, Json(serde_json::json!({ "surface_id": surface.surface_id, "bindings": bindings })))
        .into_response()
}

/// Delete `grants`, as read, while each is still the connection read, and
/// revoke them at their authorization servers, in the background; returns
/// once every deletion has ended. A grant the person connected again since
/// it was read is kept. `surface_lock`, the lock of the grants' surface, is
/// held until every deletion has ended, even when the caller is dropped.
async fn delete_and_revoke(
    state: &DelegationVaultState,
    manager: &Manager,
    grants: Vec<DelegatedGrant>,
    providers: HashMap<String, CredentialProvider>,
    surface_lock: crate::identity::handlers::surface_grants::SharedSurfaceLock,
) -> anyhow::Result<()> {
    if grants.is_empty() {
        return Ok(());
    }
    super::revocation::delete_then_revoke(
        &state.vault_store,
        grants,
        revoker(state, providers, Some(manager.actor.clone())),
        surface_lock,
        None,
    )
    .await
    .map(|_| ())
}

/// The providers of `grants`, by record id.
async fn providers_of(
    state: &DelegationVaultState,
    grants: &[DelegatedGrant],
) -> HashMap<String, CredentialProvider> {
    let mut providers = HashMap::new();
    for grant in grants {
        if providers.contains_key(&grant.credential_provider_id) {
            continue;
        }
        if let Ok(Some(provider)) = state
            .provider_store
            .get(&grant.credential_provider_id)
            .await
        {
            providers.insert(provider.id.clone(), provider);
        }
    }
    providers
}

/// `DELETE /api/v1/delegation-vault/grants/{grant_id}`
///
/// Delete one grant by binding and revoke it at its authorization server.
/// The caller must manage its surface. The grant is read again, and deleted,
/// under its surface's lock, as a surface write and the sweep remove grants,
/// so a write that deleted it and puts it back when its save fails has
/// settled first; one gone by then was removed, and is revoked, by its
/// remover. An operator can also delete one that cannot be read, which then
/// cannot be revoked: the audit records it as purged.
pub async fn delete_grant(
    State(state): State<DelegationVaultState>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    tenant: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Path(grant_id): Path<String>,
) -> Response {
    let manager = match Manager::of(caller, delegation, tenant, scope) {
        Ok(manager) => manager,
        Err(response) => return *response,
    };
    if !super::grants::is_record_id(&grant_id) {
        return error(StatusCode::BAD_REQUEST, "invalid_grant_id", "Not the id of a delegated grant");
    }
    let not_found = || error(StatusCode::NOT_FOUND, "grant_not_found", "Delegated grant not found");
    match state
        .vault_store
        .grant_by_id(&grant_id)
        .await
    {
        Ok(Some(grant))
            if grant.id == grant_id
                && (manager.is_operator() || grant.key().record_id() == grant_id)
                && manager.may_manage(grant.tenant_id.as_deref(), &grant.surface_id) =>
        {
            let lock = Arc::new(crate::identity::handlers::surface_grants::lock_surface(&grant.surface_id).await);
            let grant = match state
                .vault_store
                .grant_by_id(&grant_id)
                .await
            {
                Ok(Some(grant)) if grant.id == grant_id => grant,
                Ok(_) => return StatusCode::NO_CONTENT.into_response(),
                Err(error) => return grants_unreadable_now(&error),
            };
            let providers = providers_of(&state, std::slice::from_ref(&grant)).await;
            match delete_and_revoke(&state, &manager, vec![grant], providers, lock).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(error) => {
                    warn!(target: "credential_delegation", error = %error, "Failed to delete a delegated grant");
                    self::error(StatusCode::SERVICE_UNAVAILABLE, "grants_unavailable", "The grant could not be deleted")
                }
            }
        }
        Ok(_) => not_found(),
        Err(error) if error.is::<UnreadableGrant>() && manager.is_operator() => {
            purge(&state, &manager, &grant_id, None).await
        }
        Err(error) if error.is::<UnreadableGrant>() => {
            warn!(target: "credential_delegation", error = %error, "A delegated grant cannot be read for its deletion");
            self::error(
                StatusCode::CONFLICT,
                "grant_unreadable",
                "The grant cannot be read, so it can be neither revoked nor deleted by a tenant; an operator can purge it",
            )
        }
        Err(error) => grants_unreadable_now(&error),
    }
}

/// The answer to a removal that could not read its grants now, because the
/// vault's storage or key service is unavailable: nothing is removed, and
/// nothing is purged, since the grants may read again in a moment.
fn grants_unreadable_now(error: &anyhow::Error) -> Response {
    warn!(
        target: "credential_delegation",
        error = %error,
        "The vault could not read grants for their removal; nothing was removed"
    );
    self::error(
        StatusCode::SERVICE_UNAVAILABLE,
        "grants_unavailable",
        "The vault cannot read grants now, so nothing was removed or purged; try again later",
    )
}

/// Delete the grant `grant_id` without reading it, as an operator, and audit
/// it as purged, unrevoked.
async fn purge(
    state: &DelegationVaultState,
    manager: &Manager,
    grant_id: &str,
    binding: Option<&GrantBinding>,
) -> Response {
    match state
        .vault_store
        .purge_grant(grant_id, binding.and_then(|binding| binding.tenant_id.as_deref()))
        .await
    {
        Ok(true) => {
            super::revocation::record_purge(grant_id, binding, Some(&manager.actor));
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => error(StatusCode::NOT_FOUND, "grant_not_found", "Delegated grant not found"),
        Err(error) => {
            warn!(target: "credential_delegation", error = ?error.to_string(), "Failed to purge a delegated grant");
            self::error(StatusCode::INTERNAL_SERVER_ERROR, "purge_failed", "Failed to purge the grant")
        }
    }
}

/// The binding whose grants `DELETE /api/v1/delegation-vault/grants` removes.
#[derive(Debug, Deserialize)]
pub struct BindingGrantsQuery {
    pub surface_id: String,
    #[serde(alias = "transit_point_id")]
    pub hop: String,
    /// The binding's provider; when left out, the one the surface binds at
    /// `hop`.
    #[serde(default)]
    pub credential_provider_id: Option<String>,
    /// The surface's tenant, for an operator removing the grants of a surface
    /// that no longer exists; a tenant's token always means its own.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Only this principal's grant: `owner`, or a caller's identity hash.
    #[serde(default)]
    pub principal: Option<String>,
}

/// `DELETE /api/v1/delegation-vault/grants?surface_id=&hop=[&credential_provider_id=][&principal=][&tenant_id=]`
///
/// Delete a binding's grants, every principal's or one's, and revoke each at
/// its authorization server. The binding need not be saved any more, so the
/// grants a removed binding left can be removed. The grants are read and
/// deleted under the surface's lock, as a surface write and the sweep remove
/// grants, so none a concurrent write puts back is left. A grant that cannot be read is
/// purged, unrevoked, when an operator asks; a tenant's request is refused
/// while one of its grants cannot be read, and deletes none. While the grants
/// stored were written under another identity hash pepper, a binding's grants
/// cannot be found: `409`.
pub async fn delete_binding_grants(
    State(state): State<DelegationVaultState>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    tenant: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Query(query): Query<BindingGrantsQuery>,
) -> Response {
    let manager = match Manager::of(caller, delegation, tenant, scope) {
        Ok(manager) => manager,
        Err(response) => return *response,
    };
    let tenant_id = match (
        &manager.tenant,
        query
            .tenant_id
            .as_deref()
            .filter(|tenant| !tenant.is_empty()),
    ) {
        (Some(context), Some(requested)) if requested != context.tenant_id => return surface_not_found(),
        (Some(context), _) => Some(context.tenant_id.clone()),
        (None, requested) => requested.map(str::to_string),
    };
    let stored_surface = match state
        .agent_surface_store
        .as_ref()
    {
        Some(surfaces) => match surfaces
            .get(&query.surface_id)
            .await
        {
            Ok(surface) => surface,
            Err(error) => {
                warn!(target: "credential_delegation", error = %error, "Failed to read a surface to remove its grants");
                return self::error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "surfaces_unavailable",
                    "Surfaces are unavailable",
                );
            }
        },
        None => None,
    };
    let tenant_id = match &stored_surface {
        Some(surface) if manager.is_operator() && query.tenant_id.is_none() => surface.tenant_id.clone(),
        _ => tenant_id,
    };
    if !manager.may_manage(tenant_id.as_deref(), &query.surface_id)
        || stored_surface
            .as_ref()
            .is_some_and(|surface| surface.tenant_id != tenant_id)
    {
        return surface_not_found();
    }
    let provider_id = match query
        .credential_provider_id
        .clone()
        .or_else(|| {
            stored_surface
                .as_ref()
                .and_then(|surface| {
                    crate::identity::handlers::surface_grants::served_external_bindings(surface)
                        .into_iter()
                        .find(|binding| binding.hop == query.hop)
                        .map(|binding| {
                            binding
                                .credential_provider_id
                                .to_string()
                        })
                })
        }) {
        Some(provider_id) => provider_id,
        None => {
            return error(
                StatusCode::BAD_REQUEST,
                "credential_provider_id_required",
                "The surface binds no provider at this hop: name credential_provider_id",
            );
        }
    };
    let binding = GrantBinding::new(tenant_id.as_deref(), &query.surface_id, &query.hop, &provider_id);
    let lock = Arc::new(crate::identity::handlers::surface_grants::lock_surface(&query.surface_id).await);
    let ids = match state
        .vault_store
        .binding_grant_ids(&binding)
        .await
    {
        Ok(ids) => ids,
        Err(error) if error.is::<super::grants::PepperMismatch>() => {
            return self::error(
                StatusCode::CONFLICT,
                "identity_hash_pepper_mismatch",
                "The delegated grants stored were written under another identity hash pepper than \
                 AG_IDENTITY_HASH_PEPPER now sets, so this binding's grant ids cannot be derived and nothing was \
                 removed. Restore the pepper they were written under, or have an operator purge each grant by its \
                 id with DELETE /api/v1/delegation-vault/grants/{grant_id}: the ids are the file names in the \
                 vault's delegated_grants directory, without .json.enc",
            );
        }
        Err(error) => {
            warn!(target: "credential_delegation", error = ?error.to_string(), "Failed to list a binding's grants");
            return self::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "grants_unavailable",
                "The vault cannot read grants now",
            );
        }
    };
    let only = match query.principal.as_deref() {
        None => None,
        Some(OWNER_PRINCIPAL) => Some(binding.owner_record_id()),
        Some(principal) => {
            match GrantKey::caller(tenant_id.as_deref(), &query.surface_id, &query.hop, &provider_id, principal) {
                Some(key) => Some(key.record_id()),
                None => {
                    return error(
                        StatusCode::BAD_REQUEST,
                        "invalid_principal",
                        "principal is owner or an identity hash",
                    );
                }
            }
        }
    };
    let ids: Vec<String> = ids
        .into_iter()
        .filter(|id| {
            only.as_ref()
                .is_none_or(|only| only == id)
        })
        .collect();
    let mut readable = Vec::new();
    let mut unreadable = Vec::new();
    for id in ids {
        match state
            .vault_store
            .grant_by_id(&id)
            .await
        {
            Ok(Some(grant)) => readable.push(grant),
            Ok(None) => {}
            Err(error) if error.is::<UnreadableGrant>() => unreadable.push(id),
            Err(error) => return grants_unreadable_now(&error),
        }
    }
    if !unreadable.is_empty() && !manager.is_operator() {
        return error(
            StatusCode::CONFLICT,
            "grant_unreadable",
            "A grant of this binding cannot be read, so none was deleted; an operator can purge it",
        );
    }
    let providers = providers_of(&state, &readable).await;
    let removed: Vec<String> = readable
        .iter()
        .map(|grant| grant.id.clone())
        .collect();
    if let Err(error) = delete_and_revoke(&state, &manager, readable, providers, Arc::clone(&lock)).await {
        warn!(target: "credential_delegation", error = %error, "Failed to delete a binding's grants");
        return self::error(StatusCode::SERVICE_UNAVAILABLE, "grants_unavailable", "The grants could not be deleted");
    }
    let mut purged = Vec::new();
    for id in unreadable {
        if purge(&state, &manager, &id, Some(&binding))
            .await
            .status()
            == StatusCode::NO_CONTENT
        {
            purged.push(id);
        }
    }
    (StatusCode::OK, Json(serde_json::json!({ "removed": removed.len(), "grant_ids": removed, "purged": purged })))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_providers::storage::CredentialProviderStorage;
    use crate::delegation_vault::revocation::tests::{Answer, RecordingServer};
    use serde_json::json;
    use std::sync::Arc;

    const CALLBACK: &str = "https://boris.example/api/v1/connect/callback/as-1";
    const CALLER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    struct Fixture {
        _directory: tempfile::TempDir,
        state: DelegationVaultState,
        authorization_server: RecordingServer,
        vendor_origin: String,
    }

    fn token_answer(access_token: &str) -> Answer {
        Answer::json(
            200,
            json!({"access_token": access_token, "token_type": "Bearer", "expires_in": 3600,
                "refresh_token": format!("{access_token}-refresh"), "scope": "read"}),
        )
    }

    /// A token answer whose ID token, of `issuer` for the fixture's client,
    /// names the vendor account `account`.
    fn token_answer_of(
        access_token: &str,
        issuer: &str,
        account: &str,
    ) -> Answer {
        use base64::Engine as _;
        let encode =
            |value: serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string());
        let id_token = format!(
            "{}.{}.signature",
            encode(json!({"alg": "RS256", "typ": "JWT"})),
            encode(json!({"iss": issuer, "aud": "client-1", "sub": account}))
        );
        Answer::json(
            200,
            json!({"access_token": access_token, "token_type": "Bearer", "expires_in": 3600,
                "refresh_token": format!("{access_token}-refresh"), "scope": "read", "id_token": id_token}),
        )
    }

    impl Fixture {
        async fn new(answers: Vec<Answer>) -> Self {
            Self::answering(|_| answers).await
        }

        /// A fixture whose authorization server answers with `answers`, built
        /// from its issuer.
        async fn answering(answers: impl FnOnce(&str) -> Vec<Answer>) -> Self {
            let directory = tempfile::tempdir().unwrap();
            crate::storage::filesystem::init_global_encryption(crate::config::EncryptionConfig {
                enabled: true,
                key_env_var: "AG_TEST_MASTER_KEY".to_string(),
                ..Default::default()
            })
            .unwrap();
            crate::identity::credential_identity::configure_pepper_for_tests(true);
            let authorization_server = RecordingServer::start_answering_for(answers).await;
            let vendor_origin = "http://127.0.0.1:9".to_string();
            let issuer = authorization_server.origin();
            let providers = crate::credential_providers::storage::FileSystemCredentialProviderStore::new(
                directory
                    .path()
                    .join("providers"),
            )
            .await
            .unwrap();
            providers
                .create(
                    serde_json::from_value(json!({
                        "id": "vendor", "tenant_id": "tenant-a", "name": "Vendor", "provider_id": "vendor",
                        "provider_type": "oauth2_authorization_code", "issuer": issuer,
                        "authorization_endpoint": format!("{issuer}/authorize"),
                        "token_endpoint": format!("{issuer}/token"), "revocation_endpoint": format!("{issuer}/revoke"),
                        "token_endpoint_auth_method": "none", "client_id": "client-1", "callback_url": CALLBACK,
                        "resource": format!("{vendor_origin}/mcp"), "default_scopes": ["read", "write"],
                        "authorization_response_iss_parameter_supported": true,
                        "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
            let surfaces = crate::surfaces::FileSystemAgentSurfaceStore::new(
                directory
                    .path()
                    .join("surfaces"),
            )
            .await
            .unwrap();
            let point = |id: &str, subject: &str| {
                json!({"id": id, "alias": id, "target_endpoint": format!("{vendor_origin}/mcp"), "protocol": "mcp",
                    "require_transit_token": true,
                    "transit_credentials": {"credential_provider_id": "vendor", "consent_mode": "external",
                        "subject": subject, "scopes": ["read"]}})
            };
            crate::surfaces::AgentSurfaceStore::save(
                &surfaces,
                &serde_json::from_value(json!({
                    "surface_id": "surface", "name": "surface", "tenant_id": "tenant-a",
                    "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
                    "target": {"endpoint": "https://managed.example/agent"},
                    "transit": {"points": [point("owner-hop", "owner"), point("caller-hop", "caller")]}
                }))
                .unwrap(),
            )
            .await
            .unwrap();
            let state = DelegationVaultState {
                vault_store: Arc::new(
                    crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(
                        directory.path().join("vault"),
                    )
                    .await
                    .unwrap(),
                ),
                provider_store: Arc::new(providers),
                secrets_store: Arc::new(
                    crate::secrets::FilesystemSecretsStore::new(
                        directory
                            .path()
                            .join("secrets")
                            .to_str()
                            .unwrap(),
                    )
                    .unwrap(),
                ),
                gateway_base_url: "https://gateway.example".into(),
                agent_surface_store: Some(Arc::new(surfaces)),
                oauth_callback_route: "/oauth/callback".into(),
                vc_signer: None,
                vc_issuer: None,
                vault_population_notifier: None,
                egress_allowlist: Some(format!("{issuer},{vendor_origin}")),
                resource_origins: Default::default(),
                issuers: Default::default(),
                mcp_proxy_store: None,
            };
            Self {
                _directory: directory,
                state,
                authorization_server,
                vendor_origin,
            }
        }

        fn issuer(&self) -> String {
            self.authorization_server
                .origin()
        }

        async fn start(
            &self,
            tenant: Option<&str>,
            body: serde_json::Value,
        ) -> (StatusCode, serde_json::Value) {
            let request = serde_json::from_value(body).unwrap();
            read(
                start_connect(State(self.state.clone()), caller(), None, tenant_context(tenant), None, Json(request))
                    .await,
            )
            .await
        }

        async fn complete(
            &self,
            connect_id: &str,
            body: serde_json::Value,
        ) -> (StatusCode, serde_json::Value) {
            read(
                complete_connect(
                    State(self.state.clone()),
                    caller(),
                    None,
                    tenant_context(Some("tenant-a")),
                    None,
                    Path(connect_id.to_string()),
                    Json(serde_json::from_value(body).unwrap()),
                )
                .await,
            )
            .await
        }

        async fn grants(
            &self,
            principal: Option<&str>,
        ) -> serde_json::Value {
            let (status, body) = read(
                list_grants(
                    State(self.state.clone()),
                    caller(),
                    None,
                    tenant_context(Some("tenant-a")),
                    None,
                    Query(GrantsQuery {
                        surface_id: "surface".into(),
                        hop: None,
                        principal: principal.map(str::to_string),
                    }),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }

        /// The form fields of every token request the authorization server
        /// received.
        fn token_requests(&self) -> Vec<HashMap<String, String>> {
            self.authorization_server
                .requests()
                .iter()
                .filter(|(head, _)| head.starts_with("POST /token "))
                .map(|(_, body)| {
                    url::form_urlencoded::parse(body.as_bytes())
                        .into_owned()
                        .collect()
                })
                .collect()
        }

        async fn revoked_eventually(
            &self,
            token: &str,
        ) {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !self
                    .authorization_server
                    .revoked_tokens()
                    .contains(&token.to_string())
                {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{token} is revoked"));
        }
    }

    fn caller() -> Option<Extension<AuthGuardOk>> {
        Some(Extension(AuthGuardOk("admin-1".into())))
    }

    fn tenant_context(tenant: Option<&str>) -> Option<Extension<PatTenantContext>> {
        tenant.map(|tenant| {
            Extension(PatTenantContext {
                token_id: "pat-1".into(),
                tenant_id: tenant.into(),
            })
        })
    }

    async fn read(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    fn owner_start() -> serde_json::Value {
        json!({"surface_id": "surface", "hop": "owner-hop", "credential_provider_id": "vendor", "subject": "owner",
            "redirect_uri": CALLBACK})
    }

    /// A connect answers only the S256 challenge; completing it redeems the
    /// code with the verifier behind that challenge, the redirect URI and the
    /// resource, and keeps the grant under its binding. It completes once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connect_redeems_its_code_with_the_verifier_only_the_gateway_holds() {
        let fixture = Fixture::new(vec![token_answer("access-1")]).await;
        let (status, started) = fixture
            .start(Some("tenant-a"), owner_start())
            .await;
        assert_eq!(status, StatusCode::CREATED, "{started}");
        assert_eq!(started["code_challenge_method"], "S256");
        assert!(
            started
                .get("code_verifier")
                .is_none()
        );
        let connect_id = started["connect_id"]
            .as_str()
            .unwrap()
            .to_string();

        let (status, completed) = fixture
            .complete(&connect_id, json!({"code": "the-code", "iss": fixture.issuer()}))
            .await;
        assert_eq!(status, StatusCode::OK, "{completed}");
        assert_eq!(completed["status"], "connected");
        assert_eq!(completed["scopes"], json!(["read"]));
        assert!(
            !completed
                .to_string()
                .contains("access-1"),
            "no token is answered"
        );
        let sent = &fixture.token_requests()[0];
        assert_eq!(sent["grant_type"], "authorization_code");
        assert_eq!(sent["code"], "the-code");
        assert_eq!(sent["redirect_uri"], CALLBACK);
        assert_eq!(sent["resource"], format!("{}/mcp", fixture.vendor_origin));
        assert_eq!(super::super::connects::code_challenge(&sent["code_verifier"]), started["code_challenge"]);
        let key = GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor");
        let grant = fixture
            .state
            .vault_store
            .grant(&key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(grant.access_token, "access-1");
        assert_eq!(completed["grant_id"], grant.id);

        let (status, again) = fixture
            .complete(&connect_id, json!({"code": "the-code", "iss": fixture.issuer()}))
            .await;
        assert_eq!((status, again), (StatusCode::CONFLICT, json!({"status": "failed", "reason": "already_used"})));
        assert_eq!(fixture.token_requests().len(), 1, "a code is redeemed once");

        let listed = fixture.grants(None).await;
        let owner = listed["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|binding| binding["hop"] == "owner-hop")
            .unwrap()
            .clone();
        assert_eq!(owner["connected"], true);
        assert_eq!(owner["grant"]["state"], "live");
        assert!(
            owner["grant"]
                .get("consent_expires_at")
                .is_none(),
            "a grant under no time limit has no end: {owner}"
        );
        assert!(
            !listed
                .to_string()
                .contains("access-1"),
            "no token is listed"
        );
    }

    /// Under a consent time limit a connect says how long the grant will last
    /// before the person consents, and the grant it keeps ends then: at the
    /// shorter of its binding's limit and its provider's. Without a limit
    /// neither answer mentions one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connect_under_a_time_limit_says_how_long_the_grant_lasts_and_stores_its_end() {
        let fixture = Fixture::new(vec![token_answer("access-1"), token_answer("access-2")]).await;
        let (status, started) = fixture
            .start(Some("tenant-a"), owner_start())
            .await;
        assert_eq!(status, StatusCode::CREATED, "{started}");
        assert!(
            started
                .get("max_consent_age_secs")
                .is_none(),
            "{started}"
        );

        let mut provider = fixture
            .state
            .provider_store
            .get("vendor")
            .await
            .unwrap()
            .unwrap();
        provider.max_consent_age_secs = Some(21_600);
        fixture
            .state
            .provider_store
            .update(provider)
            .await
            .unwrap();
        async fn connect(fixture: &Fixture) -> (serde_json::Value, serde_json::Value) {
            let (status, started) = fixture
                .start(Some("tenant-a"), owner_start())
                .await;
            assert_eq!(status, StatusCode::CREATED, "{started}");
            let (status, completed) = fixture
                .complete(
                    started["connect_id"]
                        .as_str()
                        .unwrap(),
                    json!({"code": "the-code", "iss": fixture.issuer()}),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{completed}");
            (started, completed)
        }
        async fn stored(fixture: &Fixture) -> DelegatedGrant {
            fixture
                .state
                .vault_store
                .grant(&GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor"))
                .await
                .unwrap()
                .unwrap()
        }
        async fn reported_end(fixture: &Fixture) -> serde_json::Value {
            fixture.grants(None).await["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|binding| binding["hop"] == "owner-hop")
                .unwrap()["grant"]["consent_expires_at"]
                .clone()
        }

        let (started, completed) = connect(&fixture).await;
        assert_eq!(started["max_consent_age_secs"], 21_600, "the provider's limit");
        let grant = stored(&fixture).await;
        assert_eq!(grant.consent_expires_at, Some(grant.created_at + chrono::Duration::seconds(21_600)));
        assert_eq!(completed["consent_expires_at"], json!(grant.consent_expires_at));
        assert_eq!(reported_end(&fixture).await, json!(grant.consent_expires_at), "the report names the end");

        let surfaces = fixture
            .state
            .agent_surface_store
            .clone()
            .unwrap();
        let mut surface = surfaces
            .get("surface")
            .await
            .unwrap()
            .unwrap();
        surface
            .transit
            .as_mut()
            .unwrap()
            .points
            .iter_mut()
            .find(|point| point.id == "owner-hop")
            .unwrap()
            .transit_credentials
            .as_mut()
            .unwrap()
            .max_consent_age_secs = Some(3_600);
        surfaces
            .save(&surface)
            .await
            .unwrap();
        assert_eq!(
            reported_end(&fixture).await,
            json!(grant.created_at + chrono::Duration::seconds(3_600)),
            "a limit the binding set since ends the grant sooner"
        );
        let (started, _) = connect(&fixture).await;
        assert_eq!(started["max_consent_age_secs"], 3_600, "the binding's shorter limit");
        let grant = stored(&fixture).await;
        assert_eq!(grant.consent_expires_at, Some(grant.created_at + chrono::Duration::seconds(3_600)));
    }

    /// A Transit Point whose target is an MCP Proxy starts a connect only while
    /// that proxy, of the surface's tenant and served only through surfaces,
    /// sends its tool calls to the origin of the provider's resource, is still
    /// the proxy the binding was pinned to, has no method override header in
    /// its spec, and while the Transit Point meets every rule a call to it
    /// does: a proxy edited to point elsewhere, to call other operations, to
    /// take a method override header, or opened to direct callers, a binding never
    /// pinned, and a Transit Point that does not speak MCP, has a target_auth
    /// or puts the grant in `_meta`, are refused, so no consent is run for a
    /// binding every call would refuse. A binding whose proxy changed since it
    /// was pinned, or that was never pinned, is told a save re-pins it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_proxy_transit_point_connects_only_while_every_call_to_it_could_carry_the_grant() {
        use crate::credential_providers::external::tests::grant_proxy;
        use crate::mcp_proxies::McpProxyStore;
        let mut fixture = Fixture::new(vec![token_answer("proxy-access")]).await;
        let directory = tempfile::tempdir().unwrap();
        let proxies = Arc::new(
            crate::mcp_proxies::FileSystemMcpProxyStore::new(directory.path().to_path_buf())
                .await
                .unwrap(),
        );
        let mut servable = grant_proxy("drive", Some("tenant-a"), &format!("{}/drive/v3", fixture.vendor_origin));
        servable.openapi_spec =
            r#"{"openapi": "3.0.0", "paths": {"/files": {"get": {"operationId": "search"}}}}"#.into();
        proxies
            .create(&servable)
            .await
            .unwrap();
        fixture.state.mcp_proxy_store = Some(proxies.clone());
        let point = json!({"id": "drive-hop", "alias": "drive", "target_endpoint": "proxy://drive",
            "protocol": "mcp", "require_transit_token": true,
            "transit_credentials": {"credential_provider_id": "vendor", "consent_mode": "external",
                "subject": "owner", "scopes": ["read"]}});
        let surfaces = fixture
            .state
            .agent_surface_store
            .clone()
            .unwrap();
        let save = |point: serde_json::Value, pinned: bool| {
            let (surfaces, proxies) = (surfaces.clone(), proxies.clone());
            async move {
                let mut surface: crate::config::agent_surface::AgentSurface = serde_json::from_value(json!({
                    "surface_id": "drive-agent", "name": "drive-agent", "tenant_id": "tenant-a",
                    "access_point": {"listen_address": "https://gateway.example", "route": "/drive", "protocol": "mcp"},
                    "target": {"endpoint": "https://managed.example/agent"},
                    "transit": {"points": [point]}
                }))
                .unwrap();
                if pinned {
                    crate::identity::handlers::surface_tenancy::pin_mcp_proxy_grants(
                        &mut surface,
                        None,
                        Some(proxies.as_ref() as &dyn McpProxyStore),
                    )
                    .await
                    .expect("a new binding is pinned");
                }
                surfaces
                    .save(&surface)
                    .await
                    .unwrap();
            }
        };
        let start = json!({"surface_id": "drive-agent", "hop": "drive-hop", "credential_provider_id": "vendor",
            "subject": "owner", "redirect_uri": CALLBACK});
        let refused = |case: &'static str| {
            let (fixture, start) = (&fixture, start.clone());
            async move {
                let (status, refused) = fixture
                    .start(Some("tenant-a"), start)
                    .await;
                assert_eq!(
                    (status, refused["code"].clone()),
                    (StatusCode::CONFLICT, json!("binding_not_servable")),
                    "{case}"
                );
                refused["error"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            }
        };
        let re_pin = "save the surface with the proxy's current grant_pin";
        save(point.clone(), true).await;
        let (status, started) = fixture
            .start(Some("tenant-a"), start.clone())
            .await;
        assert_eq!(status, StatusCode::CREATED, "{started}");

        save(point.clone(), false).await;
        let never_pinned = refused("a binding stored outside the API, never pinned").await;
        assert!(never_pinned.contains(re_pin), "a binding without a pin is told to re-pin: {never_pinned}");
        let mut with_target_auth = point.clone();
        with_target_auth["target_auth"] =
            json!({"method": {"static_secret": {"secret_id": "vendor-key", "header_name": "x-key"}}});
        let mut a2a = point.clone();
        a2a["protocol"] = json!("a2a");
        let mut in_meta = point.clone();
        in_meta["transit_credentials"]["inject_as"] = json!({"type": "meta", "field": "token"});
        for (case, point) in
            [("a target_auth", with_target_auth), ("protocol a2a", a2a), ("the grant in _meta", in_meta)]
        {
            save(point, true).await;
            let message = refused(case).await;
            assert!(!message.contains(re_pin), "{case}: a save would not fix it: {message}");
        }

        save(point.clone(), true).await;
        let mut other_operations = servable.clone();
        other_operations.openapi_spec =
            r#"{"openapi": "3.0.0", "paths": {"/files/trash": {"delete": {"operationId": "search"}}}}"#.into();
        let mut elsewhere = servable.clone();
        elsewhere.base_url = "http://127.0.0.1:10/drive/v3".into();
        let mut direct = servable.clone();
        direct.direct_access = true;
        for (case, proxy) in
            [("other operations", other_operations.clone()), ("another origin", elsewhere), ("direct callers", direct)]
        {
            proxies
                .update(&proxy)
                .await
                .unwrap();
            let message = refused(case).await;
            if case == "other operations" {
                assert!(message.contains(re_pin), "{case}: only a re-pinning save is needed: {message}");
            }
        }
        let mut overriding = servable.clone();
        overriding.openapi_spec = r#"{"openapi": "3.0.0", "info": {"title": "Drive", "version": "1"},
            "paths": {"/files": {"get": {"operationId": "search", "parameters": [{"name": "X-HTTP-Method-Override",
                "in": "header", "schema": {"type": "string"}}], "responses": {"200": {"description": "Files"}}}}}}"#
            .into();
        proxies
            .update(&overriding)
            .await
            .unwrap();
        save(point.clone(), true).await;
        refused("a spec with a method override header, pinned as it is").await;
        proxies
            .update(&other_operations)
            .await
            .unwrap();
        save(point, true).await;
        let (status, started) = fixture
            .start(Some("tenant-a"), start)
            .await;
        assert_eq!(status, StatusCode::CREATED, "saved again, the surface is pinned to the proxy as it is: {started}");
    }

    /// The Access Point Target's binding is connected under the hop `target`:
    /// its grant is kept, reported and removed as a Transit Point's is, and
    /// the hop serves only a surface whose Target holds the binding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_access_point_targets_binding_is_connected_under_the_hop_target() {
        let fixture = Fixture::new(vec![token_answer("target-access"), Answer::status(200)]).await;
        let surfaces = fixture
            .state
            .agent_surface_store
            .clone()
            .unwrap();
        surfaces
            .save(
                &serde_json::from_value(json!({
                    "surface_id": "vendor-agent", "name": "vendor-agent", "tenant_id": "tenant-a",
                    "access_point": {"listen_address": "https://gateway.example", "route": "/vendor", "protocol": "mcp"},
                    "target": {"endpoint": format!("{}/mcp", fixture.vendor_origin)},
                    "outbound_credentials": [{"credential_provider_id": "vendor", "consent_mode": "external",
                        "subject": "caller", "scopes": ["read"]}]
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let target_start = |surface: &str| {
            json!({"surface_id": surface, "hop": "target", "credential_provider_id": "vendor", "subject": "caller",
                "principal": CALLER, "redirect_uri": CALLBACK})
        };
        let (status, refused) = fixture
            .start(Some("tenant-a"), target_start("surface"))
            .await;
        assert_eq!((status, refused["code"].clone()), (StatusCode::NOT_FOUND, json!("binding_not_found")));

        let (status, started) = fixture
            .start(Some("tenant-a"), target_start("vendor-agent"))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{started}");
        let (status, completed) = fixture
            .complete(
                started["connect_id"]
                    .as_str()
                    .unwrap(),
                json!({"code": "code", "iss": fixture.issuer()}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{completed}");
        let key = GrantKey::caller(Some("tenant-a"), "vendor-agent", "target", "vendor", CALLER).unwrap();
        let grant = fixture
            .state
            .vault_store
            .grant(&key)
            .await
            .unwrap()
            .expect("the Target's grant is kept under the hop target");
        assert_eq!(grant.access_token, "target-access");
        assert_eq!(completed["grant_id"], grant.id);

        let (status, listed) = read(
            list_grants(
                State(fixture.state.clone()),
                caller(),
                None,
                tenant_context(Some("tenant-a")),
                None,
                Query(GrantsQuery {
                    surface_id: "vendor-agent".into(),
                    hop: Some("target".into()),
                    principal: Some(CALLER.into()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{listed}");
        assert_eq!(listed["bindings"][0]["hop"], "target");
        assert_eq!(listed["bindings"][0]["subject"], "caller");
        assert_eq!(listed["bindings"][0]["callers"], 1);
        assert_eq!(listed["bindings"][0]["grant"]["grant_id"], grant.id);
        for malformed in ["not-an-identity-hash", &CALLER.to_uppercase(), &CALLER[1..]] {
            let (status, refused) = read(
                list_grants(
                    State(fixture.state.clone()),
                    caller(),
                    None,
                    tenant_context(Some("tenant-a")),
                    None,
                    Query(GrantsQuery {
                        surface_id: "vendor-agent".into(),
                        hop: Some("target".into()),
                        principal: Some(malformed.into()),
                    }),
                )
                .await,
            )
            .await;
            assert_eq!(
                (status, refused["code"].as_str()),
                (StatusCode::BAD_REQUEST, Some("invalid_principal")),
                "a malformed principal {malformed:?} is refused, as on connect and removal: {refused}"
            );
        }

        let (status, removed) = read(
            delete_binding_grants(
                State(fixture.state.clone()),
                caller(),
                None,
                tenant_context(Some("tenant-a")),
                None,
                Query(BindingGrantsQuery {
                    surface_id: "vendor-agent".into(),
                    hop: "target".into(),
                    credential_provider_id: None,
                    principal: None,
                    tenant_id: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{removed}");
        assert_eq!(removed["grant_ids"], json!([grant.id]));
        assert!(
            fixture
                .state
                .vault_store
                .grant(&key)
                .await
                .unwrap()
                .is_none()
        );
        fixture
            .revoked_eventually("target-access-refresh")
            .await;
    }

    /// A connect is refused for a binding the surface does not serve, another
    /// subject, a principal that does not fit the subject, a redirect URI that
    /// is not the provider's callback, scopes beyond the binding's, another
    /// tenant's surface, and an issuer the operator does not list.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connect_is_refused_unless_it_fits_its_binding() {
        let fixture = Fixture::new(vec![token_answer("unused")]).await;
        let change = |field: &str, value: serde_json::Value| {
            let mut body = owner_start();
            body[field] = value;
            body
        };
        for (body, tenant, status, code) in [
            (change("hop", json!("unknown-hop")), Some("tenant-a"), StatusCode::NOT_FOUND, "binding_not_found"),
            (
                change("credential_provider_id", json!("other")),
                Some("tenant-a"),
                StatusCode::NOT_FOUND,
                "binding_not_found",
            ),
            (change("subject", json!("caller")), Some("tenant-a"), StatusCode::BAD_REQUEST, "subject_mismatch"),
            (change("principal", json!(CALLER)), Some("tenant-a"), StatusCode::BAD_REQUEST, "invalid_principal"),
            (
                change("redirect_uri", json!("https://attacker.example/cb")),
                Some("tenant-a"),
                StatusCode::BAD_REQUEST,
                "redirect_uri_mismatch",
            ),
            (
                change("scopes", json!(["read", "write"])),
                Some("tenant-a"),
                StatusCode::BAD_REQUEST,
                "scope_not_permitted",
            ),
            (owner_start(), Some("tenant-b"), StatusCode::NOT_FOUND, "surface_not_found"),
        ] {
            let (answered, answer) = fixture
                .start(tenant, body.clone())
                .await;
            assert_eq!((answered, answer["code"].as_str()), (status, Some(code)), "{body}");
        }
        let mut caller = owner_start();
        caller["hop"] = json!("caller-hop");
        caller["subject"] = json!("caller");
        let (status, answer) = fixture
            .start(Some("tenant-a"), caller.clone())
            .await;
        assert_eq!((status, answer["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid_principal")));
        caller["principal"] = json!(CALLER);
        assert_eq!(
            fixture
                .start(Some("tenant-a"), caller)
                .await
                .0,
            StatusCode::CREATED
        );

        let mut state = fixture.state.clone();
        state.issuers =
            Arc::new(crate::credential_providers::external::PermittedIssuers::new(Some(HashMap::new()), None));
        let (status, answer) = read(
            start_connect(
                State(state),
                caller_extension(),
                None,
                tenant_context(Some("tenant-a")),
                None,
                Json(serde_json::from_value(owner_start()).unwrap()),
            )
            .await,
        )
        .await;
        assert_eq!((status, answer["code"].as_str()), (StatusCode::FORBIDDEN, Some("issuer_not_permitted")));
        assert!(
            fixture
                .token_requests()
                .is_empty()
        );
    }

    /// `external_consent_issuer_patterns` alone limits issuers as the exact
    /// list does: a connect for a provider whose issuer matches a pattern
    /// starts, and its completion passes the rule and reaches the token
    /// endpoint (here a loopback one Strict egress refuses, so nothing leaves);
    /// once no pattern matches, the completion and a new start are refused
    /// `issuer_not_permitted`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_connect_runs_only_while_its_providers_issuer_matches_an_operator_pattern() {
        use crate::config::network::{IssuerPattern, IssuerTenant};
        use crate::credential_providers::external::PermittedIssuers;
        let mut fixture = Fixture::new(vec![Answer::status(500)]).await;
        let issuer = "https://203.0.113.10/1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b";
        let mut provider = fixture
            .state
            .provider_store
            .get("vendor")
            .await
            .unwrap()
            .unwrap();
        provider.issuer = Some(issuer.into());
        provider.authorization_endpoint = Some(format!("{issuer}/authorize"));
        provider.token_endpoint = Some("https://127.0.0.1:1/token".into());
        provider.revocation_endpoint = None;
        provider.resource = Some("https://203.0.113.10/mcp".into());
        fixture
            .state
            .provider_store
            .update(provider)
            .await
            .unwrap();
        let surfaces = fixture
            .state
            .agent_surface_store
            .clone()
            .unwrap();
        let mut surface = surfaces
            .get("surface")
            .await
            .unwrap()
            .unwrap();
        for point in &mut surface
            .transit
            .as_mut()
            .unwrap()
            .points
        {
            point.target_endpoint = "https://203.0.113.10/mcp".into();
        }
        surfaces
            .save(&surface)
            .await
            .unwrap();
        let matching = Arc::new(PermittedIssuers::new(
            None,
            Some(vec![IssuerPattern {
                issuer: "https://203.0.113.10/{tenant}".into(),
                tenant: IssuerTenant::Uuid,
                endpoint_origins: vec!["https://127.0.0.1:1".into()],
                resource_origins: Vec::new(),
            }]),
        ));
        let none_matching = Arc::new(PermittedIssuers::new(None, Some(Vec::new())));
        let complete = |fixture: &Fixture, connect_id: String| {
            let fixture_state = fixture.state.clone();
            async move {
                read(
                    complete_connect(
                        State(fixture_state),
                        caller(),
                        None,
                        tenant_context(Some("tenant-a")),
                        None,
                        Path(connect_id),
                        Json(serde_json::from_value(json!({"code": "c", "iss": issuer})).unwrap()),
                    )
                    .await,
                )
                .await
            }
        };

        fixture.state.issuers = Arc::clone(&matching);
        let (status, started) = fixture
            .start(Some("tenant-a"), owner_start())
            .await;
        assert_eq!(status, StatusCode::CREATED, "{started}");
        let connect_id = started["connect_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            complete(&fixture, connect_id).await,
            (StatusCode::BAD_GATEWAY, json!({"status": "failed", "reason": "token_endpoint_unreachable"}))
        );

        let (status, started) = fixture
            .start(Some("tenant-a"), owner_start())
            .await;
        assert_eq!(status, StatusCode::CREATED, "{started}");
        let connect_id = started["connect_id"]
            .as_str()
            .unwrap()
            .to_string();
        fixture.state.issuers = none_matching;
        assert_eq!(
            complete(&fixture, connect_id).await,
            (StatusCode::FORBIDDEN, json!({"status": "failed", "reason": "issuer_not_permitted"}))
        );
        let (status, answer) = fixture
            .start(Some("tenant-a"), owner_start())
            .await;
        assert_eq!((status, answer["code"].as_str()), (StatusCode::FORBIDDEN, Some("issuer_not_permitted")));
    }

    fn caller_extension() -> Option<Extension<AuthGuardOk>> {
        caller()
    }

    /// A completion with another `iss`, or none when the issuer says it sends
    /// one, is refused before the connect is claimed and the code redeemed, so
    /// the connect can still be completed with the provider's `iss`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_completion_is_refused_for_an_iss_that_is_not_the_providers() {
        let fixture = Fixture::new(vec![token_answer("first"), token_answer("second")]).await;
        for (body, reason) in [
            (json!({"code": "the-code", "iss": "https://attacker.example"}), "iss_mismatch"),
            (json!({"code": "the-code"}), "iss_missing"),
        ] {
            let (_, started) = fixture
                .start(Some("tenant-a"), owner_start())
                .await;
            let connect_id = started["connect_id"]
                .as_str()
                .unwrap()
                .to_string();
            let (status, answer) = fixture
                .complete(&connect_id, body)
                .await;
            assert_eq!((status, answer), (StatusCode::BAD_REQUEST, json!({"status": "failed", "reason": reason})));
            let (status, answer) = fixture
                .complete(&connect_id, json!({"code": "the-code", "iss": fixture.issuer()}))
                .await;
            assert_eq!(status, StatusCode::OK, "{answer}");
            assert_eq!(answer["status"], "connected");
        }
        assert_eq!(fixture.token_requests().len(), 2, "only the completions with the provider's iss redeemed the code");
    }

    /// A provider created before the gateway recorded whether its issuer
    /// sends `iss` needs `iss` all the same: nothing says its issuer omits
    /// it. Only a provider whose issuer's metadata said so completes without.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_provider_created_before_iss_was_recorded_needs_iss() {
        let fixture = Fixture::new(vec![token_answer("access")]).await;
        let set_flag = |flag: Option<bool>| {
            let providers = fixture
                .state
                .provider_store
                .clone();
            async move {
                let mut provider = providers
                    .get("vendor")
                    .await
                    .unwrap()
                    .unwrap();
                provider.authorization_response_iss_parameter_supported = flag;
                providers
                    .update(provider)
                    .await
                    .unwrap();
            }
        };
        let complete_without_iss = || async {
            let (_, started) = fixture
                .start(Some("tenant-a"), owner_start())
                .await;
            fixture
                .complete(
                    started["connect_id"]
                        .as_str()
                        .unwrap(),
                    json!({"code": "the-code"}),
                )
                .await
        };
        set_flag(None).await;
        assert_eq!(
            complete_without_iss().await,
            (StatusCode::BAD_REQUEST, json!({"status": "failed", "reason": "iss_missing"}))
        );
        assert!(
            fixture
                .token_requests()
                .is_empty()
        );
        set_flag(Some(false)).await;
        assert_eq!(complete_without_iss().await.0, StatusCode::OK);
    }

    /// A refused code, or an answer granting more than was asked, keeps no
    /// grant; tokens granted beyond the request are revoked. A wider answer
    /// names the scopes beyond the request, those spelled as scope tokens
    /// only, so the operator can see what the vendor added.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_or_wider_answer_keeps_no_grant() {
        let wider = Answer::json(
            200,
            json!({"access_token": "wide", "token_type": "Bearer", "refresh_token": "wide-refresh",
                "scope": "read admin say\"hi\""}),
        );
        let fixture = Fixture::new(vec![
            Answer::json(400, json!({"error": "invalid_grant", "error_description": "vendor words"})),
            wider,
            Answer::status(200),
        ])
        .await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor");
        for (reason, expected) in [
            ("invalid_grant", json!({"status": "failed", "reason": "invalid_grant"})),
            ("scope_widened", json!({"status": "failed", "reason": "scope_widened", "widened_scopes": ["admin"]})),
        ] {
            let (_, started) = fixture
                .start(Some("tenant-a"), owner_start())
                .await;
            let (status, answer) = fixture
                .complete(
                    started["connect_id"]
                        .as_str()
                        .unwrap(),
                    json!({"code": "c", "iss": fixture.issuer()}),
                )
                .await;
            assert_eq!((status, answer), (StatusCode::BAD_GATEWAY, expected), "{reason}");
            assert!(
                fixture
                    .state
                    .vault_store
                    .grant(&key)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        fixture
            .revoked_eventually("wide-refresh")
            .await;
    }

    /// Set the provider's scope comparison, and the scopes the owner binding
    /// names.
    async fn compare_scopes_as(
        fixture: &Fixture,
        comparison: crate::credential_providers::scope_comparison::ScopeComparison,
        binding_scopes: &[&str],
    ) {
        let mut provider = fixture
            .state
            .provider_store
            .get("vendor")
            .await
            .unwrap()
            .unwrap();
        provider.scope_comparison = comparison;
        fixture
            .state
            .provider_store
            .update(provider)
            .await
            .unwrap();
        let surfaces = fixture
            .state
            .agent_surface_store
            .as_ref()
            .unwrap();
        let mut surface = surfaces
            .get("surface")
            .await
            .unwrap()
            .unwrap();
        for point in &mut surface
            .transit
            .as_mut()
            .unwrap()
            .points
        {
            if point.id == "owner-hop" {
                point
                    .transit_credentials
                    .as_mut()
                    .unwrap()
                    .scopes = binding_scopes
                    .iter()
                    .map(|scope| scope.to_string())
                    .collect();
            }
        }
        surfaces
            .save(&surface)
            .await
            .unwrap();
    }

    /// Google's and Entra's token answers, as they come: Google names `email`
    /// by its userinfo URL and adds `openid`; Entra qualifies Graph scopes
    /// with their resource and adds the OpenID Connect scopes and `User.Read`.
    /// With the provider's comparison set to its vendor, neither is a wider
    /// grant: the grant is kept, with the scopes asked for beside the ones the
    /// vendor named. The default exact comparison refuses Google's answer, and
    /// a scope nobody asked for is refused either way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_vendor_that_renames_or_adds_standard_scopes_is_compared_as_its_provider_says() {
        use crate::credential_providers::scope_comparison::ScopeComparison;
        let google = Answer::json(
            200,
            json!({"access_token": "google-access", "expires_in": 3599, "refresh_token": "google-refresh",
                "scope": "https://www.googleapis.com/auth/userinfo.email openid https://www.googleapis.com/auth/drive.readonly",
                "token_type": "Bearer", "id_token": "google-id-token"}),
        );
        let entra = Answer::json(
            200,
            json!({"token_type": "Bearer",
                "scope": "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read openid profile email",
                "expires_in": 4247, "ext_expires_in": 4247, "access_token": "entra-access",
                "refresh_token": "entra-refresh"}),
        );
        let google_scopes = ["https://www.googleapis.com/auth/drive.readonly", "email"];
        for (comparison, binding_scopes, answer, outcome) in [
            (ScopeComparison::Google, &google_scopes[..], google.clone(), "connected"),
            (ScopeComparison::Exact, &google_scopes[..], google, "scope_widened"),
            (ScopeComparison::Microsoft, &["Mail.Read"][..], entra, "connected"),
            (
                ScopeComparison::Microsoft,
                &["Mail.Read"][..],
                Answer::json(
                    200,
                    json!({"token_type": "Bearer", "access_token": "entra-access", "refresh_token": "entra-refresh",
                        "scope": "https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.Send"}),
                ),
                "scope_widened",
            ),
        ] {
            let fixture = Fixture::new(vec![answer, Answer::status(200)]).await;
            compare_scopes_as(&fixture, comparison, binding_scopes).await;
            let (status, started) = fixture
                .start(Some("tenant-a"), owner_start())
                .await;
            assert_eq!(status, StatusCode::CREATED, "{started}");
            let (_, completed) = fixture
                .complete(
                    started["connect_id"]
                        .as_str()
                        .unwrap(),
                    json!({"code": "the-code", "iss": fixture.issuer()}),
                )
                .await;
            let reached = completed["status"]
                .as_str()
                .filter(|status| *status == "connected")
                .or(completed["reason"].as_str());
            assert_eq!(reached, Some(outcome), "{comparison:?}: {completed}");
            if outcome == "connected" {
                let grant = fixture
                    .state
                    .vault_store
                    .grant(&GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor"))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    grant
                        .requested_scopes
                        .clone()
                        .unwrap_or_default(),
                    binding_scopes,
                    "{comparison:?}"
                );
                assert!(grant.scopes.len() > binding_scopes.len(), "the vendor's own words are kept: {comparison:?}");
            }
        }
    }

    /// A binding narrowed while the person consented keeps no grant asked for
    /// beyond its new scopes: the connect answers `binding_changed` and the
    /// tokens are revoked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_binding_narrowed_while_the_person_consents_keeps_no_wider_grant() {
        use crate::credential_providers::scope_comparison::ScopeComparison;
        let wide = Answer::json(
            200,
            json!({"access_token": "wide", "token_type": "Bearer", "refresh_token": "wide-refresh",
                "scope": "read write"}),
        );
        let fixture = Fixture::new(vec![wide, Answer::status(200)]).await;
        compare_scopes_as(&fixture, ScopeComparison::Exact, &["read", "write"]).await;
        let (_, started) = fixture
            .start(Some("tenant-a"), owner_start())
            .await;
        compare_scopes_as(&fixture, ScopeComparison::Exact, &["read"]).await;
        let (status, answer) = fixture
            .complete(
                started["connect_id"]
                    .as_str()
                    .unwrap(),
                json!({"code": "c", "iss": fixture.issuer()}),
            )
            .await;
        assert_eq!((status, answer), (StatusCode::CONFLICT, json!({"status": "failed", "reason": "binding_changed"})));
        assert!(
            fixture
                .state
                .vault_store
                .grant(&GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor"))
                .await
                .unwrap()
                .is_none()
        );
        fixture
            .revoked_eventually("wide-refresh")
            .await;
    }

    /// At a provider whose revocation ends the whole authorization of the
    /// vendor account that consented, a reconnect with the same account, as
    /// the connects' ID tokens name it, leaves the grant it replaces
    /// unrevoked: revoking it would end the new grant too. A reconnect with
    /// another account revokes the grant it replaces, whose authorization no
    /// grant uses any more. The grant records its account.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reconnect_at_a_vendor_whose_revocation_ends_the_authorization_revokes_only_another_accounts_grant() {
        let fixture = Fixture::answering(|issuer| {
            vec![
                token_answer_of("first", issuer, "account-1"),
                token_answer_of("second", issuer, "account-1"),
                token_answer_of("third", issuer, "account-2"),
                Answer::status(200),
            ]
        })
        .await;
        let mut provider = fixture
            .state
            .provider_store
            .get("vendor")
            .await
            .unwrap()
            .unwrap();
        provider.revocation_ends_authorization = true;
        fixture
            .state
            .provider_store
            .update(provider)
            .await
            .unwrap();
        let connect = |code: &'static str| {
            let fixture = &fixture;
            async move {
                let (_, started) = fixture
                    .start(Some("tenant-a"), owner_start())
                    .await;
                let (status, completed) = fixture
                    .complete(
                        started["connect_id"]
                            .as_str()
                            .unwrap(),
                        json!({"code": code, "iss": fixture.issuer()}),
                    )
                    .await;
                assert_eq!(status, StatusCode::OK, "{completed}");
            }
        };
        let stored = || async {
            fixture
                .state
                .vault_store
                .grant(&GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor"))
                .await
                .unwrap()
                .unwrap()
        };
        connect("c1").await;
        connect("c2").await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            fixture
                .authorization_server
                .revoked_tokens()
                .is_empty(),
            "the grant replaced by the same account is not revoked: {:?}",
            fixture
                .authorization_server
                .revoked_tokens()
        );
        let grant = stored().await;
        assert_eq!(grant.access_token, "second");
        assert_eq!(
            grant
                .vendor_subject
                .as_deref(),
            Some("account-1")
        );

        connect("c3").await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while fixture
                .authorization_server
                .revoked_tokens()
                != ["second", "second-refresh"]
            {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the grant replaced by another account is revoked");
        assert_eq!(
            stored()
                .await
                .vendor_subject
                .as_deref(),
            Some("account-2")
        );
    }

    /// A grant whose binding was removed while the person consented is not
    /// kept, and its tokens are revoked; a reconnect replaces the grant and
    /// revokes the one it replaces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_grant_is_kept_only_while_its_binding_is_and_a_reconnect_revokes_the_old_one() {
        let fixture = Fixture::new(vec![
            token_answer("first"),
            token_answer("second"),
            Answer::status(200),
            Answer::status(200),
            token_answer("third"),
            Answer::status(200),
        ])
        .await;
        let connect = || async {
            let (_, started) = fixture
                .start(Some("tenant-a"), owner_start())
                .await;
            started["connect_id"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let first = connect().await;
        let second = connect().await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor");
        assert_eq!(
            fixture
                .complete(&first, json!({"code": "c1", "iss": fixture.issuer()}))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            fixture
                .complete(&second, json!({"code": "c2", "iss": fixture.issuer()}))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            fixture
                .state
                .vault_store
                .grant(&key)
                .await
                .unwrap()
                .unwrap()
                .access_token,
            "second"
        );
        fixture
            .revoked_eventually("first-refresh")
            .await;
        fixture
            .revoked_eventually("first")
            .await;

        let third = connect().await;
        let surfaces = fixture
            .state
            .agent_surface_store
            .as_ref()
            .unwrap();
        let mut surface = surfaces
            .get("surface")
            .await
            .unwrap()
            .unwrap();
        surface
            .transit
            .as_mut()
            .unwrap()
            .points
            .retain(|point| point.id != "owner-hop");
        surfaces
            .save(&surface)
            .await
            .unwrap();
        let (status, answer) = fixture
            .complete(&third, json!({"code": "c3", "iss": fixture.issuer()}))
            .await;
        assert_eq!((status, answer), (StatusCode::CONFLICT, json!({"status": "failed", "reason": "binding_removed"})));
        fixture
            .revoked_eventually("third-refresh")
            .await;
    }

    /// Callers are counted from the vault's file names, a caller's own grant is
    /// listed with `principal`, and a tenant deletes its own grant by id,
    /// revoking it; another tenant's token finds nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn callers_are_counted_and_a_tenant_deletes_and_revokes_its_own_grant() {
        let fixture = Fixture::new(vec![token_answer("caller-access"), Answer::status(200)]).await;
        let mut body = owner_start();
        body["hop"] = json!("caller-hop");
        body["subject"] = json!("caller");
        body["principal"] = json!(CALLER);
        let (_, started) = fixture
            .start(Some("tenant-a"), body)
            .await;
        let (_, completed) = fixture
            .complete(
                started["connect_id"]
                    .as_str()
                    .unwrap(),
                json!({"code": "c", "iss": fixture.issuer()}),
            )
            .await;
        let grant_id = completed["grant_id"]
            .as_str()
            .unwrap()
            .to_string();
        let binding = |listed: &serde_json::Value| {
            listed["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|binding| binding["hop"] == "caller-hop")
                .unwrap()
                .clone()
        };
        let listed = binding(&fixture.grants(None).await);
        assert_eq!(listed["callers"], 1);
        assert!(listed.get("grant").is_none());
        let own = binding(
            &fixture
                .grants(Some(CALLER))
                .await,
        );
        assert_eq!(own["grant"]["grant_id"], grant_id);
        assert_eq!(own["grant"]["principal"], CALLER);

        let delete = |tenant: &'static str| {
            let state = fixture.state.clone();
            let grant_id = grant_id.clone();
            async move {
                delete_grant(State(state), caller(), None, tenant_context(Some(tenant)), None, Path(grant_id))
                    .await
                    .status()
            }
        };
        assert_eq!(delete("tenant-b").await, StatusCode::NOT_FOUND);
        assert_eq!(delete("tenant-a").await, StatusCode::NO_CONTENT);
        assert_eq!(delete("tenant-a").await, StatusCode::NOT_FOUND);
        fixture
            .revoked_eventually("caller-access-refresh")
            .await;
        fixture
            .revoked_eventually("caller-access")
            .await;
        assert_eq!(binding(&fixture.grants(None).await)["callers"], 0);
    }

    /// A grant that cannot be read now because the vault's storage fails, as a
    /// disk or a key service outage makes it, is neither purged nor removed,
    /// even by an operator: the removal answers `503` and says so. Only a
    /// record that cannot be decrypted or parsed is purged.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_outage_purges_nothing_and_says_so() {
        use std::os::unix::fs::PermissionsExt as _;
        let fixture = Fixture::new(vec![Answer::status(200)]).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor");
        fixture
            .state
            .vault_store
            .store_grant(crate::delegation_vault::grants::tests::grant(&key, "access"))
            .await
            .unwrap();
        let file = fixture
            ._directory
            .path()
            .join("vault/delegated_grants")
            .join(format!("{}.json.enc", key.record_id()));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&file).is_ok() {
            // Running as root: no read fails, so there is no outage to show.
            return;
        }
        let (status, body) =
            read(delete_grant(State(fixture.state.clone()), caller(), None, None, None, Path(key.record_id())).await)
                .await;
        assert_eq!((status, body["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("grants_unavailable")));
        assert!(file.exists(), "nothing is purged during an outage");
        let (status, body) = read(
            delete_binding_grants(
                State(fixture.state.clone()),
                caller(),
                None,
                None,
                None,
                Query(BindingGrantsQuery {
                    surface_id: "surface".into(),
                    hop: "owner-hop".into(),
                    credential_provider_id: None,
                    tenant_id: None,
                    principal: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!((status, body["code"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("grants_unavailable")));
        assert!(file.exists(), "nor by binding");

        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&file, "not a grant").unwrap();
        let status = delete_grant(State(fixture.state.clone()), caller(), None, None, None, Path(key.record_id()))
            .await
            .status();
        assert_eq!(status, StatusCode::NO_CONTENT, "a record that cannot be parsed is purged");
        assert!(!file.exists());
    }

    /// While a surface write holds the surface's lock it may have deleted a
    /// grant and put it back when its save fails. A person's delete, of the
    /// grant or of the binding's grants, waits for that lock and reads the
    /// grants again under it, so the grant the write put back is deleted and
    /// revoked, never released again after the person was told it is gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_grant_delete_waits_for_a_surface_write_and_deletes_the_grant_it_put_back() {
        let key = GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor");
        for by_binding in [false, true] {
            let fixture = Fixture::new(vec![Answer::status(200)]).await;
            let vault = fixture
                .state
                .vault_store
                .clone();
            let grant = vault
                .store_grant(crate::delegation_vault::grants::tests::grant(&key, "owner-access"))
                .await
                .unwrap()
                .grant;
            let held = crate::identity::handlers::surface_grants::lock_surface("surface").await;
            let state = fixture.state.clone();
            let delete = tokio::spawn(async move {
                if by_binding {
                    delete_binding_grants(
                        State(state),
                        caller(),
                        None,
                        tenant_context(Some("tenant-a")),
                        None,
                        Query(BindingGrantsQuery {
                            surface_id: "surface".into(),
                            hop: "owner-hop".into(),
                            credential_provider_id: None,
                            tenant_id: None,
                            principal: None,
                        }),
                    )
                    .await
                    .status()
                } else {
                    delete_grant(State(state), caller(), None, tenant_context(Some("tenant-a")), None, Path(grant.id))
                        .await
                        .status()
                }
            });
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            assert!(!delete.is_finished(), "by binding {by_binding}: the delete waits for the surface's lock");
            let deleted = vault
                .delete_grant_of_connection(&key.record_id(), grant_created_at(&vault, &key).await)
                .await
                .unwrap()
                .expect("the write deletes the grant");
            vault
                .store_grant(deleted)
                .await
                .unwrap();
            drop(held);

            let status = tokio::time::timeout(std::time::Duration::from_secs(10), delete)
                .await
                .expect("the delete ends once the lock is free")
                .unwrap();
            assert!(status.is_success(), "by binding {by_binding}: {status}");
            assert!(
                vault
                    .grant(&key)
                    .await
                    .unwrap()
                    .is_none(),
                "by binding {by_binding}: the grant the write put back is deleted"
            );
            fixture
                .revoked_eventually("owner-access-refresh")
                .await;
        }
    }

    async fn grant_created_at(
        vault: &Arc<dyn crate::delegation_vault::storage::DelegationVaultStorage>,
        key: &GrantKey,
    ) -> chrono::DateTime<chrono::Utc> {
        vault
            .grant(key)
            .await
            .unwrap()
            .expect("the grant is stored")
            .created_at
    }

    /// A token with a resource pattern but no tenant is no operator: it never
    /// purges a grant that cannot be read, whatever surface its pattern names.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resource_scoped_token_without_a_tenant_purges_nothing() {
        let fixture = Fixture::new(vec![Answer::status(200)]).await;
        let key = GrantKey::owner(Some("tenant-a"), "surface", "owner-hop", "vendor");
        fixture
            .state
            .vault_store
            .store_grant(crate::delegation_vault::grants::tests::grant(&key, "access"))
            .await
            .unwrap();
        let file = fixture
            ._directory
            .path()
            .join("vault/delegated_grants")
            .join(format!("{}.json.enc", key.record_id()));
        std::fs::write(&file, "not a grant").unwrap();
        let pattern = |pattern: &str| {
            Some(Extension(crate::auth_manager::pat::PatResourceScope(Arc::new(regex::Regex::new(pattern).unwrap()))))
        };
        for scope in [pattern("^other-surface$"), pattern("^surface$")] {
            let status = delete_grant(State(fixture.state.clone()), caller(), None, None, scope, Path(key.record_id()))
                .await
                .status();
            assert_ne!(status, StatusCode::NO_CONTENT);
            assert!(file.exists(), "nothing is purged");
        }
        let query = || BindingGrantsQuery {
            surface_id: "surface".into(),
            hop: "owner-hop".into(),
            credential_provider_id: None,
            tenant_id: Some("tenant-a".into()),
            principal: None,
        };
        let status = delete_binding_grants(
            State(fixture.state.clone()),
            caller(),
            None,
            None,
            pattern("^surface$"),
            Query(query()),
        )
        .await
        .status();
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(file.exists(), "nothing is purged by binding either");
    }

    struct UnreadableSurfaces;

    #[async_trait::async_trait]
    impl crate::surfaces::AgentSurfaceStore for UnreadableSurfaces {
        async fn get_checked(
            &self,
            surface_id: &str,
        ) -> anyhow::Result<Option<crate::config::agent_surface::AgentSurface>> {
            self.get(surface_id).await
        }

        async fn save(
            &self,
            _surface: &AgentSurface,
        ) -> anyhow::Result<()> {
            anyhow::bail!("disk unavailable")
        }

        async fn get(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<Option<AgentSurface>> {
            anyhow::bail!("disk unavailable")
        }

        async fn list_all(&self) -> anyhow::Result<Vec<AgentSurface>> {
            anyhow::bail!("disk unavailable")
        }

        async fn delete(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<()> {
            anyhow::bail!("disk unavailable")
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_binding_removal_answers_503_while_its_surface_cannot_be_read() {
        let fixture = Fixture::new(vec![]).await;
        let mut state = fixture.state.clone();
        state.agent_surface_store = Some(Arc::new(UnreadableSurfaces));
        let query = |credential_provider_id: Option<&str>| BindingGrantsQuery {
            surface_id: "surface".into(),
            hop: "owner-hop".into(),
            credential_provider_id: credential_provider_id.map(str::to_string),
            tenant_id: None,
            principal: None,
        };
        for credential_provider_id in [None, Some("vendor")] {
            let (status, body) = read(
                delete_binding_grants(
                    State(state.clone()),
                    caller(),
                    None,
                    None,
                    None,
                    Query(query(credential_provider_id)),
                )
                .await,
            )
            .await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
            assert_eq!(body["code"], "surfaces_unavailable");
        }
        let (status, body) = read(
            delete_binding_grants(State(fixture.state.clone()), caller(), None, None, None, Query(query(None))).await,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}
