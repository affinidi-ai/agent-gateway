//! API handlers for delegation vault management and OAuth callback

use super::{
    DelegationToken, DelegationTokenListItem,
    notifier::SharedVaultPopulationNotifier,
    oauth,
    read_scope::{VaultReadScope, VaultReader},
    storage::DelegationVaultStorage,
};
use crate::audit::events::DelegationFailureReason;
use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::PatDelegationContext;
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::identity::VCIssuer;
use crate::identity::ssi::vc_issuer::VcSigner;
use crate::observability::loggable;
use crate::secrets::SecretsStore;
use crate::surfaces::AgentSurfaceStore;
use axum::{
    Extension, Form, Json,
    extract::{
        Path, Query, State,
        rejection::{FormRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Shared state for delegation vault handlers
#[derive(Clone)]
pub struct DelegationVaultState {
    pub vault_store: Arc<dyn DelegationVaultStorage>,
    pub provider_store: Arc<dyn CredentialProviderStorage>,
    pub secrets_store: Arc<dyn SecretsStore>,
    pub gateway_base_url: String,
    pub agent_surface_store: Option<Arc<dyn AgentSurfaceStore>>,
    pub oauth_callback_route: String,
    pub vc_signer: Option<Arc<dyn VcSigner>>,
    /// Channel-agnostic VC issuer used to mint a workload-binding VP for
    /// consent_granted audit events when workload-binding attestation is
    /// enabled. Optional only because tests may construct this state without
    /// identity support.
    pub vc_issuer: Option<Arc<VCIssuer>>,

    /// Wakes parked tool-call tasks that are waiting for the OAuth flow to
    /// finish (set by orchestrator at startup; `None` only in test contexts).
    #[allow(dead_code)] // set on OAuth success paths; optional in tests
    pub vault_population_notifier: Option<SharedVaultPopulationNotifier>,

    /// The test allow-list of authorization server and vendor fixtures the
    /// connect API's token requests and revocations may reach; `None` in
    /// production.
    pub egress_allowlist: Option<String>,
    /// gateway.json's `external_consent_resource_origins`.
    pub resource_origins: Arc<std::collections::HashMap<String, Vec<String>>>,
    /// gateway.json's `external_consent_issuers` and
    /// `external_consent_issuer_patterns`.
    pub issuers: Arc<crate::credential_providers::external::PermittedIssuers>,
    /// The MCP Proxies a `proxy://` Transit Point's binding sends its grants
    /// through.
    pub mcp_proxy_store: Option<Arc<crate::mcp_proxies::FileSystemMcpProxyStore>>,
    pub identity_strategies: Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>,
    pub verifier: Arc<crate::jwt_bearer::JwtBearerVerifier>,
    pub provider_egress: oauth::TokenEgress,
    /// gateway.json's `sts.mcp_issuer`: the issuer of this gateway's own STS
    /// tokens, through which no consent confirmation confirms a caller.
    pub gateway_mcp_issuer: Option<String>,
}

/// A read refused because the credential providers could not be read. It
/// answers `500` with `refusal` and no detail.
struct ProvidersUnreadable {
    refusal: &'static str,
}

impl IntoResponse for ProvidersUnreadable {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": self.refusal }))).into_response()
    }
}

/// What the caller may read of the agent-keyed tokens and the delegation
/// audit. While the credential providers cannot be read, a caller that needs
/// them is refused with `refusal` and no detail.
async fn caller_read_scope(
    state: &DelegationVaultState,
    reader: &VaultReader,
    action: &'static str,
    refusal: &'static str,
) -> Result<VaultReadScope, ProvidersUnreadable> {
    VaultReadScope::of(Some(state.provider_store.as_ref()), reader)
        .await
        .map_err(|error| {
            warn!(
                target: "credential_delegation",
                action,
                error = %error,
                "Delegation vault read refused: the credential providers could not be read"
            );
            ProvidersUnreadable { refusal }
        })
}

/// GET /api/v1/delegation-vault
pub async fn list_tokens(
    State(state): State<DelegationVaultState>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    reader: VaultReader,
) -> impl IntoResponse {
    // Fail closed: the list shows other users' and agents' grants, every one
    // the caller's read scope covers, so it must be attributable to an
    // authenticated actor, as the revokes are.
    if management_caller_context(caller.as_ref(), delegation.as_ref()).is_none() {
        warn!(
            target: "credential_delegation",
            action = "list",
            "Delegation token list rejected — no authenticated caller"
        );
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "no authenticated caller"})))
            .into_response();
    }
    let scope = match caller_read_scope(&state, &reader, "list", "Failed to list").await {
        Ok(scope) => scope,
        Err(refused) => return refused.into_response(),
    };

    match state
        .vault_store
        .list_all()
        .await
    {
        Ok(tokens) => {
            let items: Vec<DelegationTokenListItem> = tokens
                .iter()
                .filter(|t| scope.reads(Some(&t.credential_provider_id)))
                .map(|t| t.into())
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(items).unwrap())).into_response()
        }
        Err(e) => {
            warn!(target: "credential_delegation", action = "list", error = %e, "Delegation token list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to list"}))).into_response()
        }
    }
}

/// GET /api/v1/delegation-vault/{id}
pub async fn get_token(
    State(state): State<DelegationVaultState>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    reader: VaultReader,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Fail closed: a single-grant read must be attributable to an authenticated
    // actor — symmetric with the revokes.
    if management_caller_context(caller.as_ref(), delegation.as_ref()).is_none() {
        warn!(
            target: "credential_delegation",
            id = %id,
            action = "get",
            "Delegation token read rejected — no authenticated caller"
        );
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "no authenticated caller"})))
            .into_response();
    }
    let scope = match caller_read_scope(&state, &reader, "get", "Failed to get").await {
        Ok(scope) => scope,
        Err(refused) => return refused.into_response(),
    };

    match state
        .vault_store
        .get(&id)
        .await
    {
        Ok(Some(token)) if scope.reads(Some(&token.credential_provider_id)) => {
            // Return metadata only — never expose access_token/refresh_token via API
            let item: DelegationTokenListItem = (&token).into();
            (StatusCode::OK, Json(serde_json::to_value(item).unwrap())).into_response()
        }
        Ok(_) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Delegation token not found"}))).into_response()
        }
        Err(e) => {
            warn!(target: "credential_delegation", action = "get", error = %e, "Delegation token read failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to get"}))).into_response()
        }
    }
}

/// DELETE /api/v1/delegation-vault/{id}
pub async fn revoke_token(
    State(state): State<DelegationVaultState>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    reader: VaultReader,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Fail closed: a revoke must be attributable to an authenticated actor.
    let caller_ctx = match management_caller_context(caller.as_ref(), delegation.as_ref()) {
        Some(ctx) => ctx,
        None => {
            warn!(
                target: "credential_delegation",
                id = %id,
                action = "revoke",
                "Delegation token revoke rejected — no authenticated caller"
            );
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "no authenticated caller"})))
                .into_response();
        }
    };
    if !reader.is_appliance_wide() {
        warn!(
            target: "credential_delegation",
            id = %loggable::untrusted(&id),
            action = "revoke",
            "Delegation token revoke refused: only an appliance-wide caller revokes"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    match state
        .vault_store
        .delete(&id)
        .await
    {
        Ok(true) => {
            info!(
                target: "credential_delegation",
                id = %id,
                actor = %caller_ctx.sub.as_deref().unwrap_or_default(),
                action = "revoke",
                "Delegation token revoked via API"
            );
            super::audit::emit("token_revoked", || {
                let mut evt = super::audit::audit_event(
                    super::audit::DelegationAuditAction::TokenRevoked,
                    None,
                    None,
                    None,
                    None,
                );
                evt.token_id = Some(id.to_string());
                evt.caller = Some(caller_ctx);
                evt
            });
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Delegation token not found"}))).into_response()
        }
        Err(e) => {
            warn!(
                target: "credential_delegation",
                id = %loggable::untrusted(&id),
                action = "revoke",
                error = %loggable::untrusted(&e.to_string()),
                "Delegation token revoke failed"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to revoke"}))).into_response()
        }
    }
}

/// DELETE /api/v1/delegation-vault/by-user/{user_hash}
pub async fn revoke_user_tokens(
    State(state): State<DelegationVaultState>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    reader: VaultReader,
    Path(user_hash): Path<String>,
) -> impl IntoResponse {
    // Fail closed: a mass-revoke must be attributable to an authenticated actor.
    let caller_ctx = match management_caller_context(caller.as_ref(), delegation.as_ref()) {
        Some(ctx) => ctx,
        None => {
            warn!(
                target: "credential_delegation",
                user_hash = %user_hash,
                action = "revoke_all",
                "Delegation mass-revoke rejected — no authenticated caller"
            );
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "no authenticated caller"})))
                .into_response();
        }
    };
    if !reader.is_appliance_wide() {
        warn!(
            target: "credential_delegation",
            user_hash = %loggable::untrusted(&user_hash),
            action = "revoke_all",
            "Delegation mass-revoke refused: only an appliance-wide caller revokes"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    match state
        .vault_store
        .delete_by_user(&user_hash)
        .await
    {
        Ok(count) => {
            info!(
                target: "credential_delegation",
                user_hash = %user_hash,
                count = %count,
                actor = %caller_ctx.sub.as_deref().unwrap_or_default(),
                action = "revoke_all",
                "All delegation tokens revoked for user via API"
            );
            super::audit::emit("user_tokens_revoked", || {
                let mut evt = super::audit::audit_event(
                    super::audit::DelegationAuditAction::UserTokensRevoked,
                    None,
                    Some(&user_hash),
                    None,
                    None,
                );
                evt.detail = Some(format!("{} tokens revoked", count));
                evt.caller = Some(caller_ctx);
                evt
            });
            (StatusCode::OK, Json(serde_json::json!({"revoked": count}))).into_response()
        }
        Err(e) => {
            warn!(
                target: "credential_delegation",
                user_hash = %loggable::untrusted(&user_hash),
                action = "revoke_all",
                error = %loggable::untrusted(&e.to_string()),
                "Delegation mass-revoke failed"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to revoke"}))).into_response()
        }
    }
}

/// Query parameters for OAuth callback
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub iss: Option<String>,
}

/// The consent start state, in the start page's query or the start POST's form.
#[derive(Deserialize)]
pub struct ConsentStartParams {
    pub state: String,
}

/// The only text a refused consent start or callback shows: nothing the
/// request, the vendor or an error carried is reflected.
pub(super) const CONSENT_REFUSED_PAGE: &str = r#"<!DOCTYPE html>
<html><head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2>Authorization Failed</h2>
<p>The authorization could not be completed.</p>
<p>Please start again from the original application.</p>
</body></html>"#;

/// A consent refusal: its status and the reason the audit and the log name.
struct ConsentRefusal {
    status: StatusCode,
    reason: DelegationFailureReason,
}

impl ConsentRefusal {
    fn bad_request(reason: DelegationFailureReason) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            reason,
        }
    }
}

/// The fixed refusal page for `refusal`, with `Cache-Control: no-store`,
/// `Referrer-Policy: no-referrer` and the binding cookie cleared on
/// `cookie`, logged as a WARN with the reason and the provider it names, only
/// when that is a plain slug. It is audited as `delegation_failed` only when
/// `audited` names the provider: the request carried a state this gateway
/// sealed for its stage, so requests without one cannot flood the audit log or
/// its integrations. Without one, the path's segment names the provider.
fn consent_refused(
    refusal: ConsentRefusal,
    path_segment: &str,
    cookie: Option<&str>,
    audited: Option<&str>,
) -> Response {
    let ConsentRefusal { status, reason } = refusal;
    let provider_id = plain_slug(audited.unwrap_or(path_segment));
    warn!(
        target: "credential_delegation",
        provider_id,
        reason = ?reason,
        "OAuth consent refused"
    );
    if audited.is_some() {
        super::audit::emit("delegation_failed", || {
            super::audit::audit_event(
                super::audit::DelegationAuditAction::DelegationFailed {
                    reason,
                    provider_id: provider_id.map(str::to_string),
                },
                None,
                None,
                provider_id,
                None,
            )
        });
    }
    let mut response = (status, Html(CONSENT_REFUSED_PAGE)).into_response();
    consent_page_headers(&mut response, "no-referrer");
    if let Some(cleared) = cookie.and_then(|name| binding_cookie(name, "", 0).ok()) {
        attach_binding_cookie(&mut response, cleared);
    }
    response
}

fn consent_page_headers(
    response: &mut Response,
    referrer_policy: &'static str,
) {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static(referrer_policy));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
}

/// The `Set-Cookie` value of the binding cookie `name`: `Path=/`, no `Domain`,
/// `Secure`, `HttpOnly`, `SameSite=Lax`, or an error when `name` or `value`
/// cannot be sent in a header.
fn binding_cookie(
    name: &str,
    value: &str,
    max_age: i64,
) -> Result<HeaderValue, axum::http::header::InvalidHeaderValue> {
    HeaderValue::from_str(&format!("{name}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax"))
}

/// Adds `cookie` to `response` and marks the response as the gateway's own,
/// so the cookie guard keeps it.
fn attach_binding_cookie(
    response: &mut Response,
    cookie: HeaderValue,
) {
    response
        .headers_mut()
        .append(header::SET_COOKIE, cookie);
    response
        .extensions_mut()
        .insert(super::consent_cookie::GatewayConsentCookie);
}

/// `provider_id` when it is 1 to 128 bytes of ASCII letters, digits, `-`, `_`
/// and `.`: the only path text a log, an audit record or a cookie path takes.
fn plain_slug(provider_id: &str) -> Option<&str> {
    (!provider_id.is_empty()
        && provider_id.len() <= 128
        && provider_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    .then_some(provider_id)
}

/// The provider a refusal of a request carrying `sealed` names: the state's
/// `provider_id` slug when the path's segment is the state's own record id, as
/// it is for a provider whose callback path ends in its id, so refusals and
/// grants name the provider alike; otherwise the path's segment, which is a
/// provider's slug or names another provider than the state's.
fn refused_provider<'a>(
    path_segment: &'a str,
    sealed: &'a super::OAuthState,
) -> &'a str {
    if path_segment == sealed.credential_provider_id {
        &sealed.provider_id
    } else {
        path_segment
    }
}

/// The provider a consent state names, checked against the path: the stored
/// provider still has the state's id and slug, is an authorization code
/// provider without an issuer, and its `callback_path` ends in the path's
/// segment.
async fn consent_provider(
    state: &DelegationVaultState,
    path_segment: &str,
    oauth_state: &super::OAuthState,
) -> Result<crate::credential_providers::CredentialProvider, ConsentRefusal> {
    match state
        .provider_store
        .get(&oauth_state.credential_provider_id)
        .await
    {
        Ok(Some(provider))
            if provider.id == oauth_state.credential_provider_id
                && provider.provider_id == oauth_state.provider_id
                && provider.uses_legacy_consent()
                && provider
                    .callback_path
                    .rsplit('/')
                    .next()
                    == Some(path_segment) =>
        {
            Ok(provider)
        }
        Ok(_) => Err(ConsentRefusal::bad_request(DelegationFailureReason::ConsentProviderMismatch)),
        Err(e) => {
            error!(target: "credential_delegation", error = %e, "Failed to load credential provider for consent");
            Err(ConsentRefusal::bad_request(DelegationFailureReason::CredentialsUnavailable))
        }
    }
}

/// A consent start a start page GET or start POST carries, once decoded and
/// checked: the encoded start state, the state, its provider and the
/// provider's redirect URI.
struct ConsentStartRequest {
    encoded: String,
    start: super::OAuthState,
    provider: crate::credential_providers::CredentialProvider,
    redirect_uri: url::Url,
}

/// Why a consent start was refused and, when its start state was valid so the
/// refusal is audited, the provider it names.
struct StartRefused {
    refusal: ConsentRefusal,
    audited: Option<String>,
}

/// Decodes the start state `params` carry, one without a stage or a
/// [`ConsentStage::ConfirmStart`](super::ConsentStage::ConfirmStart) one, and
/// resolves its provider, whose redirect URI must follow the consent rules and
/// be no other provider's.
async fn resolve_consent_start(
    state: &DelegationVaultState,
    path_segment: &str,
    params: Option<ConsentStartParams>,
) -> Result<ConsentStartRequest, StartRefused> {
    let (encoded, start) = params
        .and_then(|params| {
            oauth::decode_start_state(&params.state)
                .ok()
                .map(|start| (params.state, start))
        })
        .ok_or(StartRefused {
            refusal: ConsentRefusal::bad_request(DelegationFailureReason::ConsentStateInvalid),
            audited: None,
        })?;
    let named = refused_provider(path_segment, &start).to_string();
    let refuse = |refusal| StartRefused {
        refusal,
        audited: Some(named.clone()),
    };
    let provider = consent_provider(state, path_segment, &start)
        .await
        .map_err(refuse)?;
    let redirect_uri = provider
        .consent_redirect_uri(&state.gateway_base_url)
        .map_err(|_| refuse(ConsentRefusal::bad_request(DelegationFailureReason::RedirectUriInvalid)))?;
    match crate::credential_providers::redirect_uri_taken_by(
        state.provider_store.as_ref(),
        &provider,
        &state.gateway_base_url,
    )
    .await
    {
        Ok(None) => Ok(ConsentStartRequest {
            encoded,
            start,
            provider,
            redirect_uri,
        }),
        Ok(Some(_)) => Err(refuse(ConsentRefusal::bad_request(DelegationFailureReason::RedirectUriInvalid))),
        Err(e) => {
            error!(target: "credential_delegation", error = %e, "Failed to list credential providers for consent");
            Err(refuse(ConsentRefusal::bad_request(DelegationFailureReason::CredentialsUnavailable)))
        }
    }
}

/// GET {callback_path}/start
///
/// The consent start page: shows the agent, surface, provider and scopes a
/// start link asks for, with a button that POSTs it back. It claims nothing and
/// sets no cookie, so a link scanner may fetch it any number of times.
pub async fn consent_start_page(
    State(state): State<DelegationVaultState>,
    Path(provider_id): Path<String>,
    query: Result<Query<ConsentStartParams>, QueryRejection>,
) -> Response {
    let ConsentStartRequest { encoded, start, provider, .. } = match resolve_consent_start(
        &state,
        &provider_id,
        query
            .ok()
            .map(|Query(params)| params),
    )
    .await
    {
        Ok(request) => request,
        Err(StartRefused { refusal, audited }) => {
            return consent_refused(refusal, &provider_id, None, audited.as_deref());
        }
    };
    let surface_name = match &state.agent_surface_store {
        Some(store) => store
            .get(&start.surface_id)
            .await
            .ok()
            .flatten()
            .map(|surface| surface.name),
        None => None,
    }
    .unwrap_or_else(|| start.surface_id.clone());
    let provider_name = html_escape(&provider.name);
    let (sign_in_first, button) = match &start.stage {
        Some(super::ConsentStage::ConfirmStart(_)) => (
            format!(
                "<p>You sign in to your identity provider first, to confirm it is you, and then continue to \
                 {provider_name}.</p>\n"
            ),
            format!("Sign in, then continue to {provider_name}"),
        ),
        _ => (String::new(), format!("Continue to {provider_name}")),
    };
    let scopes = if start.scopes.is_empty() {
        "(none)".to_string()
    } else {
        start.scopes.join(", ")
    };
    let page = format!(
        r#"<!DOCTYPE html>
<html><head><title>Authorize {provider}</title></head>
<body style="font-family: sans-serif; padding: 40px; max-width: 640px; margin: auto;">
<h2>Authorize {provider}</h2>
<p>An agent asks to use your {provider} account on your behalf.</p>
<dl>
<dt>Agent</dt><dd><code>{agent}</code></dd>
<dt>Surface</dt><dd>{surface}</dd>
<dt>Provider</dt><dd>{provider}</dd>
<dt>Scopes</dt><dd><code>{scopes}</code></dd>
</dl>
<p>Continue only if you started this from your own application.</p>
{sign_in_first}<form method="post" action="start">
<input type="hidden" name="state" value="{state}">
<button type="submit">{button}</button>
</form>
</body></html>"#,
        provider = provider_name,
        agent = html_escape(&start.agent_did),
        surface = html_escape(&surface_name),
        scopes = html_escape(&scopes),
        state = html_escape(&encoded),
    );
    let mut response = Html(page).into_response();
    consent_page_headers(&mut response, "same-origin");
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// Whether a start POST is the person's click on a page of `redirect_uri`'s
/// origin: the browser says `Sec-Fetch-Site: same-origin`, `Sec-Fetch-User: ?1`
/// and `Sec-Fetch-Dest: document`, a navigation the person started, so script
/// on that origin cannot submit the page without a click; or, when it sends no
/// fetch metadata, an `Origin` of that origin. Any `Origin` sent must be that
/// origin.
fn same_origin_post(
    headers: &HeaderMap,
    redirect_uri: &url::Url,
) -> bool {
    let expected = redirect_uri
        .origin()
        .ascii_serialization();
    let origin = headers
        .get(header::ORIGIN)
        .map(|value| value.as_bytes() == expected.as_bytes());
    let says = |name: &str, value: &[u8]| {
        headers
            .get(name)
            .is_some_and(|header| header.as_bytes() == value)
    };
    match headers.get("sec-fetch-site") {
        Some(_) => {
            says("sec-fetch-site", b"same-origin")
                && says("sec-fetch-user", b"?1")
                && says("sec-fetch-dest", b"document")
                && origin != Some(false)
        }
        None => origin == Some(true),
    }
}

/// POST {callback_path}/start
///
/// The person confirmed the start page: build the vendor's URL, or the
/// identity provider's for a start state that confirms its caller, and the
/// binding cookie, then claim the start state, set the cookie and send the
/// browser there. A start state is used once on this process, and a POST
/// refused before the claim leaves it unused.
pub async fn consent_start(
    State(state): State<DelegationVaultState>,
    Path(provider_id): Path<String>,
    headers: HeaderMap,
    form: Result<Form<ConsentStartParams>, FormRejection>,
) -> Response {
    let ConsentStartRequest {
        start, provider, redirect_uri, ..
    } = match resolve_consent_start(
        &state,
        &provider_id,
        form.ok()
            .map(|Form(params)| params),
    )
    .await
    {
        Ok(request) => request,
        Err(StartRefused { refusal, audited }) => {
            return consent_refused(refusal, &provider_id, None, audited.as_deref());
        }
    };
    let audited = Some(refused_provider(&provider_id, &start));
    if !same_origin_post(&headers, &redirect_uri) {
        return consent_refused(
            ConsentRefusal {
                status: StatusCode::FORBIDDEN,
                reason: DelegationFailureReason::CrossSiteConsentStart,
            },
            &provider_id,
            None,
            audited,
        );
    }
    let begun = match &start.stage {
        None => begin_vendor_consent(&state, &provider, &start, &redirect_uri).await,
        Some(super::ConsentStage::ConfirmStart(binding)) => {
            begin_confirmation(&state, &provider, &start, binding).await
        }
        Some(_) => Err(DelegationFailureReason::ConsentStateInvalid),
    };
    let begun = match begun {
        Ok(begun) => begun,
        Err(reason) => return consent_refused(ConsentRefusal::bad_request(reason), &provider_id, None, audited),
    };
    let Ok(location) = HeaderValue::from_str(
        begun
            .authorization_url
            .as_str(),
    ) else {
        return consent_refused(
            ConsentRefusal::bad_request(DelegationFailureReason::AuthorizationUrlInvalid),
            &provider_id,
            None,
            audited,
        );
    };
    let max_age = (begun.expires_at - Utc::now())
        .num_seconds()
        .max(0);
    let Ok(cookie) = binding_cookie(&begun.cookie_name, &begun.cookie_value, max_age) else {
        error!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            "The consent binding cookie cannot be sent in a header"
        );
        return consent_refused(
            ConsentRefusal::bad_request(DelegationFailureReason::ConsentStateInvalid),
            &provider_id,
            None,
            audited,
        );
    };
    if !oauth::claim_oauth_state(&start).await {
        return consent_refused(
            ConsentRefusal::bad_request(DelegationFailureReason::ConsentStateReused),
            &provider_id,
            None,
            audited,
        );
    }
    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        action = "oauth_consent_start",
        "OAuth consent started"
    );
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, location);
    consent_page_headers(&mut response, "no-referrer");
    attach_binding_cookie(&mut response, cookie);
    response
}

async fn begin_vendor_consent(
    state: &DelegationVaultState,
    provider: &crate::credential_providers::CredentialProvider,
    start: &super::OAuthState,
    redirect_uri: &url::Url,
) -> Result<oauth::ConsentStart, DelegationFailureReason> {
    oauth::begin_consent(provider, start, redirect_uri, &state.secrets_store)
        .await
        .map_err(|e| {
            warn!(
                target: "credential_delegation",
                provider_id = %provider.provider_id,
                error = %e,
                "Could not begin OAuth consent"
            );
            if e.is::<oauth::ProviderSecretError>() {
                DelegationFailureReason::CredentialsUnavailable
            } else {
                DelegationFailureReason::AuthorizationUrlInvalid
            }
        })
}

async fn begin_confirmation(
    state: &DelegationVaultState,
    provider: &crate::credential_providers::CredentialProvider,
    start: &super::OAuthState,
    binding: &super::ConsentConfirmBinding,
) -> Result<oauth::ConsentStart, DelegationFailureReason> {
    let sign_in = super::consent_confirmation::sign_in(
        provider,
        binding,
        state
            .identity_strategies
            .as_ref(),
        &state.secrets_store,
        &state.gateway_base_url,
    )
    .await?;
    oauth::begin_confirmation(start, binding, &sign_in).map_err(|e| {
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            error = %e,
            "Could not begin consent confirmation"
        );
        DelegationFailureReason::ConsentStateInvalid
    })
}

/// The reason a provider's `error` answer is refused with: a denied consent
/// for an RFC 6749 error code, an invalid response otherwise; and the code
/// the log may name.
fn provider_error(error: &str) -> (DelegationFailureReason, &str) {
    let valid = !error.is_empty()
        && error.len() <= 128
        && error
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if valid {
        (DelegationFailureReason::ConsentDenied, error)
    } else {
        (DelegationFailureReason::ConsentResponseInvalid, oauth::UNRECOGNIZED_ERROR)
    }
}

/// Whether the surface a confirmation state was minted on still exists under
/// the tenant the caller's `user_identity_hash` was computed for.
async fn sealed_surface_unchanged(
    state: &DelegationVaultState,
    sealed: &super::OAuthState,
    binding: &super::ConsentConfirmBinding,
) -> bool {
    let Some(surfaces) = &state.agent_surface_store else {
        return false;
    };
    matches!(
        surfaces.get(&sealed.surface_id).await,
        Ok(Some(surface)) if surface.tenant_id == binding.tenant_id
    )
}

/// GET {callback_path}/confirm
///
/// The identity provider's redirect after a consent confirmation sign-in. The
/// state must be a confirmation state of this gateway, held by the browser
/// that posted its start page, and is used once; its surface must still exist
/// under the sealed tenant, and its provider must still confirm through the
/// sealed strategy. An identity provider error is a denied
/// consent. Once the caller is confirmed
/// ([`confirm_caller`](super::consent_confirmation::confirm_caller)) the
/// browser goes on to the vendor with a vendor state on the same browser
/// binding, so its cookie stays as it is. A caller the sign-in does not
/// confirm is refused with 403; every refusal clears the cookie and stores
/// nothing.
pub async fn consent_confirmation_callback(
    State(state): State<DelegationVaultState>,
    Path(provider_id): Path<String>,
    cookies: Option<Extension<super::consent_cookie::ConsentCookies>>,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return consent_refused(
            ConsentRefusal::bad_request(DelegationFailureReason::ConsentResponseInvalid),
            &provider_id,
            None,
            None,
        );
    };
    let sealed = query
        .state
        .as_deref()
        .and_then(|encoded| oauth::decode_confirmation_state(encoded).ok());
    let cookie_name = sealed
        .as_ref()
        .and_then(oauth::binding_cookie_name);
    let audited = sealed
        .as_ref()
        .map(|sealed| refused_provider(&provider_id, sealed).to_string());
    let refuse = |reason: DelegationFailureReason| {
        let status = match reason {
            DelegationFailureReason::ConsentIdentityMismatch
            | DelegationFailureReason::ConsentIdentityMissing
            | DelegationFailureReason::BrowserBindingMismatch => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        };
        consent_refused(ConsentRefusal { status, reason }, &provider_id, cookie_name.as_deref(), audited.as_deref())
    };
    let (Some(sealed), Some(cookie_name)) = (&sealed, cookie_name.as_deref()) else {
        return refuse(DelegationFailureReason::ConsentStateInvalid);
    };
    let Some(super::ConsentStage::Confirmation(sign_in)) = &sealed.stage else {
        return refuse(DelegationFailureReason::ConsentStateInvalid);
    };
    let presented = cookies
        .as_ref()
        .and_then(|Extension(cookies)| cookies.get(cookie_name));
    if !oauth::browser_binding_matches(sealed, presented) {
        return refuse(DelegationFailureReason::BrowserBindingMismatch);
    }
    if !sealed_surface_unchanged(&state, sealed, &sign_in.binding).await {
        return refuse(DelegationFailureReason::ConsentStateInvalid);
    }
    if !oauth::claim_oauth_state(sealed).await {
        return refuse(DelegationFailureReason::ConsentStateReused);
    }
    let provider = match consent_provider(&state, &provider_id, sealed).await {
        Ok(provider) => provider,
        Err(refusal) => return refuse(refusal.reason),
    };
    let Some(confirmation) = super::consent_confirmation::confirmation_for(&provider, &sign_in.binding) else {
        return refuse(DelegationFailureReason::ConsentStateInvalid);
    };
    if let Some(error) = &query.error {
        let (reason, logged) = provider_error(error);
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            oauth_error = %logged,
            "Identity provider returned an error to the consent confirmation"
        );
        return refuse(reason);
    }
    let Some(code) = query
        .code
        .as_deref()
        .filter(|code| !code.is_empty())
    else {
        return refuse(DelegationFailureReason::ConsentResponseInvalid);
    };
    if let Err(reason) = super::consent_confirmation::confirm_caller(
        &state,
        &provider,
        confirmation,
        sealed,
        sign_in,
        code,
        query.iss.as_deref(),
    )
    .await
    {
        return refuse(reason);
    }
    let Ok(redirect_uri) = provider.consent_redirect_uri(&state.gateway_base_url) else {
        return refuse(DelegationFailureReason::RedirectUriInvalid);
    };
    let vendor_url =
        match oauth::continue_to_vendor(&provider, sealed, &sign_in.binding, &redirect_uri, &state.secrets_store).await
        {
            Ok(vendor_url) => vendor_url,
            Err(e) => {
                warn!(
                    target: "credential_delegation",
                    provider_id = %provider.provider_id,
                    error = %e,
                    "Could not continue a confirmed consent to the vendor"
                );
                return refuse(if e.is::<oauth::ProviderSecretError>() {
                    DelegationFailureReason::CredentialsUnavailable
                } else {
                    DelegationFailureReason::AuthorizationUrlInvalid
                });
            }
        };
    let Ok(location) = HeaderValue::from_str(vendor_url.as_str()) else {
        return refuse(DelegationFailureReason::AuthorizationUrlInvalid);
    };
    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        action = "consent_confirmed",
        "Consent caller confirmed at their identity provider"
    );
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, location);
    consent_page_headers(&mut response, "no-referrer");
    response
}

/// GET {callback_path}
///
/// Handles the OAuth provider redirect after user consent. Every check runs
/// before the code is exchanged: the state is a callback state of this
/// gateway, the path's segment ends its provider's `callback_path`, the provider is unchanged, the
/// browser holds the binding cookie the start POST set, and the `iss` is the
/// one the operator recorded. The tokens are then stored in the vault.
pub async fn oauth_callback(
    State(state): State<DelegationVaultState>,
    Path(provider_id): Path<String>,
    cookies: Option<Extension<super::consent_cookie::ConsentCookies>>,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return consent_refused(
            ConsentRefusal::bad_request(DelegationFailureReason::ConsentResponseInvalid),
            &provider_id,
            None,
            None,
        );
    };
    let callback_state = query
        .state
        .as_deref()
        .and_then(|encoded| oauth::decode_callback_state(encoded).ok());
    let cookie_name = callback_state
        .as_ref()
        .and_then(oauth::binding_cookie_name);
    let audited = callback_state
        .as_ref()
        .map(|sealed| refused_provider(&provider_id, sealed).to_string());
    let named = audited
        .as_deref()
        .unwrap_or(&provider_id);
    let refuse =
        |refusal: ConsentRefusal| consent_refused(refusal, &provider_id, cookie_name.as_deref(), audited.as_deref());
    info!(
        target: "credential_delegation",
        provider_id = plain_slug(named),
        has_code = %query.code.is_some(),
        has_error = %query.error.is_some(),
        action = "oauth_callback",
        "OAuth callback received"
    );

    if let Some(error) = &query.error {
        let (reason, logged) = provider_error(error);
        warn!(
            target: "credential_delegation",
            provider_id = plain_slug(named),
            oauth_error = %logged,
            "OAuth provider returned an error"
        );
        return refuse(ConsentRefusal::bad_request(reason));
    }

    let (Some(oauth_state), Some(cookie_name)) = (callback_state, cookie_name.as_deref()) else {
        return refuse(ConsentRefusal::bad_request(DelegationFailureReason::ConsentStateInvalid));
    };
    let provider = match consent_provider(&state, &provider_id, &oauth_state).await {
        Ok(provider) => provider,
        Err(refusal) => return refuse(refusal),
    };

    let presented = cookies
        .as_ref()
        .and_then(|Extension(cookies)| cookies.get(cookie_name));
    if !oauth::browser_binding_matches(&oauth_state, presented) {
        return refuse(ConsentRefusal {
            status: StatusCode::FORBIDDEN,
            reason: DelegationFailureReason::BrowserBindingMismatch,
        });
    }
    if let Some(expected) = provider
        .authorization_response_issuer
        .as_deref()
    {
        match query.iss.as_deref() {
            None => return refuse(ConsentRefusal::bad_request(DelegationFailureReason::IssMissing)),
            Some(iss) if iss != expected => {
                return refuse(ConsentRefusal::bad_request(DelegationFailureReason::IssMismatch));
            }
            Some(_) => {}
        }
    }
    let Some(code) = query
        .code
        .filter(|code| !code.is_empty())
    else {
        return refuse(ConsentRefusal::bad_request(DelegationFailureReason::ConsentResponseInvalid));
    };

    // Each state stores at most one credential, and the code is exchanged only
    // for a state not used before.
    if !oauth::claim_oauth_state(&oauth_state).await {
        return refuse(ConsentRefusal::bad_request(DelegationFailureReason::ConsentStateReused));
    }

    let token_response = match oauth::exchange_code_for_tokens(
        &provider,
        &code,
        &state.gateway_base_url,
        &state.secrets_store,
        oauth_state
            .code_verifier
            .as_deref(),
    )
    .await
    {
        Ok(tr) => tr,
        Err(e) => {
            warn!(
                target: "credential_delegation",
                provider_id = %provider.provider_id,
                error = %e,
                "Token exchange failed during the OAuth callback"
            );
            return refuse(ConsentRefusal::bad_request(DelegationFailureReason::TokenExchangeFailed));
        }
    };

    // Build the DelegationCredential VC
    let granted_scopes: Vec<String> = token_response
        .scope
        .as_deref()
        .map(|s| {
            s.split_whitespace()
                .map(String::from)
                .collect()
        })
        .unwrap_or_else(|| {
            provider
                .default_scopes
                .clone()
        });

    // Derive gateway DID from base URL: https://example.com → did:web:example.com
    let gateway_did = state
        .gateway_base_url
        .strip_prefix("https://")
        .or_else(|| {
            state
                .gateway_base_url
                .strip_prefix("http://")
        })
        .map(|domain| format!("did:web:{}", domain))
        .unwrap_or_else(|| "did:web:gateway.local".to_string());

    let delegation_vc = oauth::build_delegation_vc(
        &gateway_did,
        &oauth_state.agent_did,
        &oauth_state.user_identity_hash,
        &provider,
        &granted_scopes,
        state.vc_signer.as_ref(),
    )
    .await;

    let delegation_vc_json = match &delegation_vc {
        Ok(vc) => serde_json::to_string(vc).ok(),
        Err(e) => {
            warn!(
                target: "credential_delegation",
                error = %e,
                "Failed to build signed DelegationCredential VC — storing without VC"
            );
            None
        }
    };

    // Calculate token expiry
    let expires_at = token_response
        .expires_in
        .map(|secs| Utc::now() + Duration::seconds(secs));

    let now = Utc::now();
    let delegation_token = DelegationToken {
        id: Uuid::new_v4().to_string(),
        agent_did: oauth_state.agent_did.clone(),
        user_identity_hash: oauth_state
            .user_identity_hash
            .clone(),
        credential_provider_id: oauth_state
            .credential_provider_id
            .clone(),
        provider_id: oauth_state
            .provider_id
            .clone(),
        access_token: token_response.access_token,
        refresh_token: token_response.refresh_token,
        token_type: token_response.token_type,
        scopes: granted_scopes.clone(),
        expires_at,
        delegation_vc: delegation_vc_json,
        consent_identity: None,
        consent_granted_at: now,
        last_used_at: None,
        created_at: now,
        updated_at: now,
    };

    match state
        .vault_store
        .store(delegation_token)
        .await
    {
        Ok(stored_token) => {
            let delegation_token_id_for_audit = stored_token.id;
            info!(
                target: "credential_delegation",
                provider_id = %provider.provider_id,
                agent_did = %oauth_state.agent_did,
                user_hash = %oauth_state.user_identity_hash,
                scopes = ?granted_scopes,
                expires_at = ?expires_at,
                action = "oauth_callback_success",
                "OAuth consent complete — tokens stored in vault"
            );

            // Audit: consent granted. Built only when a sink selects it, since
            // it may mint a signed VP.
            if super::audit::wants("consent_granted") {
                let mut evt = super::audit::audit_event(
                    super::audit::DelegationAuditAction::ConsentGranted,
                    Some(&oauth_state.agent_did),
                    Some(&oauth_state.user_identity_hash),
                    Some(&provider.id),
                    Some(&oauth_state.surface_id),
                );
                evt.scopes = Some(granted_scopes.clone());
                evt.provider_name = Some(provider.name.clone());
                evt.token_id = Some(delegation_token_id_for_audit.clone());
                evt.agent_identity_did = Some(oauth_state.agent_did.clone());
                let surface = if let Some(ref cs) = state.agent_surface_store {
                    match cs
                        .get(&oauth_state.surface_id)
                        .await
                    {
                        Ok(surface) => surface,
                        Err(e) => {
                            warn!(
                                target: "credential_delegation",
                                surface_id = %oauth_state.surface_id,
                                error = %e,
                                "Failed to load surface for consent_granted audit enrichment"
                            );
                            None
                        }
                    }
                } else {
                    None
                };
                if let Some(ch) = surface.as_ref() {
                    evt.channel_name = Some(ch.name.clone());
                }

                let workload_binding_enabled = surface
                    .as_ref()
                    .and_then(|ch| ch.transit.as_ref())
                    .map(|transit| {
                        transit
                            .points
                            .iter()
                            .any(|tp| {
                                tp.workload_binding
                                    .as_ref()
                                    .is_some_and(|wb| wb.enabled)
                            })
                    })
                    .unwrap_or(false);

                // Mint the signed workload-binding VP only when workload-binding
                // attestation is explicitly enabled for the surface. The callback
                // response is just a static success page; any VP lives only in the
                // operator audit trail.
                if workload_binding_enabled {
                    if let Some(ref vc_issuer) = state.vc_issuer {
                        let delegation_action = serde_json::json!({
                            "providerId": provider.provider_id,
                            "providerName": provider.name,
                            "outcome": "consent_granted",
                            "scopes": granted_scopes,
                            "expiresAt": expires_at.map(|t| t.to_rfc3339()),
                            "tokenId": delegation_token_id_for_audit.clone(),
                        });
                        let workload_binding = serde_json::json!({
                            "agentIdentity": { "id": oauth_state.agent_did },
                            "userIdentity": { "userIdentityHash": oauth_state.user_identity_hash },
                            "delegationAction": delegation_action,
                        });
                        let identity_fields: std::collections::HashMap<String, serde_json::Value> =
                            std::collections::HashMap::new();
                        match vc_issuer
                            .create_agent_identity_presentation_with_binding(
                                &oauth_state.agent_did,
                                &identity_fields,
                                Some(workload_binding),
                                None,
                                None,
                            )
                            .await
                        {
                            Ok(jwt) => {
                                evt.vp_jwt = Some(jwt);
                            }
                            Err(e) => {
                                warn!(
                                    target: "credential_delegation",
                                    agent_did = %oauth_state.agent_did,
                                    provider_id = %provider.provider_id,
                                    error = %e,
                                    "Failed to mint consent_granted workload-binding VP for audit log"
                                );
                            }
                        }
                    } else {
                        warn!(
                            target: "credential_delegation",
                            "No VC issuer available — consent_granted workload-binding audit event will be unsigned"
                        );
                    }
                }

                super::audit::submit(evt);
            }

            // Wake any parked tool-call tasks waiting for this vault key to
            // be populated by the MCP elicitation flow.
            if let Some(notifier) = &state.vault_population_notifier {
                notifier
                    .notify(&oauth_state.agent_did, &oauth_state.user_identity_hash, &oauth_state.provider_id)
                    .await;
            }
        }
        Err(e) => {
            error!(
                target: "credential_delegation",
                error = %e,
                "Failed to store delegation token after successful OAuth"
            );
            return refuse(ConsentRefusal {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                reason: DelegationFailureReason::VaultStoreRejected,
            });
        }
    }

    let mut response = Html(format!(
        r#"<!DOCTYPE html>
<html><head><title>Authorization Successful</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2 style="color: #22c55e;">Authorization Successful</h2>
<p>{} access has been granted for scopes: <code>{}</code></p>
<p>You may close this window and return to your application.</p>
<p style="color: #666; font-size: 0.9em;">The agent can now access {} on your behalf.</p>
<script>
// Attempt to close the window after a short delay
setTimeout(function() {{ window.close(); }}, 3000);
</script>
</body></html>"#,
        html_escape(&provider.name),
        html_escape(&granted_scopes.join(", ")),
        html_escape(&provider.name)
    ))
    .into_response();
    consent_page_headers(&mut response, "no-referrer");
    if let Ok(cleared) = binding_cookie(cookie_name, "", 0) {
        attach_binding_cookie(&mut response, cleared);
    }
    response
}

/// Resolve the authenticated management-API actor from the request extensions
/// set by `require_session_auth`: `AuthGuardOk` carries the console `user_id`
/// and, on a personal access token, `PatDelegationContext` carries the token id.
/// Returns `None` when the request has no authenticated principal so mutating
/// handlers can fail closed.
fn management_caller_context(
    caller: Option<&Extension<AuthGuardOk>>,
    delegation: Option<&Extension<PatDelegationContext>>,
) -> Option<super::audit::AuditCallerContext> {
    let user_id = caller.map(|Extension(AuthGuardOk(id))| id.as_str());
    let token_id = delegation.map(|Extension(ctx)| ctx.token_id.as_str());
    super::audit::management_caller_context(user_id, token_id)
}

/// Simple HTML escaping for dynamic content in callback pages
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Query parameters for the audit log endpoint
#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub page: Option<usize>,
    pub page_size: Option<usize>,
    pub filter: Option<String>,
}

/// GET /api/v1/delegation-audit
pub async fn list_audit_events(
    State(state): State<DelegationVaultState>,
    reader: VaultReader,
    Query(query): Query<AuditLogQuery>,
) -> impl IntoResponse {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query
        .page_size
        .unwrap_or(25)
        .clamp(1, 100);
    let filter = query.filter.as_deref();
    let scope = match caller_read_scope(&state, &reader, "audit", "Failed to read audit log").await {
        Ok(scope) => scope,
        Err(refused) => return refused.into_response(),
    };

    // Exclude VP-audit categories (policy decisions / trust checks) up front so
    // `events`, `total`, and `total_pages` stay consistent — they belong to the
    // VP Audit Log (/v1/audit), not the Credential Delegation Audit Log.
    let result = super::audit::read_audit_log(
        page,
        page_size,
        super::audit::AuditLogFilter {
            text: filter,
            exclude_vp_audit: true,
            ..Default::default()
        },
        scope,
    )
    .await;

    audit_response(result).into_response()
}

/// Answers with the page, or with `500` when the read failed. An empty page
/// would assert that this is the whole of the administrator's evidence, and
/// the io detail stays in the log.
fn audit_response(result: anyhow::Result<super::audit::AuditLogPage>) -> (StatusCode, Json<serde_json::Value>) {
    let body = result.and_then(|page| serde_json::to_value(page).map_err(anyhow::Error::from));
    match body {
        Ok(body) => (StatusCode::OK, Json(body)),
        Err(e) => {
            warn!(target: "credential_delegation", action = "audit", error = %e, "Failed to read the VP Audit Log");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to read the audit log"})))
        }
    }
}

#[cfg(test)]
mod audit_response_tests {
    use super::*;

    fn page() -> crate::delegation_vault::audit::AuditLogPage {
        crate::delegation_vault::audit::AuditLogPage {
            events: Vec::new(),
            total: 0,
            page: 1,
            page_size: 25,
            total_pages: 1,
            category_counts: std::collections::BTreeMap::new(),
            truncated: true,
            dropped_records: 0,
            history_bytes: 2048,
            soft_cap_bytes: 1024,
        }
    }

    #[test]
    fn a_read_that_failed_is_answered_with_an_error_not_an_empty_page() {
        let (status, Json(body)) = audit_response(Err(anyhow::anyhow!("Audit logger not initialized")));

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, serde_json::json!({"error": "Failed to read the audit log"}));
    }

    #[test]
    fn a_page_is_answered_with_its_counts_and_its_truncated_flag() {
        let (status, Json(body)) = audit_response(Ok(page()));

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["truncated"], serde_json::json!(true));
        assert_eq!(body["total"], serde_json::json!(0));
        assert_eq!(body["total_pages"], serde_json::json!(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The binding cookie carries the attributes that keep it on the gateway's
    /// own host, and a name or value that cannot be sent in a header is an
    /// error rather than a missing cookie.
    #[test]
    fn a_binding_cookie_has_its_attributes_or_is_an_error() {
        let cookie = binding_cookie("__Host-ag_consent_abc", "value", 60).unwrap();
        assert_eq!(cookie, "__Host-ag_consent_abc=value; Path=/; Max-Age=60; Secure; HttpOnly; SameSite=Lax");
        assert!(binding_cookie("__Host-ag_consent_abc", "line\nbreak", 60).is_err());
        assert!(binding_cookie("__Host-ag_consent_\r", "value", 60).is_err());
    }
}
