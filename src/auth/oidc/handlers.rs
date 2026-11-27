use std::sync::Arc;
use std::time::Duration;

use axum::{
    Extension,
    extract::{Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, REFERRER_POLICY, SET_COOKIE},
    },
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use url::Url;
use zeroize::Zeroizing;

use super::config::{OidcConfig, TokenEndpointAuthMethod};
use super::discovery::{Discovery, ProviderMetadata};
use super::egress::ProviderEgress;
use super::pending::{PENDING_SIGN_IN_TTL, PendingSignIns, random_token};
use super::roles::{mapped_role, unmet_required_claim};
use super::throttle::SignInThrottle;
use super::tokens::{SeenLogoutTokens, TokenFailure, verify_id_token};
use super::user_provisioning::{ProvisionRefusal, provision_user_from_oidc};
use crate::auth::session::{OidcSessionBinding, SessionManager};
use crate::auth::session_cookie::{
    OIDC_STATE_COOKIE_NAME, build_oidc_state_cookie, clear_oidc_state_cookie, request_cookie,
};
use crate::auth::session_finalizer::{AuthenticatedPrincipal, SessionFinalizer, SessionManagerFinalizer};
use crate::auth::sign_in_pages::{
    is_allowed_return_target, sign_in_error_page, sign_in_success_response, throttled_sign_in_page,
};
use crate::auth::storage::{OidcIdentity, PasskeyStorage, UserData};
use crate::delegation_vault::oauth::{generate_pkce_challenge, generate_pkce_verifier};
use crate::integrations::{LoginFailure, LoginMethod};
use crate::jwt_bearer::JwksClient;
use crate::metrics::MetricsStore;
use crate::observability::loggable;
use crate::source_auth::client_ip::ClientIp;

/// The largest token endpoint response accepted.
const MAX_TOKEN_RESPONSE_BYTES: usize = 256 * 1024;

/// What a browser says a request will be used for (Fetch Metadata).
const SEC_FETCH_DEST: &str = "sec-fetch-dest";

/// Everything OIDC sign-in needs.
pub struct OidcState {
    pub config: Arc<OidcConfig>,
    pub(super) discovery: Discovery,
    pub(super) jwks: JwksClient,
    egress: ProviderEgress,
    pending: PendingSignIns,
    throttle: SignInThrottle,
    pub(super) seen_logout_tokens: SeenLogoutTokens,
    pub storage: Arc<PasskeyStorage>,
    pub session_manager: Arc<SessionManager>,
    terms_manager: Arc<crate::terms::TermsManager>,
}

impl OidcState {
    pub fn new(
        config: OidcConfig,
        storage: Arc<PasskeyStorage>,
        session_manager: Arc<SessionManager>,
        terms_manager: Arc<crate::terms::TermsManager>,
    ) -> Self {
        Self::with_egress(config, storage, session_manager, terms_manager, ProviderEgress::from_environment())
    }

    pub(crate) fn with_egress(
        config: OidcConfig,
        storage: Arc<PasskeyStorage>,
        session_manager: Arc<SessionManager>,
        terms_manager: Arc<crate::terms::TermsManager>,
        egress: ProviderEgress,
    ) -> Self {
        Self {
            config: Arc::new(config),
            discovery: Discovery::new(egress.clone()),
            jwks: JwksClient::new(),
            egress,
            pending: PendingSignIns::default(),
            throttle: SignInThrottle::default(),
            seen_logout_tokens: SeenLogoutTokens::default(),
            storage,
            session_manager,
            terms_manager,
        }
    }

    /// Fetch the provider's discovery document once at startup, so a problem with it is in the
    /// log before anyone tries to sign in. Sign-in fetches it again if this attempt fails.
    pub async fn check_provider(&self) {
        match self
            .discovery
            .metadata(&self.config)
            .await
        {
            Ok(_) => info!(issuer = %self.config.issuer, "OIDC sign-in is ready"),
            Err(detail) => warn!(
                issuer = %self.config.issuer,
                %detail,
                "The OpenID provider cannot be used yet; dashboard sign-in will retry it"
            ),
        }
    }
}

/// Why a sign-in was refused. The reason code goes to the log; the browser gets a generic page.
#[derive(Debug)]
pub(super) enum Refusal {
    NotNavigation,
    IssuerMismatch,
    StateUnknown,
    BindingMismatch,
    CodeMissing,
    AccessDenied,
    ExchangeFailed,
    IdTokenInvalid,
    ClaimNotAllowed,
    RoleUnmapped,
    UserDisabled,
    UsernameTaken,
    UserLimit(crate::config::LimitExceeded),
    OpUnavailable,
    ServerError,
}

impl Refusal {
    fn code(&self) -> &'static str {
        match self {
            Self::NotNavigation => "not_navigation",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::StateUnknown => "state_unknown",
            Self::BindingMismatch => "binding_mismatch",
            Self::CodeMissing => "code_missing",
            Self::AccessDenied => "access_denied",
            Self::ExchangeFailed => "exchange_failed",
            Self::IdTokenInvalid => "id_token_invalid",
            Self::ClaimNotAllowed => "claim_not_allowed",
            Self::RoleUnmapped => "role_unmapped",
            Self::UserDisabled => "user_disabled",
            Self::UsernameTaken => "username_taken",
            Self::UserLimit(_) => "user_limit",
            Self::OpUnavailable => "op_unavailable",
            Self::ServerError => "server_error",
        }
    }

    /// `401` for a code the provider refused (`invalid_grant`): the code is the one thing a
    /// caller sends that could be a guess. `400` for a sign-in start that is not a page the browser
    /// opens, a sign-in link naming another provider, an unknown or unbound `state` or a callback
    /// without a code; `502` for an ID token that did not
    /// verify, which comes from the provider and never from the caller; `403` for an account the
    /// settings refuse or whose every username another user holds.
    fn status(&self) -> StatusCode {
        match self {
            Self::NotNavigation
            | Self::IssuerMismatch
            | Self::StateUnknown
            | Self::BindingMismatch
            | Self::CodeMissing => StatusCode::BAD_REQUEST,
            Self::ExchangeFailed => StatusCode::UNAUTHORIZED,
            Self::IdTokenInvalid => StatusCode::BAD_GATEWAY,
            Self::AccessDenied
            | Self::ClaimNotAllowed
            | Self::RoleUnmapped
            | Self::UserDisabled
            | Self::UsernameTaken
            | Self::UserLimit(_) => StatusCode::FORBIDDEN,
            Self::OpUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn title(&self) -> &'static str {
        match self {
            Self::ClaimNotAllowed
            | Self::RoleUnmapped
            | Self::UserDisabled
            | Self::UsernameTaken
            | Self::UserLimit(_)
            | Self::OpUnavailable => "Sign-in unavailable",
            _ => "Sign-in failed",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::NotNavigation => "Open the sign-in page to sign in.".to_string(),
            Self::IssuerMismatch => "This sign-in link is not for this dashboard.".to_string(),
            Self::StateUnknown | Self::BindingMismatch => {
                "This sign-in has expired or was started in another browser. Start again from the sign-in page."
                    .to_string()
            }
            Self::AccessDenied => "The OpenID provider did not complete the sign-in.".to_string(),
            Self::ClaimNotAllowed | Self::RoleUnmapped | Self::UserDisabled | Self::UsernameTaken => {
                "Your account is not allowed to use this dashboard. Please contact your administrator.".to_string()
            }
            Self::UserLimit(limit) => limit.message(),
            Self::OpUnavailable => "Sign-in is unavailable: the OpenID provider could not be reached.".to_string(),
            Self::CodeMissing | Self::ExchangeFailed | Self::IdTokenInvalid | Self::ServerError => {
                "The sign-in could not be completed.".to_string()
            }
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let mut response = sign_in_error_page(self.status(), self.title(), &self.message());
        let headers = response.headers_mut();
        // On a mismatch the cookie belongs to a newer sign-in in this browser, which must still
        // be able to finish, and a start that is not a navigation may come from another site.
        if !matches!(self, Self::BindingMismatch | Self::NotNavigation)
            && let Ok(clear) = HeaderValue::from_str(&clear_oidc_state_cookie())
        {
            headers.append(SET_COOKIE, clear);
        }
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// Log a refusal with its reason code and what caused it, and return it.
pub(super) fn refused(
    refusal: Refusal,
    user_id: Option<&str>,
    detail: impl std::fmt::Display,
) -> Refusal {
    warn!(reason = refusal.code(), user_id = user_id.unwrap_or("-"), %detail, "OIDC sign-in refused");
    refusal
}

#[derive(Debug, Deserialize)]
pub struct OidcLoginQuery {
    pub next: Option<String>,
}

/// Start an OIDC sign-in. `next` is kept as the return target only when the return-target
/// allowlist admits it; otherwise the browser lands on `/`. A request the browser says is not a
/// page it opens (`Sec-Fetch-Dest` other than `document`), such as an image or frame another site
/// embeds, is refused before it counts against the sign-in budget.
/// GET /oidc/login
pub async fn oidc_login(
    State(oidc): State<Arc<OidcState>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    Query(query): Query<OidcLoginQuery>,
) -> Response {
    if let Some(destination) = headers
        .get(SEC_FETCH_DEST)
        .filter(|destination| destination.as_bytes() != b"document")
    {
        let destination = String::from_utf8_lossy(destination.as_bytes());
        let detail = format!("Sec-Fetch-Dest is {}", loggable::untrusted(&destination));
        return refused(Refusal::NotNavigation, None, detail).into_response();
    }
    if let Some(throttled) = throttled(&oidc, client_ip.map(|Extension(ClientIp(ip))| ip)) {
        return throttled;
    }
    let return_target = query
        .next
        .filter(|next| is_allowed_return_target(next))
        .unwrap_or_else(|| "/".to_string());
    start_sign_in(&oidc, None, return_target).await
}

/// Send the browser to the provider with PKCE, a `state` and a `nonce`, bound to this browser by
/// a cookie, remembering `return_target`, which the caller has checked, for the callback.
/// `login_hint` is passed on to the provider.
pub(super) async fn start_sign_in(
    oidc: &OidcState,
    login_hint: Option<&str>,
    return_target: String,
) -> Response {
    let metadata = match oidc
        .discovery
        .metadata(&oidc.config)
        .await
    {
        Ok(metadata) => metadata,
        Err(detail) => return refused(Refusal::OpUnavailable, None, detail).into_response(),
    };
    let Ok(mut authorization) = Url::parse(&metadata.authorization_endpoint) else {
        return refused(Refusal::OpUnavailable, None, "authorization_endpoint is not a URL").into_response();
    };

    let state = random_token();
    let nonce = random_token();
    let code_verifier = generate_pkce_verifier();
    authorization
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &oidc.config.client_id)
        .append_pair(
            "redirect_uri",
            oidc.config
                .redirect_uri
                .as_str(),
        )
        .append_pair("scope", &oidc.config.scopes.join(" "))
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &generate_pkce_challenge(&code_verifier))
        .append_pair("code_challenge_method", "S256")
        .extend_pairs(login_hint.map(|hint| ("login_hint", hint)));

    let Ok(cookie) = HeaderValue::from_str(&build_oidc_state_cookie(&state, PENDING_SIGN_IN_TTL.as_secs())) else {
        return refused(Refusal::ServerError, None, "the state cookie could not be built").into_response();
    };
    oidc.pending
        .insert(state, nonce, code_verifier, return_target);

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (headers, Redirect::to(authorization.as_str())).into_response()
}

/// The `429` page for a client over its sign-in budget or locked out, if it is.
pub(super) fn throttled(
    oidc: &OidcState,
    client: Option<std::net::IpAddr>,
) -> Option<Response> {
    let retry_after = oidc.throttle.admit(client)?;
    warn!(reason = "throttled", "Throttling OIDC sign-in from a client over its limit");
    Some(throttled_sign_in_page(retry_after))
}

/// What the provider sends the browser back with.
#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Finish an OIDC sign-in: check the browser binding, exchange the code, verify the ID token,
/// apply `required_claims` and `role_mapping`, and hand the new session to the dashboard.
/// GET /oidc/callback
pub async fn oidc_callback(
    Extension(metric_store): Extension<Option<Arc<MetricsStore>>>,
    State(oidc): State<Arc<OidcState>>,
    client_ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    let client = client_ip.map(|Extension(ClientIp(ip))| ip);
    if let Some(throttled) = throttled(&oidc, client) {
        return throttled;
    }
    match complete_sign_in(&oidc, &headers, params, metric_store).await {
        Ok(response) => {
            oidc.throttle
                .clear_failures(client);
            response
        }
        Err(refusal) => {
            if matches!(refusal, Refusal::ExchangeFailed) {
                oidc.throttle
                    .record_failure(client);
            }
            refusal.into_response()
        }
    }
}

async fn complete_sign_in(
    oidc: &OidcState,
    headers: &HeaderMap,
    params: CallbackParams,
    metric_store: Option<Arc<MetricsStore>>,
) -> Result<Response, Refusal> {
    let state = params
        .state
        .ok_or_else(|| refused(Refusal::StateUnknown, None, "the callback has no state"))?;
    let bound = request_cookie(headers, OIDC_STATE_COOKIE_NAME).is_some_and(|cookie| {
        cookie
            .as_bytes()
            .ct_eq(state.as_bytes())
            .into()
    });
    if !bound {
        return Err(refused(Refusal::BindingMismatch, None, "the state cookie is missing or names another sign-in"));
    }
    let pending = oidc
        .pending
        .take(&state)
        .ok_or_else(|| refused(Refusal::StateUnknown, None, "no sign-in is waiting for this state"))?;
    if let Some(error) = params.error {
        return Err(refused(Refusal::AccessDenied, None, format!("the provider answered {}", loggable_code(&error))));
    }
    let code = Zeroizing::new(
        params
            .code
            .ok_or_else(|| refused(Refusal::CodeMissing, None, "the callback has neither a code nor an error"))?,
    );

    let metadata = oidc
        .discovery
        .metadata(&oidc.config)
        .await
        .map_err(|detail| refused(Refusal::OpUnavailable, None, detail))?;
    let id_token = match exchange_code(oidc, &metadata, &code, &pending.code_verifier).await {
        Ok(id_token) => id_token,
        Err(ExchangeFailure::CodeRefused(detail)) => {
            login_failed(LoginFailure::OidcRejected);
            return Err(refused(Refusal::ExchangeFailed, None, detail));
        }
        Err(ExchangeFailure::Unreachable(detail)) => {
            oidc.discovery
                .mark_stale()
                .await;
            return Err(refused(Refusal::OpUnavailable, None, detail));
        }
        Err(ExchangeFailure::Unusable(detail)) => return Err(refused(Refusal::ServerError, None, detail)),
    };
    let verified = match verify_id_token(&id_token, &oidc.config, &oidc.jwks, &metadata.jwks_uri, &pending.nonce).await
    {
        Ok(verified) => verified,
        Err(TokenFailure::KeysUnavailable(detail) | TokenFailure::KeyNotFoundDuringCooldown(detail)) => {
            oidc.discovery
                .mark_stale()
                .await;
            return Err(refused(Refusal::OpUnavailable, None, detail));
        }
        Err(TokenFailure::Invalid(detail)) => {
            login_failed(LoginFailure::OidcRejected);
            return Err(refused(Refusal::IdTokenInvalid, None, detail));
        }
    };

    let binding = OidcSessionBinding {
        issuer: oidc.config.issuer.clone(),
        subject: verified.subject.clone(),
        sid: verified.sid.clone(),
        id_token: Some(id_token.to_string()),
    };
    let identity = OidcIdentity {
        issuer: oidc.config.issuer.clone(),
        subject: verified.subject,
    };
    let existing = oidc
        .storage
        .load_user_by_oidc_identity(&identity)
        .await
        .map_err(|e| refused(Refusal::ServerError, None, e))?;
    let existing_id = existing
        .as_ref()
        .map(|user| user.user_id.as_str());

    if let Some(claim) = unmet_required_claim(&verified.claims, &oidc.config.required_claims) {
        end_sessions(oidc, existing.as_ref()).await;
        login_failed(LoginFailure::ClaimNotAllowed);
        return Err(refused(Refusal::ClaimNotAllowed, existing_id, format!("required claim {claim} is not met")));
    }
    let Some(role) = mapped_role(&verified.claims, &oidc.config.role_mapping) else {
        end_sessions(oidc, existing.as_ref()).await;
        login_failed(LoginFailure::RoleNotMapped);
        return Err(refused(Refusal::RoleUnmapped, existing_id, "no value of the role claim is mapped"));
    };

    let provisioned =
        match provision_user_from_oidc(&oidc.storage, identity, &verified.claims, &oidc.config.claims, role).await {
            Ok(provisioned) => provisioned,
            Err(ProvisionRefusal::NotApproved(user)) => {
                end_sessions(oidc, Some(user.as_ref())).await;
                login_failed(LoginFailure::NotApproved(user.as_ref()));
                return Err(refused(Refusal::UserDisabled, Some(&user.user_id), "the user is not approved"));
            }
            Err(ProvisionRefusal::UserLimit(limit)) => {
                return Err(refused(Refusal::UserLimit(limit), None, "the appliance user limit is reached"));
            }
            Err(ProvisionRefusal::UsernameTaken) => {
                return Err(refused(
                    Refusal::UsernameTaken,
                    existing_id,
                    "every username for this account belongs to another user",
                ));
            }
            Err(ProvisionRefusal::Storage(e)) => return Err(refused(Refusal::ServerError, existing_id, e)),
        };
    let user = &provisioned.user;
    if provisioned.role_changed() {
        end_sessions(oidc, Some(user)).await;
    }

    let finalized = SessionManagerFinalizer::new(oidc.session_manager.clone(), oidc.terms_manager.clone())
        .finalize_session(AuthenticatedPrincipal::new(user.username.clone(), user.user_id.clone()).with_oidc(binding))
        .await
        .map_err(|e| refused(Refusal::ServerError, Some(&user.user_id), format!("{e:?}")))?;

    info!(user_id = %user.user_id, role = %user.role, "OIDC sign-in succeeded");
    crate::auth::sign_in_events::raise_sign_in_events(&provisioned, LoginMethod::Oidc, metric_store);

    let mut response_headers = finalized.headers;
    if let Ok(clear) = HeaderValue::from_str(&clear_oidc_state_cookie()) {
        response_headers.append(SET_COOKIE, clear);
    }
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response_headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    sign_in_success_response(response_headers, &pending.return_target, &finalized.session_token).map_err(|status| {
        refused(Refusal::ServerError, Some(&user.user_id), format!("the hand-off page could not be built ({status})"))
    })
}

fn login_failed(failure: LoginFailure<'_>) {
    crate::integrations::trigger_user_login_failed(LoginMethod::Oidc, failure);
}

/// End every session of a user whose access a sign-in withdrew or changed, so their other tabs
/// and devices sign in again under the new decision.
async fn end_sessions(
    oidc: &OidcState,
    user: Option<&UserData>,
) {
    if let Some(user) = user {
        let ended = oidc
            .session_manager
            .remove_sessions_for_user(&user.user_id)
            .await;
        if ended > 0 {
            info!(user_id = %user.user_id, ended, "Ended the user's other sessions after an OIDC sign-in");
        }
    }
}

/// An OAuth error code from the provider, reduced to the characters such codes use, so a hostile
/// value cannot forge log lines.
fn loggable_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect()
}

#[derive(Default, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    error: Option<String>,
}

/// Why a code exchange failed. The detail is for the log and never holds the code, the secret or
/// a token.
#[derive(Debug)]
enum ExchangeFailure {
    /// The provider refused the code (`invalid_grant`, RFC 6749 section 5.2).
    CodeRefused(String),
    /// The token endpoint could not be reached, was refused, answered `404` or failed with a
    /// `5xx`: a moved endpoint could explain it, so the discovery document is fetched again.
    Unreachable(String),
    /// Any other answer, such as `invalid_client`, or a response without a usable ID token: a
    /// configuration or provider fault.
    Unusable(String),
}

/// Sort a token endpoint error answer by whose fault it is.
fn failed_exchange(
    status: reqwest::StatusCode,
    error: Option<&str>,
) -> ExchangeFailure {
    let detail = format!(
        "token endpoint answered HTTP {status} ({})",
        error
            .map(loggable_code)
            .unwrap_or_else(|| "no error code".to_string())
    );
    if status == reqwest::StatusCode::NOT_FOUND || status.is_server_error() {
        ExchangeFailure::Unreachable(detail)
    } else if error == Some("invalid_grant") {
        ExchangeFailure::CodeRefused(detail)
    } else {
        ExchangeFailure::Unusable(detail)
    }
}

/// Exchange the authorization code at the token endpoint and return the ID token.
async fn exchange_code(
    oidc: &OidcState,
    metadata: &ProviderMetadata,
    code: &str,
    code_verifier: &str,
) -> Result<Zeroizing<String>, ExchangeFailure> {
    let client = oidc
        .egress
        .client_for(&metadata.token_endpoint, Duration::from_secs(crate::http_client::EXTERNAL_TIMEOUT_SECS))
        .await
        .map_err(|e| ExchangeFailure::Unreachable(format!("token endpoint refused: {e}")))?;
    let config = &oidc.config;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", config.redirect_uri.as_str()),
        ("code_verifier", code_verifier),
    ];
    let mut request = client
        .post(&metadata.token_endpoint)
        .header(reqwest::header::ACCEPT, "application/json");
    match config.token_endpoint_auth_method {
        TokenEndpointAuthMethod::ClientSecretBasic => {
            let credentials = crate::delegation_vault::revocation::basic_authorization(
                &config.client_id,
                config.client_secret.expose(),
            );
            let mut authorization = HeaderValue::from_str(&credentials)
                .map_err(|_| ExchangeFailure::Unusable("the client credentials are not a valid header".to_string()))?;
            authorization.set_sensitive(true);
            request = request.header(AUTHORIZATION, authorization);
        }
        TokenEndpointAuthMethod::ClientSecretPost => {
            form.push(("client_id", &config.client_id));
            form.push(("client_secret", config.client_secret.expose()));
        }
    }
    let response = request
        .form(&form)
        .send()
        .await
        .map_err(|e| ExchangeFailure::Unreachable(format!("token request failed: {}", e.without_url())))?;
    let status = response.status();
    let limits = crate::proxy::upstream_body::UpstreamBodyLimits::new(
        MAX_TOKEN_RESPONSE_BYTES,
        None,
        crate::http_client::EXTERNAL_TIMEOUT_SECS,
    );
    let body = Zeroizing::new(
        crate::proxy::upstream_body::read_bounded(response, limits)
            .await
            .map_err(|e| ExchangeFailure::Unusable(format!("the token response could not be read: {e}")))?
            .to_vec(),
    );
    let parsed: TokenResponse = serde_json::from_slice(&body).unwrap_or_default();
    if !status.is_success() {
        return Err(failed_exchange(status, parsed.error.as_deref()));
    }
    parsed
        .id_token
        .map(Zeroizing::new)
        .ok_or_else(|| ExchangeFailure::Unusable("the token response has no id_token".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_provider_error_code_is_reduced_before_it_is_logged() {
        assert_eq!(loggable_code("access_denied"), "access_denied");
        assert_eq!(loggable_code("x\nINFO forged line"), "xINFOforgedline");
        assert_eq!(loggable_code(&"a".repeat(200)).len(), 64);
    }

    #[test]
    fn only_a_refused_code_counts_as_a_failed_sign_in() {
        assert_eq!(Refusal::ExchangeFailed.status(), StatusCode::UNAUTHORIZED);
        for refusal in [Refusal::IssuerMismatch, Refusal::StateUnknown, Refusal::BindingMismatch, Refusal::CodeMissing]
        {
            assert_eq!(refusal.status(), StatusCode::BAD_REQUEST, "{}", refusal.code());
        }
        assert_eq!(Refusal::IdTokenInvalid.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(Refusal::OpUnavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(Refusal::ServerError.status(), StatusCode::INTERNAL_SERVER_ERROR);
        for refusal in [
            Refusal::AccessDenied,
            Refusal::ClaimNotAllowed,
            Refusal::RoleUnmapped,
            Refusal::UserDisabled,
            Refusal::UsernameTaken,
        ] {
            assert_eq!(refusal.status(), StatusCode::FORBIDDEN, "{}", refusal.code());
        }
    }

    #[test]
    fn a_token_endpoint_error_is_sorted_by_whose_fault_it_is() {
        use reqwest::StatusCode as Status;
        for (status, error, expected) in [
            (Status::BAD_REQUEST, Some("invalid_grant"), "code_refused"),
            (Status::BAD_REQUEST, Some("invalid_request"), "unusable"),
            (Status::UNAUTHORIZED, Some("invalid_client"), "unusable"),
            (Status::BAD_REQUEST, None, "unusable"),
            (Status::NOT_FOUND, None, "unreachable"),
            (Status::BAD_GATEWAY, Some("invalid_grant"), "unreachable"),
        ] {
            let sorted = match failed_exchange(status, error) {
                ExchangeFailure::CodeRefused(_) => "code_refused",
                ExchangeFailure::Unreachable(_) => "unreachable",
                ExchangeFailure::Unusable(_) => "unusable",
            };
            assert_eq!(sorted, expected, "{status} {error:?}");
        }
    }

    #[test]
    fn a_refused_account_learns_nothing_about_why() {
        let messages: Vec<String> =
            [Refusal::ClaimNotAllowed, Refusal::RoleUnmapped, Refusal::UserDisabled, Refusal::UsernameTaken]
                .iter()
                .map(Refusal::message)
                .collect();
        assert!(
            messages
                .windows(2)
                .all(|pair| pair[0] == pair[1]),
            "{messages:?}"
        );
    }

    #[tokio::test]
    async fn the_user_limit_is_a_readable_uncached_page_naming_the_limit() {
        let refusal = Refusal::UserLimit(crate::config::LimitExceeded {
            dimension: "users".to_string(),
            limit: 1,
            current: 1,
        });

        let response = refusal.into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        assert!(
            response
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .any(|cookie| {
                    cookie
                        .to_str()
                        .unwrap()
                        .starts_with("__Host-oidc_state=;")
                })
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let page = String::from_utf8(body.to_vec()).unwrap();
        assert!(page.contains("Sign-in unavailable"), "{page}");
        assert!(page.contains("Appliance limit reached for 'users': 1 of 1 in use"), "{page}");
    }

    #[test]
    fn a_binding_mismatch_leaves_the_newer_sign_ins_cookie_in_place() {
        let response = Refusal::BindingMismatch.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response
                .headers()
                .get(SET_COOKIE)
                .is_none()
        );
    }
}
