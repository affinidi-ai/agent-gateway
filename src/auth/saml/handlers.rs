use axum::{
    Extension, Form, Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use super::service::{SamlService, TooManyPendingAuthnRequests};
use super::user_provisioning::provision_user_from_saml;
use crate::auth::session::SessionManager;
use crate::auth::session_finalizer::{
    AuthenticatedPrincipal, SessionFinalizationError, SessionFinalizer, SessionManagerFinalizer,
};
use crate::auth::storage::PasskeyStorage;
use crate::sts::throttle::TokenEndpointThrottle;

use crate::metrics::MetricsStore;

/// SAML state for authentication
#[derive(Clone)]
pub struct SamlState {
    /// SAML service instance
    pub saml_service: Arc<SamlService>,

    /// Storage for user data
    pub storage: Arc<PasskeyStorage>,

    /// Session manager
    pub session_manager: Arc<SessionManager>,

    /// Path to avatars storage
    pub avatars_storage_path: String,

    /// Optional notification store for sending notifications
    pub notification_store: Arc<tokio::sync::RwLock<Option<Arc<crate::integrations::FileSystemNotificationStore>>>>,

    /// Terms enforcement for human authentication.
    pub terms_manager: Arc<crate::terms::TermsManager>,

    /// Per-source-address limit on starting a sign-in, built from `saml.json` `login_throttle`.
    pub login_throttle: Arc<TokenEndpointThrottle>,
}

/// SAML login request (POST form from Azure AD)
#[derive(Debug, Deserialize)]
pub struct SamlLoginForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,

    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// Response for successful SAML login
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct SamlLoginResponse {
    pub session_token: String,
    pub user: SamlUserInfo,
}

/// User information from SAML
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct SamlUserInfo {
    pub user_id: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct SamlLoginQuery {
    pub next: Option<String>,
}

const CLI_AUTHORIZE_PATH: &str = "/api/auth/cli/authorize";

/// Only the dashboard root and the CLI authorize path (with its query) may be a return target.
/// Anything else, including off-origin and protocol-relative targets, an encoded slash or
/// backslash in the path, and characters that could break out of the ACS markup, is rejected.
/// The query may carry an encoded slash or backslash, since the CLI `state` is opaque.
pub(crate) fn is_allowed_return_target(target: &str) -> bool {
    let path = target
        .split_once('?')
        .map_or(target, |(path, _)| path)
        .to_ascii_lowercase();
    if path.contains("%2f") || path.contains("%5c") {
        return false;
    }
    let charset_ok = target.len() <= 1024
        && target.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'-' | b'_' | b'.' | b'/' | b'?' | b'&' | b'=' | b'%' | b'~' | b':' | b'+')
        });
    if !charset_ok {
        return false;
    }
    match target.split_once('?') {
        None => target == "/",
        Some((path, query)) => path == CLI_AUTHORIZE_PATH && !query.is_empty(),
    }
}

/// Initiate SAML login (SP-initiated flow)
/// GET /saml/login
///
/// A source address over its login limit gets 429 before any AuthnRequest is recorded. The
/// address comes from `X-Forwarded-For` / `Forwarded`; without either the per-address check is
/// skipped and only the cap on outstanding sign-ins applies. When that cap is reached the answer
/// is 503, since a request the gateway cannot record would be rejected at the ACS anyway. Both
/// answers are readable pages.
pub async fn saml_login(
    State(saml_state): State<Arc<SamlState>>,
    headers: HeaderMap,
    Query(query): Query<SamlLoginQuery>,
) -> Response {
    info!("Initiating SAML login");

    if let Some(retry_after) = saml_state
        .login_throttle
        .record_source_attempt(&headers)
    {
        warn!("Throttling SAML login from a source over its limit");
        return throttled_login_page(retry_after);
    }

    let return_target = query
        .next
        .as_deref()
        .filter(|next| is_allowed_return_target(next));

    match saml_state
        .saml_service
        .create_authn_request(return_target)
    {
        Ok(authn_request) => Redirect::to(&authn_request).into_response(),
        Err(e) if e.is::<TooManyPendingAuthnRequests>() => {
            warn!("Refusing SAML login: {}", e);
            saml_error_page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Sign-in busy",
                "Too many sign-ins are in progress. Please try again in a few minutes.",
            )
        }
        Err(e) => {
            error!("Failed to create SAML authn request: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn throttled_login_page(retry_after: u64) -> Response {
    let mut response = saml_error_page(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many sign-in attempts",
        &format!("Please try again in {retry_after} seconds."),
    );
    let headers = response.headers_mut();
    headers.insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Render a self-contained HTML error page for a failed SAML sign-in, so the
/// user sees why (e.g. the appliance user limit was reached) instead of a blank
/// status page.
fn saml_error_page(
    status: StatusCode,
    title: &str,
    message: &str,
) -> Response {
    let escape = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>{title}</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;">
    <h1>{title}</h1>
    <p>{message}</p>
    <p><a href="/login">Return to sign in</a></p>
</body>
</html>"#,
        title = escape(title),
        message = escape(message),
    );
    (status, Html(html)).into_response()
}

fn acs_success_html(
    redirect_target: &str,
    session_token: &str,
) -> String {
    let redirect_target_js = serde_json::to_string(redirect_target).unwrap_or_else(|_| "\"/\"".to_string());
    let redirect_target_attr = redirect_target
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <meta http-equiv="refresh" content="0;url={redirect_target_attr}">
    <script>
        sessionStorage.setItem('session_token', '{session_token}');
        window.location.href = {redirect_target_js};
    </script>
</head>
<body>
    <p>Login successful. Redirecting...</p>
</body>
</html>"#
    )
}

/// Assertion Consumer Service - receives SAML response from Azure AD
/// POST /saml/acs
pub async fn saml_acs(
    Extension(metric_store): Extension<Option<Arc<MetricsStore>>>,
    State(saml_state): State<Arc<SamlState>>,
    Form(form): Form<SamlLoginForm>,
) -> Result<Response, SessionFinalizationError> {
    info!("Processing SAML response at ACS endpoint");

    // Validate SAML response and extract assertion
    let assertion = saml_state
        .saml_service
        .validate_response(&form.saml_response)
        .map_err(|e| {
            error!("SAML response validation failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    // Extract user attributes
    let attributes = saml_state
        .saml_service
        .extract_attributes(&assertion)
        .map_err(|e| {
            error!("Failed to extract SAML attributes: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Provision or update user
    let user = match provision_user_from_saml(
        &saml_state.storage,
        &attributes,
        saml_state
            .saml_service
            .config(),
        &saml_state.avatars_storage_path,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            // A reached appliance user limit is reported to the SSO user as a
            // readable page rather than a blank 500.
            if let Some(limit) = e.downcast_ref::<crate::config::LimitExceeded>() {
                error!("SAML sign-in blocked by appliance limit: {}", limit.message());
                return Ok(saml_error_page(StatusCode::FORBIDDEN, "Sign-in unavailable", &limit.message()));
            }
            error!("Failed to provision user from SAML: {}", e);
            return Ok(saml_error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Sign-in failed",
                "We couldn't complete your sign-in. Please contact your administrator.",
            ));
        }
    };
    let finalized_session = SessionManagerFinalizer::new(
        saml_state
            .session_manager
            .clone(),
        saml_state
            .terms_manager
            .clone(),
    )
    .finalize_session(AuthenticatedPrincipal::new(user.username.clone(), user.user_id.clone()))
    .await?;

    if let Some(metrics) = metric_store {
        let user_role = user.role.clone();
        tokio::spawn(async move {
            metrics
                .record_user_login(user_role.to_string().as_str())
                .await;
        });
    }

    // Trigger user.login integration (async, non-blocking)
    let notif_store_guard = saml_state
        .notification_store
        .read()
        .await;
    if let Some(notif_store) = notif_store_guard.as_ref() {
        let notif = notif_store.clone();
        let user_clone = user.clone();
        crate::observability::spawn_traced_task("integration.user_login", async move {
            crate::integrations::trigger_user_login(notif.as_ref(), &user_clone).await;
        });
    }
    drop(notif_store_guard);

    info!("SAML login successful for user: {} (role: {:?})", user.username, user.role);

    tracing::info!("Setting SAML session cookie");

    let redirect_target = form
        .relay_state
        .as_deref()
        .and_then(|relay_state| {
            saml_state
                .saml_service
                .take_return_target(relay_state)
        })
        .filter(|target| is_allowed_return_target(target));

    let html = acs_success_html(
        redirect_target
            .as_deref()
            .unwrap_or("/"),
        &finalized_session.session_token,
    );

    Ok((finalized_session.headers, Html(html)).into_response())
}

/// Serve SAML metadata
/// GET /saml/metadata
pub async fn saml_metadata(State(saml_state): State<Arc<SamlState>>) -> Result<Response, StatusCode> {
    info!("Serving SAML metadata");

    let metadata = saml_state
        .saml_service
        .generate_metadata()
        .map_err(|e| {
            error!("Failed to generate SAML metadata: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(([(axum::http::header::CONTENT_TYPE, "application/xml")], metadata).into_response())
}

/// SAML logout endpoint
/// POST /saml/logout
pub async fn saml_logout(
    State(saml_state): State<Arc<SamlState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    info!("Processing SAML logout");

    if let Some(token) = crate::auth_manager::middleware::extract_session_token_from_headers(&headers) {
        saml_state
            .session_manager
            .remove_session(&token)
            .await;
        info!("Session deleted");
    }

    let session_cookie =
        match axum::http::header::HeaderValue::from_str(&crate::auth::session_cookie::clear_session_cookie()) {
            Ok(value) => value,
            Err(err) => {
                error!("Failed to serialize session cookie header: {}", err);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let mut response_headers = axum::http::header::HeaderMap::new();
    response_headers.insert(axum::http::header::SET_COOKIE, session_cookie);

    (response_headers, StatusCode::OK).into_response()
}

/// Check SAML authentication status
/// GET /auth/check
#[allow(clippy::result_large_err)] // FIXME: Response is not an error
pub async fn saml_check_auth(
    headers: axum::http::HeaderMap,
    axum::Extension(session_manager): axum::Extension<Arc<SessionManager>>,
    axum::Extension(terms_manager): axum::Extension<Arc<crate::terms::TermsManager>>,
) -> Result<Json<serde_json::Value>, Response> {
    let session_token =
        crate::auth_manager::middleware::extract_session_token_from_headers(&headers).ok_or_else(|| {
            tracing::debug!("Auth check: No session token found in Authorization header or cookie");
            StatusCode::UNAUTHORIZED.into_response()
        })?;

    tracing::debug!(
        "Auth check: Validating session token {}...",
        session_token
            .chars()
            .take(8)
            .collect::<String>()
    );

    // Validate session
    match session_manager
        .validate_session_record(&session_token)
        .await
    {
        Some(session) => {
            let consent_required = if session.terms_gate == crate::auth::session::TermsSessionGate::ConsentPending {
                terms_manager
                    .status(&session.user_id, crate::terms::AcceptanceContext::Login)
                    .await
                    .map_err(IntoResponse::into_response)?
                    .consent_required
            } else {
                false
            };
            tracing::info!("Auth check: Session valid for user {} ({})", session.username, session.user_id);
            Ok(Json(serde_json::json!({
                "authenticated": true,
                "username": session.username,
                "user_id": session.user_id,
                "consent_required": consent_required
            })))
        }
        None => {
            tracing::warn!(
                "Auth check: Session validation failed for token {}...",
                session_token
                    .chars()
                    .take(8)
                    .collect::<String>()
            );
            Err(StatusCode::UNAUTHORIZED.into_response())
        }
    }
}

/// Generic logout endpoint for SAML (compatible with frontend)
/// POST /auth/logout
pub async fn saml_logout_generic(
    headers: axum::http::HeaderMap,
    axum::Extension(session_manager): axum::Extension<Arc<SessionManager>>,
) -> impl IntoResponse {
    info!("Processing generic SAML logout");

    if let Some(token) = crate::auth_manager::middleware::extract_session_token_from_headers(&headers) {
        session_manager
            .remove_session(&token)
            .await;
        info!("Session removed");
    }

    let session_cookie =
        match axum::http::header::HeaderValue::from_str(&crate::auth::session_cookie::clear_session_cookie()) {
            Ok(value) => value,
            Err(err) => {
                error!("Failed to serialize session cookie header: {}", err);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let mut response_headers = axum::http::header::HeaderMap::new();
    response_headers.insert(axum::http::header::SET_COOKIE, session_cookie);

    (response_headers, StatusCode::OK).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::auth_config::{SamlAttributeMapping, SamlConfig};
    use crate::config::types::LoginThrottleConfig;
    use axum::http::header::LOCATION;
    use std::collections::HashMap;

    const CLI_TARGET: &str = "/api/auth/cli/authorize?port=52111&state=st&challenge=ch";

    #[test]
    fn return_target_accepts_the_dashboard_root_and_cli_authorize() {
        assert!(is_allowed_return_target("/"));
        assert!(is_allowed_return_target(CLI_TARGET));
        assert!(is_allowed_return_target("/api/auth/cli/authorize?port=52111&state=a%20b&challenge=ch"));
    }

    #[test]
    fn return_target_rejects_paths_outside_the_allow_list() {
        assert!(!is_allowed_return_target("/settings"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize/extra?port=1"));
        assert!(!is_allowed_return_target("/?port=52111"));
        assert!(!is_allowed_return_target("/api/v1/secrets?x=1"));
    }

    #[test]
    fn return_target_rejects_off_origin_targets() {
        assert!(!is_allowed_return_target("//evil.example"));
        assert!(!is_allowed_return_target("https://evil.example"));
        assert!(!is_allowed_return_target("/\\evil.example"));
        assert!(!is_allowed_return_target("/%2fevil.example"));
        assert!(!is_allowed_return_target("/%5Cevil.example"));
        assert!(!is_allowed_return_target("evil.example"));
    }

    #[test]
    fn return_target_accepts_an_encoded_slash_or_backslash_in_the_cli_state() {
        let target = format!("/api/auth/cli/authorize?port=52111&state={}&challenge=ch", urlencoding::encode("a/b\\c"));
        assert_eq!(target, "/api/auth/cli/authorize?port=52111&state=a%2Fb%5Cc&challenge=ch");

        assert!(is_allowed_return_target(&target));
    }

    #[test]
    fn return_target_rejects_traversal_in_the_path_even_with_a_query() {
        assert!(!is_allowed_return_target("/api/auth/cli/authorize%2f?port=1"));
        assert!(!is_allowed_return_target("/api/auth/cli%2Fauthorize?port=1"));
        assert!(!is_allowed_return_target("/api/auth/cli%5cauthorize?port=1"));
        assert!(!is_allowed_return_target("/api/auth/cli\\authorize?port=1"));
        assert!(!is_allowed_return_target("/api/auth/../auth/cli/authorize?port=1"));
        assert!(!is_allowed_return_target("/api/auth/%2e%2e/cli/authorize?port=1"));
        assert!(!is_allowed_return_target("//api/auth/cli/authorize?port=1"));
        assert!(!is_allowed_return_target("/%2f/api/auth/cli/authorize?port=1"));
    }

    #[test]
    fn return_target_rejects_markup_and_control_characters() {
        assert!(!is_allowed_return_target("/a\"</script><script>alert(1)"));
        assert!(!is_allowed_return_target("/a'b"));
        assert!(!is_allowed_return_target("/a b"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?port=1<"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?port=1>"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?port=1\n"));
        assert!(!is_allowed_return_target("/api/auth/cli/authorize?port=1\u{7f}"));
    }

    #[test]
    fn acs_html_redirects_to_the_target_in_markup_and_script() {
        let html = acs_success_html(CLI_TARGET, "tok-1");

        assert!(html.contains("content=\"0;url=/api/auth/cli/authorize?port=52111&amp;state=st&amp;challenge=ch\""));
        assert!(html.contains("window.location.href = \"/api/auth/cli/authorize?port=52111&state=st&challenge=ch\";"));
        assert!(html.contains("sessionStorage.setItem('session_token', 'tok-1');"));
    }

    #[test]
    fn acs_html_escapes_a_hostile_target_in_the_meta_refresh() {
        let html = acs_success_html("/a\"><script>x</script>", "tok-1");

        assert!(html.contains("content=\"0;url=/a&quot;&gt;&lt;script&gt;x&lt;/script&gt;\""));
    }

    async fn saml_state(dir: &std::path::Path) -> Arc<SamlState> {
        saml_state_with_throttle(dir, LoginThrottleConfig::default()).await
    }

    async fn saml_state_with_throttle(
        dir: &std::path::Path,
        login_throttle: LoginThrottleConfig,
    ) -> Arc<SamlState> {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::default()
            .self_signed(&key)
            .unwrap();
        let cert_path = dir.join("idp.crt");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        let config = SamlConfig {
            idp_entity_id: "test-idp".to_string(),
            idp_sso_url: "https://idp.example.test/sso".to_string(),
            idp_slo_url: None,
            sp_entity_id: "test-sp".to_string(),
            sp_acs_url: "https://sp.example.test/saml/acs".to_string(),
            idp_cert_path: cert_path
                .to_string_lossy()
                .to_string(),
            attribute_mapping: SamlAttributeMapping::default(),
            role_mapping: HashMap::new(),
            require_encrypted_assertions: false,
            sign_requests: false,
            sp_key_path: None,
            sp_cert_path: None,
            graph_api: None,
            login_throttle: Default::default(),
        };
        let avatars = dir
            .join("avatars")
            .to_string_lossy()
            .to_string();
        Arc::new(SamlState {
            saml_service: Arc::new(SamlService::new(config).unwrap()),
            storage: Arc::new(
                PasskeyStorage::new(
                    dir.join("passkeys")
                        .to_string_lossy()
                        .to_string(),
                    avatars.clone(),
                )
                .await
                .unwrap(),
            ),
            session_manager: Arc::new(SessionManager::new()),
            avatars_storage_path: avatars,
            notification_store: Arc::new(tokio::sync::RwLock::new(None)),
            terms_manager: Arc::new(crate::terms::TermsManager::disabled()),
            login_throttle: Arc::new(TokenEndpointThrottle::per_source_address(&login_throttle)),
        })
    }

    async fn login_from(
        state: &Arc<SamlState>,
        source_ip: Option<&str>,
    ) -> Response {
        let mut headers = HeaderMap::new();
        if let Some(ip) = source_ip {
            headers.insert("x-forwarded-for", HeaderValue::from_str(ip).unwrap());
        }
        saml_login(State(state.clone()), headers, Query(SamlLoginQuery { next: None })).await
    }

    async fn login_location(
        state: Arc<SamlState>,
        next: Option<&str>,
    ) -> String {
        saml_login(State(state), HeaderMap::new(), Query(SamlLoginQuery { next: next.map(str::to_string) }))
            .await
            .headers()
            .get(LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }

    fn relay_state_key(location: &str) -> &str {
        location
            .split_once("&RelayState=")
            .map(|(_, key)| key)
            .unwrap()
    }

    #[tokio::test]
    async fn saml_login_sends_a_short_relay_state_key_that_returns_the_target_once() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state(dir.path()).await;

        let location = login_location(state.clone(), Some(CLI_TARGET)).await;

        assert!(location.starts_with("https://idp.example.test/sso?SAMLRequest="));
        let key = relay_state_key(&location);
        assert!(key.len() <= super::super::relay_state::MAX_RELAY_STATE_BYTES, "{key}");
        assert!(!location.contains(&*urlencoding::encode(CLI_TARGET)));
        let service = &state.saml_service;
        assert_eq!(
            service
                .take_return_target(key)
                .as_deref(),
            Some(CLI_TARGET)
        );
        assert!(
            service
                .take_return_target(key)
                .is_none()
        );
    }

    #[tokio::test]
    async fn saml_login_keeps_a_cli_target_whose_state_has_an_encoded_slash() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state(dir.path()).await;
        let target = "/api/auth/cli/authorize?port=52111&state=a%2Fb%5Cc&challenge=ch";

        let location = login_location(state.clone(), Some(target)).await;

        assert_eq!(
            state
                .saml_service
                .take_return_target(relay_state_key(&location))
                .as_deref(),
            Some(target)
        );
    }

    #[tokio::test]
    async fn an_unknown_relay_state_returns_no_target() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state(dir.path()).await;

        for relay_state in ["0123456789abcdef0123456789abcdef", CLI_TARGET, ""] {
            assert!(
                state
                    .saml_service
                    .take_return_target(relay_state)
                    .is_none(),
                "{relay_state}"
            );
        }
    }

    #[tokio::test]
    async fn saml_login_answers_503_when_too_many_sign_ins_are_outstanding() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state(dir.path()).await;
        for _ in 0..super::super::pending_requests::MAX_PENDING_AUTHN_REQUESTS {
            login_location(state.clone(), None).await;
        }

        let response = login_from(&state, None).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response
                .headers()
                .get(LOCATION)
                .is_none()
        );
    }

    #[tokio::test]
    async fn saml_login_drops_a_target_outside_the_allow_list() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state(dir.path()).await;

        for next in ["//evil.example", "/settings", "https://evil.example"] {
            let location = login_location(state.clone(), Some(next)).await;
            assert!(!location.contains("RelayState"), "{next}");
        }
        let location = login_location(state, None).await;
        assert!(!location.contains("RelayState"));
    }
    fn throttle_of(
        enabled: bool,
        requests: u32,
    ) -> LoginThrottleConfig {
        LoginThrottleConfig {
            enabled,
            per_ip: crate::config::types::RateLimitConfig {
                requests,
                window_secs: 60,
                burst: None,
            },
        }
    }

    #[tokio::test]
    async fn saml_login_lets_a_source_under_its_limit_through() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state_with_throttle(dir.path(), throttle_of(true, 2)).await;

        for _ in 0..2 {
            assert!(
                login_from(&state, Some("203.0.113.7"))
                    .await
                    .status()
                    .is_redirection()
            );
        }
    }

    #[tokio::test]
    async fn saml_login_answers_429_with_retry_after_for_a_source_over_its_limit() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state_with_throttle(dir.path(), throttle_of(true, 1)).await;
        login_from(&state, Some("203.0.113.7")).await;

        let response = login_from(&state, Some("203.0.113.7")).await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = response
            .headers()
            .get(header::RETRY_AFTER)
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&retry_after), "{retry_after}");
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap(),
            "no-store"
        );
        assert!(
            response
                .headers()
                .get(LOCATION)
                .is_none()
        );
    }

    #[tokio::test]
    async fn saml_login_counts_each_source_separately() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state_with_throttle(dir.path(), throttle_of(true, 1)).await;
        login_from(&state, Some("203.0.113.7")).await;
        login_from(&state, Some("203.0.113.7")).await;

        let response = login_from(&state, Some("198.51.100.4")).await;

        assert!(
            response
                .status()
                .is_redirection()
        );
    }

    #[tokio::test]
    async fn a_throttled_saml_login_records_no_authn_request() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state_with_throttle(dir.path(), throttle_of(true, 1)).await;
        login_from(&state, Some("203.0.113.7")).await;
        for _ in 0..5 {
            assert_eq!(
                login_from(&state, Some("203.0.113.7"))
                    .await
                    .status(),
                StatusCode::TOO_MANY_REQUESTS
            );
        }

        for _ in 1..super::super::pending_requests::MAX_PENDING_AUTHN_REQUESTS {
            assert!(
                login_from(&state, None)
                    .await
                    .status()
                    .is_redirection()
            );
        }
        assert_eq!(
            login_from(&state, None)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn saml_login_skips_the_source_limit_when_the_throttle_is_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let state = saml_state_with_throttle(dir.path(), throttle_of(false, 1)).await;

        for _ in 0..5 {
            assert!(
                login_from(&state, Some("203.0.113.7"))
                    .await
                    .status()
                    .is_redirection()
            );
        }
    }
}
