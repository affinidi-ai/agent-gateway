use axum::{
    Extension, Form, Json,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};

use super::service::SamlService;
use super::user_provisioning::provision_user_from_saml;
use crate::auth::session::SessionManager;
use crate::auth::session_finalizer::{
    AuthenticatedPrincipal, SessionFinalizationError, SessionFinalizer, SessionManagerFinalizer,
};
use crate::auth::storage::PasskeyStorage;

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
}

/// SAML login request (POST form from Azure AD)
#[derive(Debug, Deserialize)]
pub struct SamlLoginForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,

    #[serde(rename = "RelayState")]
    #[allow(dead_code)]
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

/// Initiate SAML login (SP-initiated flow)
/// GET /saml/login
pub async fn saml_login(State(saml_state): State<Arc<SamlState>>) -> Result<Redirect, StatusCode> {
    info!("Initiating SAML login");

    // Create authentication request
    let authn_request = saml_state
        .saml_service
        .create_authn_request()
        .map_err(|e| {
            error!("Failed to create SAML authn request: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Redirect to IdP
    Ok(Redirect::to(&authn_request))
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

    // Return HTML with cookie and redirect
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <meta http-equiv="refresh" content="0;url=/">
    <script>
        sessionStorage.setItem('session_token', '{}');
        window.location.href = '/';
    </script>
</head>
<body>
    <p>Login successful. Redirecting...</p>
</body>
</html>"#,
        finalized_session.session_token
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
