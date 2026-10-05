use axum::{
    Extension, Json,
    extract::State,
    http::{
        StatusCode,
        header::{HeaderMap, HeaderValue, SET_COOKIE},
    },
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};
use webauthn_rs::prelude::*;

use super::state::{AuthState, ChallengeState};
use crate::auth::session_finalizer::{
    AuthenticatedPrincipal, SessionFinalizationError, SessionFinalizer, SessionManagerFinalizer,
};

use crate::metrics::MetricsStore;

/// Request to start passkey registration
#[derive(Debug, Deserialize)]
pub struct RegisterStartRequest {
    pub username: String,
}

/// Response from registration start
#[derive(Debug, Serialize)]
pub struct RegisterStartResponse {
    pub challenge_id: String,
    pub creation_options: CreationChallengeResponse,
}

/// Request to complete passkey registration
#[derive(Debug, Deserialize)]
pub struct RegisterFinishRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
    #[serde(default)]
    pub accepted_terms: Vec<crate::terms::AcceptedTermsVersion>,
}

pub(crate) enum RegisterFinishError {
    Status(StatusCode),
    Terms(crate::terms::TermsError),
}

impl From<StatusCode> for RegisterFinishError {
    fn from(value: StatusCode) -> Self {
        Self::Status(value)
    }
}

impl From<crate::terms::TermsError> for RegisterFinishError {
    fn from(value: crate::terms::TermsError) -> Self {
        Self::Terms(value)
    }
}

impl IntoResponse for RegisterFinishError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Status(status) => status.into_response(),
            Self::Terms(error) => error.into_response(),
        }
    }
}

/// Request to start passkey authentication
#[derive(Debug, Deserialize)]
pub struct LoginStartRequest {
    pub username: String,
}

/// Response from login start
#[derive(Debug, Serialize)]
pub struct LoginStartResponse {
    pub challenge_id: String,
    pub request_options: RequestChallengeResponse,
}

/// Request to complete passkey authentication
#[derive(Debug, Deserialize)]
pub struct LoginFinishRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

/// Response from successful login
#[derive(Debug, Serialize)]
pub struct LoginFinishResponse {
    pub session_token: String,
    pub consent_required: bool,
}

/// Response for auth check
#[derive(Debug, Serialize)]
pub struct AuthCheckResponse {
    pub authenticated: bool,
    pub username: Option<String>,
    pub consent_required: bool,
}

/// Start passkey registration
pub async fn register_start(
    State(auth_state): State<Arc<AuthState>>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, (StatusCode, String)> {
    let user_exists = auth_state
        .storage
        .load_user(&req.username)
        .await
        .map_err(|e| {
            error!("Failed to check whether user exists: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start registration".to_string())
        })?
        .is_some();

    // Enforce the appliance user limit before starting a new registration.
    if let Ok(users) = auth_state
        .storage
        .list_users()
        .await
        && let Err(e) = crate::config::global_limits().check_can_add("users", users.len())
    {
        crate::config::log_limit_reached("users", &e);
        return Err((StatusCode::FORBIDDEN, e.message()));
    }

    if user_exists {
        error!("Registration requested for an existing username: {}", req.username);
    }

    // Generate registration challenge
    let user_unique_id = uuid::Uuid::new_v4();

    let (mut ccr, reg_state) = auth_state
        .webauthn
        .start_passkey_registration(user_unique_id, &req.username, &req.username, None)
        .map_err(|e| {
            error!("Failed to start passkey registration: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start passkey registration".to_string())
        })?;

    // Modify to allow cross-platform authenticators (1Password, security keys, etc.)
    // Set authenticatorAttachment to None to allow both platform and cross-platform
    if let Some(ref mut auth_sel) = ccr
        .public_key
        .authenticator_selection
    {
        auth_sel.authenticator_attachment = None;
    }

    // Store challenge state
    let challenge_id = uuid::Uuid::new_v4().to_string();
    let challenge_state = ChallengeState {
        registration_state: (!user_exists).then_some(reg_state),
        authentication_state: None,
        username: req.username.clone(),
        created_at: chrono::Utc::now(),
    };

    auth_state
        .challenges
        .write()
        .await
        .insert(challenge_id.clone(), challenge_state);

    Ok(Json(RegisterStartResponse {
        challenge_id,
        creation_options: ccr,
    }))
}

/// Complete passkey registration
pub async fn register_finish(
    Extension(metrics_store): Extension<Option<Arc<MetricsStore>>>,
    State(auth_state): State<Arc<AuthState>>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<StatusCode, RegisterFinishError> {
    info!("Completing passkey registration for challenge: {}", req.challenge_id);

    // Retrieve challenge state
    let mut challenges = auth_state
        .challenges
        .write()
        .await;
    let challenge_state = challenges
        .remove(&req.challenge_id)
        .ok_or_else(|| {
            error!("Challenge not found: {}", req.challenge_id);
            StatusCode::BAD_REQUEST
        })?;

    let reg_state = challenge_state
        .registration_state
        .ok_or(StatusCode::BAD_REQUEST)?;

    drop(challenges); // Release lock

    // Get username from challenge state
    let username = challenge_state
        .username
        .clone();

    // Verify the credential
    let passkey = auth_state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            error!("Failed to finish passkey registration: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    let terms_request = crate::terms::AcceptTermsRequest {
        accepted_terms: req.accepted_terms,
    };
    auth_state
        .terms_manager
        .validate_registration(&terms_request)
        .await?;

    let user_write_guard = auth_state
        .storage
        .user_write_guard()
        .await;
    let user = auth_state
        .storage
        .prepare_user_with_passkey(username.as_str(), passkey)
        .await
        .map_err(|e| {
            error!("Failed to prepare passkey user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    auth_state
        .terms_manager
        .accept(&user.user_id, crate::terms::AcceptanceContext::Registration, terms_request)
        .await?;
    auth_state
        .storage
        .save_user(&user)
        .await
        .map_err(|e| {
            error!(user_id = %user.user_id, error = %e, "Failed to store passkey user; any recorded Terms acceptance is retained");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    if user.is_primary {
        info!("First user '{}' registered as Primary Administrator (cannot be deleted or demoted)", username);
    } else {
        info!("New user '{}' registered with status 'new' - requires approval", username);
    }
    drop(user_write_guard);

    info!("Successfully registered passkey for user: {}", username);

    info!("User registration complete - role: {:?}, status: {:?}, user_id: {}", user.role, user.status, user.user_id);

    // Trigger user.created integration (async, non-blocking)
    let notif_store_guard = auth_state
        .notification_store
        .read()
        .await;
    if let Some(notif_store) = notif_store_guard.as_ref() {
        let notif = notif_store.clone();
        let user_clone = user.clone();
        tokio::spawn(async move {
            crate::integrations::trigger_user_created(notif.as_ref(), &user_clone).await;
        });

        if let Some(metrics_store) = metrics_store {
            let user_role = user.role.clone();
            tokio::spawn(async move {
                metrics_store
                    .record_user_event("created", user_role.to_string().as_str())
                    .await;
            });
        }
    }
    drop(notif_store_guard);

    if user.role == crate::auth::UserRole::Administrator && user.status == crate::auth::UserStatus::Approved {
        // First user - send admin welcome notification
        info!("First user detected as admin - attempting to send welcome notification");
        let notif_store_guard = auth_state
            .notification_store
            .read()
            .await;
        if let Some(notif_store) = notif_store_guard.as_ref() {
            use crate::integrations::NotificationStore;
            match notif_store
                .create_admin_welcome_notification(&user.user_id)
                .await
            {
                Ok(_) => info!("Successfully created admin welcome notification for user_id: {}", user.user_id),
                Err(e) => error!("Failed to create welcome notification for first user: {}", e),
            }
        } else {
            error!("Notification store not available - cannot send admin welcome");
        }
    } else if user.status == crate::auth::UserStatus::New {
        // New user - notify all administrators
        info!("New user pending approval - notifying administrators");
        let notif_store_guard = auth_state
            .notification_store
            .read()
            .await;
        if let Some(notif_store) = notif_store_guard.as_ref() {
            use crate::integrations::NotificationStore;

            // Find all administrators to notify
            if let Ok(user_ids) = auth_state
                .storage
                .list_users()
                .await
            {
                for admin_user_id in user_ids {
                    if let Ok(Some(admin_user)) = auth_state
                        .storage
                        .load_user_by_id(&admin_user_id)
                        .await
                        && admin_user.role == crate::auth::UserRole::Administrator
                    {
                        let mut notification = crate::integrations::Notification::new(
                            crate::integrations::types::NotificationType::System,
                            "New User Awaiting Approval".to_string(),
                            format!(
                                "User '{}' has registered and is awaiting approval. Please review and approve this user in the User Management section.",
                                username
                            ),
                            serde_json::json!({"username": username, "user_id": user.user_id, "action": crate::integrations::types::NotificationAction::UserApproval}),
                        );
                        notification.user_id = admin_user.user_id;
                        if let Err(e) = notif_store
                            .create(&notification)
                            .await
                        {
                            error!("Failed to create admin notification for new user: {}", e);
                        }
                    }
                }
            }
        } else {
            error!("Notification store not available - cannot notify admins");
        }
    }

    Ok(StatusCode::OK)
}

/// Start passkey authentication
pub async fn login_start(
    State(auth_state): State<Arc<AuthState>>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, StatusCode> {
    let is_approved = auth_state
        .storage
        .is_user_approved(&req.username)
        .await
        .map_err(|e| {
            error!("Failed to check user approval status: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let passkeys = auth_state
        .storage
        .get_passkeys(&req.username)
        .await
        .map_err(|e| {
            error!("Failed to load passkeys: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let passkeys = if !is_approved {
        error!("User '{}' is not approved to sign in", req.username);
        Vec::new()
    } else if passkeys.is_empty() {
        error!("No passkeys found for user: {}", req.username);
        Vec::new()
    } else {
        passkeys
    };

    // Generate authentication challenge
    let (rcr, auth_state_data) = auth_state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| {
            error!("Failed to start passkey authentication: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Store challenge state
    let challenge_id = uuid::Uuid::new_v4().to_string();
    let challenge_state = ChallengeState {
        registration_state: None,
        authentication_state: Some(auth_state_data),
        username: req.username.clone(),
        created_at: chrono::Utc::now(),
    };

    auth_state
        .challenges
        .write()
        .await
        .insert(challenge_id.clone(), challenge_state);

    Ok(Json(LoginStartResponse {
        challenge_id,
        request_options: rcr,
    }))
}

/// Complete passkey authentication
pub async fn login_finish(
    Extension(metrics_store): Extension<Option<Arc<MetricsStore>>>,
    State(auth_state): State<Arc<AuthState>>,
    Json(req): Json<LoginFinishRequest>,
) -> Result<impl IntoResponse, SessionFinalizationError> {
    info!("Completing passkey authentication for challenge: {}", req.challenge_id);

    // Retrieve challenge state
    let mut challenges = auth_state
        .challenges
        .write()
        .await;
    let challenge_state = challenges
        .remove(&req.challenge_id)
        .ok_or_else(|| {
            error!("Challenge not found: {}", req.challenge_id);
            StatusCode::BAD_REQUEST
        })?;

    let auth_state_data = challenge_state
        .authentication_state
        .ok_or(StatusCode::BAD_REQUEST)?;

    drop(challenges); // Release lock

    // Get username from challenge state
    let username = challenge_state
        .username
        .clone();

    // Verify the credential
    let _auth_result = auth_state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state_data)
        .map_err(|e| {
            error!("Failed to finish passkey authentication: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    // Load user to get user_id
    let mut user = auth_state
        .storage
        .load_user(&username)
        .await
        .map_err(|e| {
            error!("Failed to load user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            error!("User not found after authentication: {}", username);
            StatusCode::UNAUTHORIZED
        })?;

    // Update last_logged_in timestamp
    user.last_logged_in = Some(chrono::Utc::now());
    if let Err(e) = auth_state
        .storage
        .save_user(&user)
        .await
    {
        error!("Failed to update last_logged_in for user {}: {}", username, e);
    }

    let finalized_session = SessionManagerFinalizer::new(
        auth_state
            .session_manager
            .clone(),
        auth_state
            .terms_manager
            .clone(),
    )
    .finalize_session(AuthenticatedPrincipal::new(username.clone(), user.user_id.clone()))
    .await?;

    // Trigger user.login integration (async, non-blocking)
    let notif_store_guard = auth_state
        .notification_store
        .read()
        .await;
    if let Some(notif_store) = notif_store_guard.as_ref() {
        let notif = notif_store.clone();
        let user_clone = user.clone();
        tokio::spawn(async move {
            crate::integrations::trigger_user_login(notif.as_ref(), &user_clone).await;
        });

        if let Some(metrics_store) = metrics_store {
            let user_role = user.role.clone();
            tokio::spawn(async move {
                metrics_store
                    .record_user_login(user_role.to_string().as_str())
                    .await;
            });
        }
    }
    drop(notif_store_guard);

    info!("Successfully authenticated user: {}", username);

    Ok((
        finalized_session.headers,
        Json(LoginFinishResponse {
            session_token: finalized_session.session_token,
            consent_required: finalized_session.consent_required,
        }),
    ))
}

/// Check authentication status
pub async fn check_auth(
    State(auth_state): State<Arc<AuthState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<AuthCheckResponse>, crate::terms::TermsError> {
    let session_token = crate::auth_manager::middleware::extract_session_token_from_headers(&headers);

    info!("Checking authentication, session token present: {}", session_token.is_some());
    if let Some(token) = session_token.as_deref()
        && let Some(session) = auth_state
            .session_manager
            .validate_session_record(token)
            .await
    {
        let consent_required = if session.terms_gate == crate::auth::session::TermsSessionGate::ConsentPending {
            let status = auth_state
                .terms_manager
                .status(&session.user_id, crate::terms::AcceptanceContext::Login)
                .await?;
            session.terms_gate == crate::auth::session::TermsSessionGate::ConsentPending && status.consent_required
        } else {
            false
        };
        info!("Authentication successful for user: {}", session.username);
        return Ok(Json(AuthCheckResponse {
            authenticated: true,
            username: Some(session.username),
            consent_required,
        }));
    }

    info!("Authentication check failed, no valid session");
    Ok(Json(AuthCheckResponse {
        authenticated: false,
        username: None,
        consent_required: false,
    }))
}

/// Logout
pub async fn logout(
    State(auth_state): State<Arc<AuthState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Some(token) = crate::auth_manager::middleware::extract_session_token_from_headers(&headers) {
        auth_state
            .session_manager
            .remove_session(&token)
            .await;
        info!("User logged out");
    }

    let session_cookie = match HeaderValue::from_str(&crate::auth::session_cookie::clear_session_cookie()) {
        Ok(value) => value,
        Err(err) => {
            error!("Failed to serialize session cookie header: {}", err);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut response_headers = HeaderMap::new();
    response_headers.insert(SET_COOKIE, session_cookie);

    (response_headers, StatusCode::OK).into_response()
}

#[cfg(test)]
mod tests {
    use super::{LoginStartRequest, RegisterStartRequest, login_start, register_start};
    use crate::auth::{
        AuthState,
        storage::UserData,
        types::{UserRole, UserStatus},
    };
    use axum::{Json, extract::State};
    use std::sync::Arc;
    use tempfile::{TempDir, tempdir};

    async fn test_auth_state() -> (TempDir, Arc<AuthState>) {
        let temp_dir = tempdir().unwrap();
        let state = AuthState::new(
            "example.com".to_string(),
            url::Url::parse("https://example.com").unwrap(),
            temp_dir
                .path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            temp_dir
                .path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
            30,
            temp_dir
                .path()
                .join("sessions")
                .to_string_lossy()
                .into_owned(),
            std::sync::Arc::new(crate::terms::TermsManager::disabled()),
        )
        .await
        .unwrap();

        (temp_dir, Arc::new(state))
    }

    async fn save_user(
        state: &AuthState,
        username: &str,
        status: UserStatus,
    ) {
        let now = chrono::Utc::now();
        state
            .storage
            .save_user(&UserData {
                user_id: uuid::Uuid::new_v4().to_string(),
                username: username.to_string(),
                passkeys: Vec::new(),
                role: UserRole::User,
                status,
                is_primary: false,
                first_name: None,
                last_name: None,
                email: None,
                department: None,
                job_title: None,
                avatar_path: None,
                created_at: now,
                updated_at: now,
                last_logged_in: None,
                saml_id: None,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn auth_checks_preserve_allowed_sessions_during_terms_outage() {
        let (directory, mut state) = test_auth_state().await;
        let path = directory.path().join("terms");
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("acceptances"), b"not a directory").unwrap();
        let manager = Arc::new(
            crate::terms::TermsManager::open(true, "appliance".into(), path, None)
                .await
                .unwrap(),
        );
        Arc::get_mut(&mut state)
            .unwrap()
            .terms_manager = manager.clone();
        for gate in [
            crate::auth::session::TermsSessionGate::AllowedAtLogin,
            crate::auth::session::TermsSessionGate::LegacyAllowed,
            crate::auth::session::TermsSessionGate::ConsentPending,
        ] {
            let token = state
                .session_manager
                .create_session_with_terms_gate("alice".into(), "user-1".into(), gate)
                .await;
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}")
                    .parse()
                    .unwrap(),
            );
            let passkey = super::check_auth(State(state.clone()), headers.clone()).await;
            let saml = crate::auth::saml::handlers::saml_check_auth(
                headers,
                axum::Extension(state.session_manager.clone()),
                axum::Extension(manager.clone()),
            )
            .await;
            if gate == crate::auth::session::TermsSessionGate::ConsentPending {
                assert!(matches!(passkey, Err(crate::terms::TermsError::Operational(_))));
                assert_eq!(saml.unwrap_err().status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
            } else {
                let Json(passkey) = passkey.unwrap();
                assert!(passkey.authenticated);
                assert!(!passkey.consent_required);
                let Json(saml) = saml.unwrap();
                assert_eq!(saml["authenticated"], true);
                assert_eq!(saml["consent_required"], false);
            }
        }
    }

    #[tokio::test]
    async fn unavailable_users_receive_login_challenges() {
        let (_temp_dir, state) = test_auth_state().await;
        save_user(&state, "pending-user", UserStatus::New).await;
        save_user(&state, "passkeyless-user", UserStatus::Approved).await;

        for username in ["missing-user", "pending-user", "passkeyless-user"] {
            let Json(response) =
                login_start(State(state.clone()), Json(LoginStartRequest { username: username.to_string() }))
                    .await
                    .unwrap();

            assert!(
                response
                    .request_options
                    .public_key
                    .allow_credentials
                    .is_empty()
            );
            assert!(
                state
                    .challenges
                    .read()
                    .await
                    .get(&response.challenge_id)
                    .is_some_and(|challenge| challenge
                        .authentication_state
                        .is_some())
            );
        }
    }

    #[tokio::test]
    async fn existing_username_receives_unfinishable_registration_challenge() {
        let (_temp_dir, state) = test_auth_state().await;
        save_user(&state, "existing-user", UserStatus::Approved).await;

        let Json(response) = register_start(
            State(state.clone()),
            Json(RegisterStartRequest {
                username: "existing-user".to_string(),
            }),
        )
        .await
        .unwrap();

        assert!(
            state
                .challenges
                .read()
                .await
                .get(&response.challenge_id)
                .is_some_and(|challenge| challenge
                    .registration_state
                    .is_none())
        );
    }

    #[tokio::test]
    async fn new_username_receives_finishable_registration_challenge() {
        let (_temp_dir, state) = test_auth_state().await;

        let Json(response) = register_start(
            State(state.clone()),
            Json(RegisterStartRequest {
                username: "new-user".to_string(),
            }),
        )
        .await
        .unwrap();

        assert!(
            state
                .challenges
                .read()
                .await
                .get(&response.challenge_id)
                .is_some_and(|challenge| challenge
                    .registration_state
                    .is_some())
        );
    }
}
