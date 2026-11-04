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
use tracing::{error, info, warn};
use webauthn_rs::prelude::*;

use super::state::{AuthState, ChallengeState};
use super::storage::UserData;
use crate::auth::session_finalizer::{
    AuthenticatedPrincipal, SessionFinalizationError, SessionFinalizer, SessionManagerFinalizer,
};
use crate::config::types::SecretValue;

use crate::metrics::MetricsStore;

/// Request to start passkey registration
#[derive(Debug, Deserialize)]
pub struct RegisterStartRequest {
    pub username: String,
    /// Required while no user exists.
    #[serde(default)]
    pub setup_token: Option<SecretValue>,
}

/// The one answer to a first registration without the valid setup token, missing or wrong.
pub(crate) const SETUP_TOKEN_REQUIRED: &str = "A valid setup token is required to register the first administrator";

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
    /// Required while no user exists.
    #[serde(default)]
    pub setup_token: Option<SecretValue>,
}

pub(crate) enum RegisterFinishError {
    Status(StatusCode),
    Terms(crate::terms::TermsError),
    SetupTokenRequired,
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
            Self::SetupTokenRequired => (StatusCode::FORBIDDEN, SETUP_TOKEN_REQUIRED).into_response(),
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
#[derive(Serialize)]
pub struct LoginFinishResponse {
    pub session_token: String,
    pub consent_required: bool,
}

impl std::fmt::Debug for LoginFinishResponse {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("LoginFinishResponse")
            .field("session_token", &crate::observability::loggable::secret(&self.session_token))
            .field("consent_required", &self.consent_required)
            .finish()
    }
}

/// Response for auth check
#[derive(Debug, Serialize)]
pub struct AuthCheckResponse {
    pub authenticated: bool,
    pub username: Option<String>,
    pub consent_required: bool,
}

/// Start passkey registration. While no user exists, only a request with the setup token gets a
/// challenge.
pub async fn register_start(
    State(auth_state): State<Arc<AuthState>>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, (StatusCode, String)> {
    let users = auth_state
        .storage
        .list_users()
        .await
        .map_err(|e| {
            error!("Failed to list users before starting a registration: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start registration".to_string())
        })?;

    if users.is_empty()
        && !auth_state
            .setup_token
            .matches(req.setup_token.as_deref())
    {
        warn!("Refused to start registering the first administrator without a valid setup token");
        return Err((StatusCode::FORBIDDEN, SETUP_TOKEN_REQUIRED.to_string()));
    }

    // Enforce the appliance user limit before starting a new registration.
    if let Err(e) = crate::config::global_limits().check_can_add("users", users.len()) {
        crate::config::log_limit_reached("users", &e);
        return Err((StatusCode::FORBIDDEN, e.message()));
    }

    let existing_user = auth_state
        .storage
        .load_user(&req.username)
        .await
        .map_err(|e| {
            error!("Failed to check whether user exists: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start registration".to_string())
        })?;

    if let Some(existing_user) = &existing_user {
        error!("Registration requested for the username of existing user_id: {}", existing_user.user_id);
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
        registration_state: existing_user
            .is_none()
            .then_some(reg_state),
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

    let user =
        persist_registration(&auth_state, username.as_str(), vec![passkey], terms_request, req.setup_token.as_deref())
            .await?;

    info!("Successfully registered passkey for user_id: {}", user.user_id);

    info!("User registration complete - role: {:?}, status: {:?}, user_id: {}", user.role, user.status, user.user_id);

    crate::integrations::trigger_user_created(&user);
    let notif_store_guard = auth_state
        .notification_store
        .read()
        .await;
    if notif_store_guard.is_some()
        && let Some(metrics_store) = metrics_store
    {
        let user_role = user.role.clone();
        tokio::spawn(async move {
            metrics_store
                .record_user_event("created", user_role.to_string().as_str())
                .await;
        });
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

/// Stores a verified registration. The first user becomes the Primary Administrator only with the
/// setup token, checked again under the user write guard, only while the user directory on disk
/// holds no user, which another gateway sharing it may have stored, and only after this gateway
/// claimed the token file, so a token is used once even by gateways sharing storage.
pub(crate) async fn persist_registration(
    auth_state: &AuthState,
    username: &str,
    passkeys: Vec<Passkey>,
    terms_request: crate::terms::AcceptTermsRequest,
    setup_token: Option<&str>,
) -> Result<UserData, RegisterFinishError> {
    let _user_write_guard = auth_state
        .storage
        .user_write_guard()
        .await;
    let user = auth_state
        .storage
        .prepare_user_with_passkeys(username, passkeys)
        .await
        .map_err(|e| {
            error!("Failed to prepare passkey user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    if user.is_primary
        && !auth_state
            .setup_token
            .matches(setup_token)
    {
        warn!("Refused to register the first administrator without a valid setup token");
        return Err(RegisterFinishError::SetupTokenRequired);
    }
    if user.is_primary {
        match auth_state
            .storage
            .has_user_records_on_disk()
            .await
        {
            Ok(false) => {}
            Ok(true) => {
                warn!("Refused to register the first administrator: the user directory already holds a user");
                return Err(RegisterFinishError::SetupTokenRequired);
            }
            Err(e) => {
                error!("Failed to check the user directory before registering the first administrator: {:#}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
            }
        }
    }

    auth_state
        .terms_manager
        .accept(&user.user_id, crate::terms::AcceptanceContext::Registration, terms_request)
        .await?;
    if user.is_primary {
        match auth_state
            .setup_token
            .claim()
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                warn!(
                    "Refused to register the first administrator: the setup token file was missing or held another \
                     token, because it was used already or another gateway is claiming it"
                );
                return Err(RegisterFinishError::SetupTokenRequired);
            }
            Err(e) => {
                error!("Failed to use the setup token: {:#}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
            }
        }
    }
    auth_state
        .storage
        .save_user(&user)
        .await
        .map_err(|e| {
            if user.is_primary {
                error!(user_id = %user.user_id, error = %e, "Failed to store the first administrator after using the setup token; restart the gateway to generate a new setup token");
            } else {
                error!(user_id = %user.user_id, error = %e, "Failed to store passkey user; any recorded Terms acceptance is retained");
            }
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    if user.is_primary {
        info!("First user_id '{}' registered as Primary Administrator (cannot be deleted or demoted)", user.user_id);
    } else {
        info!("New user_id '{}' registered with status 'new' - requires approval", user.user_id);
    }
    Ok(user)
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
        error!("Sign-in requested for a user that is not approved");
        Vec::new()
    } else if passkeys.is_empty() {
        error!("Sign-in requested for a user without passkeys");
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
            error!("User not found after authentication");
            StatusCode::UNAUTHORIZED
        })?;

    // Update last_logged_in timestamp
    user.last_logged_in = Some(chrono::Utc::now());
    if let Err(e) = auth_state
        .storage
        .save_user(&user)
        .await
    {
        error!("Failed to update last_logged_in for user_id {}: {}", user.user_id, e);
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

    crate::integrations::trigger_user_login(&user);
    let notif_store_guard = auth_state
        .notification_store
        .read()
        .await;
    if notif_store_guard.is_some()
        && let Some(metrics_store) = metrics_store
    {
        let user_role = user.role.clone();
        tokio::spawn(async move {
            metrics_store
                .record_user_login(user_role.to_string().as_str())
                .await;
        });
    }
    drop(notif_store_guard);

    info!("Successfully authenticated user_id: {}", user.user_id);

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
        info!("Authentication successful for user_id: {}", session.user_id);
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
    use super::{
        LoginFinishResponse, LoginStartRequest, RegisterFinishRequest, RegisterStartRequest, RegisterStartResponse,
        SETUP_TOKEN_REQUIRED, login_start, persist_registration, register_start,
    };
    use crate::auth::{
        AuthState,
        storage::UserData,
        types::{UserRole, UserStatus},
    };
    use crate::config::types::SecretValue;
    use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
    use std::sync::Arc;
    use tempfile::{TempDir, tempdir};

    const SETUP_TOKEN: &str = "handlers-test-setup-token-0123456789-abcdefghijk";

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
            Some(SecretValue::from(SETUP_TOKEN)),
        )
        .await
        .unwrap();

        (temp_dir, Arc::new(state))
    }

    fn setup_token_file(directory: &TempDir) -> std::path::PathBuf {
        directory
            .path()
            .join("users")
            .join("setup-token")
    }

    async fn start(
        state: &Arc<AuthState>,
        username: &str,
        setup_token: Option<&str>,
    ) -> Result<RegisterStartResponse, (StatusCode, String)> {
        register_start(
            State(state.clone()),
            Json(RegisterStartRequest {
                username: username.to_string(),
                setup_token: setup_token.map(SecretValue::from),
            }),
        )
        .await
        .map(|Json(response)| response)
    }

    async fn register(
        state: &AuthState,
        username: &str,
        setup_token: Option<&str>,
    ) -> Result<UserData, (StatusCode, String)> {
        let terms = crate::terms::AcceptTermsRequest { accepted_terms: Vec::new() };
        match persist_registration(state, username, Vec::new(), terms, setup_token).await {
            Ok(user) => Ok(user),
            Err(error) => {
                let response = error.into_response();
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap();
                Err((status, String::from_utf8(body.to_vec()).unwrap()))
            }
        }
    }

    async fn stored_users(state: &AuthState) -> Vec<UserData> {
        let mut users = Vec::new();
        for user_id in state
            .storage
            .list_users()
            .await
            .unwrap()
        {
            users.push(
                state
                    .storage
                    .load_user_by_id(&user_id)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        users
    }

    fn setup_token_refusal() -> (StatusCode, String) {
        (StatusCode::FORBIDDEN, SETUP_TOKEN_REQUIRED.to_string())
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
                setup_token: None,
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
                setup_token: Some(SecretValue::from(SETUP_TOKEN)),
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

    #[tokio::test]
    async fn register_start_without_a_setup_token_is_refused_while_no_user_exists() {
        let (_temp_dir, state) = test_auth_state().await;

        let refusal = start(&state, "first-admin", None)
            .await
            .unwrap_err();

        assert_eq!(refusal, setup_token_refusal());
        assert!(
            state
                .challenges
                .read()
                .await
                .is_empty(),
            "no challenge may be created without the setup token"
        );
    }

    #[tokio::test]
    async fn register_start_with_a_wrong_setup_token_gets_the_same_refusal() {
        let (_temp_dir, state) = test_auth_state().await;
        let wrong_same_length = SETUP_TOKEN.replace('h', "H");

        for wrong in [wrong_same_length.as_str(), &SETUP_TOKEN[1..], ""] {
            let refusal = start(&state, "first-admin", Some(wrong))
                .await
                .unwrap_err();
            assert_eq!(refusal, setup_token_refusal(), "{wrong:?}");
        }
        assert!(
            state
                .challenges
                .read()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn register_start_needs_no_setup_token_once_a_user_exists() {
        let (_temp_dir, state) = test_auth_state().await;
        save_user(&state, "existing-user", UserStatus::Approved).await;

        let response = start(&state, "second-user", None)
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

    #[tokio::test]
    async fn the_first_registration_with_the_setup_token_becomes_the_primary_administrator() {
        let (directory, state) = test_auth_state().await;

        let user = register(&state, "first-admin", Some(SETUP_TOKEN))
            .await
            .unwrap();

        assert_eq!(user.role, UserRole::Administrator);
        assert_eq!(user.status, UserStatus::Approved);
        assert!(user.is_primary);
        assert_eq!(
            stored_users(&state)
                .await
                .len(),
            1
        );
        assert!(!setup_token_file(&directory).exists(), "the token file is removed");
        assert!(
            !state
                .setup_required()
                .await
                .unwrap()
        );
        assert!(
            !state
                .setup_token
                .matches(Some(SETUP_TOKEN))
        );
    }

    #[tokio::test]
    async fn the_first_registration_without_a_setup_token_is_refused_and_saves_no_user() {
        let (directory, state) = test_auth_state().await;

        let refusal = register(&state, "first-admin", None)
            .await
            .unwrap_err();

        assert_eq!(refusal, setup_token_refusal());
        assert!(
            stored_users(&state)
                .await
                .is_empty()
        );
        assert!(setup_token_file(&directory).exists());
    }

    #[tokio::test]
    async fn the_first_registration_with_a_wrong_setup_token_is_refused_and_keeps_the_token() {
        let (directory, state) = test_auth_state().await;

        let refusal = register(&state, "first-admin", Some(&SETUP_TOKEN.replace('h', "H")))
            .await
            .unwrap_err();

        assert_eq!(refusal, setup_token_refusal());
        assert!(
            stored_users(&state)
                .await
                .is_empty()
        );
        assert!(setup_token_file(&directory).exists());
        assert!(
            state
                .setup_token
                .matches(Some(SETUP_TOKEN))
        );
    }

    #[tokio::test]
    async fn a_registration_after_setup_needs_no_setup_token_and_lands_as_new() {
        let (_temp_dir, state) = test_auth_state().await;
        register(&state, "first-admin", Some(SETUP_TOKEN))
            .await
            .unwrap();

        let second = register(&state, "second-user", None)
            .await
            .unwrap();

        assert_eq!(second.role, UserRole::User);
        assert_eq!(second.status, UserStatus::New);
        assert!(!second.is_primary);
    }

    #[tokio::test]
    async fn the_setup_token_works_only_once() {
        let (_temp_dir, state) = test_auth_state().await;
        register(&state, "first-admin", Some(SETUP_TOKEN))
            .await
            .unwrap();
        state
            .storage
            .delete_user("first-admin")
            .await
            .unwrap();

        let start_again = start(&state, "second-admin", Some(SETUP_TOKEN))
            .await
            .unwrap_err();
        let register_again = register(&state, "second-admin", Some(SETUP_TOKEN))
            .await
            .unwrap_err();

        assert_eq!(start_again, setup_token_refusal());
        assert_eq!(register_again, setup_token_refusal());
        assert!(
            stored_users(&state)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_first_registration_is_refused_when_another_gateway_already_stored_a_user() {
        let (directory, state) = test_auth_state().await;
        let other_gateway = crate::auth::storage::PasskeyStorage::new(
            directory
                .path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            directory
                .path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        let now = chrono::Utc::now();
        other_gateway
            .save_user(&UserData {
                user_id: uuid::Uuid::new_v4().to_string(),
                username: "other-admin".to_string(),
                passkeys: Vec::new(),
                role: UserRole::Administrator,
                status: UserStatus::Approved,
                is_primary: true,
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

        let refusal = register(&state, "first-admin", Some(SETUP_TOKEN))
            .await
            .unwrap_err();

        assert_eq!(refusal, setup_token_refusal());
        assert!(
            stored_users(&state)
                .await
                .is_empty(),
            "this gateway's cache never saw the other gateway's user"
        );
        let user_records = std::fs::read_dir(directory.path().join("users"))
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".json")
            })
            .count();
        assert_eq!(user_records, 1, "no second user is stored");
        assert!(setup_token_file(&directory).exists(), "the refusal does not use the token up");
        assert!(state.setup_token.is_pending());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_first_registrations_with_one_token_create_one_primary_administrator() {
        let (_temp_dir, state) = test_auth_state().await;

        let registrations = ["first-admin", "second-admin"].map(|username| {
            let state = state.clone();
            tokio::spawn(async move { register(&state, username, Some(SETUP_TOKEN)).await })
        });
        for registration in registrations {
            registration
                .await
                .unwrap()
                .unwrap();
        }

        let users = stored_users(&state).await;
        assert_eq!(users.len(), 2);
        assert_eq!(
            users
                .iter()
                .filter(|user| user.is_primary && user.role == UserRole::Administrator)
                .count(),
            1
        );
        assert_eq!(
            users
                .iter()
                .filter(|user| !user.is_primary && user.status == UserStatus::New)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn a_first_registration_whose_claim_was_taken_elsewhere_is_refused() {
        let (directory, state) = test_auth_state().await;
        std::fs::remove_file(setup_token_file(&directory)).unwrap();

        let refusal = register(&state, "first-admin", Some(SETUP_TOKEN))
            .await
            .unwrap_err();

        assert_eq!(refusal, setup_token_refusal());
        assert!(
            stored_users(&state)
                .await
                .is_empty()
        );
        assert!(state.setup_token.is_pending(), "a claim that finds no token file keeps the token");
    }

    #[test]
    fn register_requests_redact_the_setup_token_in_debug_output() {
        let start: RegisterStartRequest =
            serde_json::from_value(serde_json::json!({"username": "first-admin", "setup_token": SETUP_TOKEN})).unwrap();
        let finish: RegisterFinishRequest = serde_json::from_value(serde_json::json!({
            "challenge_id": "challenge",
            "credential": {
                "id": "AAAA",
                "rawId": "AAAA",
                "response": {"attestationObject": "AAAA", "clientDataJSON": "AAAA"},
                "type": "public-key",
                "extensions": {}
            },
            "setup_token": SETUP_TOKEN
        }))
        .unwrap();

        let rendered = format!("{start:?} {finish:?}");

        assert_eq!(start.setup_token.as_deref(), Some(SETUP_TOKEN));
        assert_eq!(finish.setup_token.as_deref(), Some(SETUP_TOKEN));
        assert!(!rendered.contains(SETUP_TOKEN), "{rendered}");
    }

    #[test]
    fn login_finish_response_debug_shows_only_a_token_prefix() {
        let token = "0f2c9d7e-1b3a-4c5d-8e9f-a0b1c2d3e4f5";
        let rendered = format!(
            "{:?}",
            LoginFinishResponse {
                session_token: token.to_string(),
                consent_required: false,
            }
        );

        assert!(rendered.contains(r#"session_token: "0f2c9d7e...""#), "{rendered}");
        assert!(!rendered.contains(token), "{rendered}");
    }
}
