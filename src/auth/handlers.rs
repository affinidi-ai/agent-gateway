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

/// Start passkey registration
pub async fn register_start(
    State(auth_state): State<Arc<AuthState>>,
    Json(req): Json<RegisterStartRequest>,
) -> Result<Json<RegisterStartResponse>, (StatusCode, String)> {
    let existing_user = auth_state
        .storage
        .load_user(&req.username)
        .await
        .map_err(|e| {
            error!("Failed to check whether user exists: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to start registration".to_string())
        })?;

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

    if let Some(existing_user) = &existing_user {
        warn!("Registration requested for the username of existing user_id: {}", existing_user.user_id);
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

    let challenge_id = auth_state
        .store_challenge(ChallengeState {
            registration_state: Some(reg_state),
            authentication_state: None,
            username: req.username.clone(),
            created_at: chrono::Utc::now(),
        })
        .await;

    Ok(Json(RegisterStartResponse {
        challenge_id,
        creation_options: ccr,
    }))
}

/// How long after the username check a finished registration is answered, whether it created an
/// account or found the username taken.
///
/// A taken username stores nothing, while a new account is answered only after its user record
/// and its Terms acceptance are written: about 1.3 ms more on a local SSD, and more on slower
/// volumes. If each answered as soon as its work was done, the faster answer would tell that the
/// username is taken. Both instead wait until this long after the check, which covers those
/// writes on all but very slow storage, so neither answers sooner than the other. The other work
/// a new account starts, such as notifying administrators, runs after the answer.
const REGISTRATION_ANSWER_TIME: std::time::Duration = std::time::Duration::from_millis(25);

/// Complete passkey registration
pub async fn register_finish(
    Extension(metrics_store): Extension<Option<Arc<MetricsStore>>>,
    State(auth_state): State<Arc<AuthState>>,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<StatusCode, RegisterFinishError> {
    info!("Completing passkey registration for challenge: {}", req.challenge_id);

    let challenge_state = auth_state
        .take_challenge(&req.challenge_id)
        .await
        .ok_or_else(|| {
            error!("Challenge not found or expired: {}", req.challenge_id);
            StatusCode::BAD_REQUEST
        })?;

    let reg_state = challenge_state
        .registration_state
        .ok_or(StatusCode::BAD_REQUEST)?;

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
    let answer_at = tokio::time::Instant::now() + REGISTRATION_ANSWER_TIME;
    // The user limit is checked before the username, so a full appliance refuses a taken
    // username and a free one alike.
    let user_count = auth_state
        .storage
        .list_users()
        .await
        .map_err(|e| {
            error!("Failed to count users: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .len();
    if user_count > 0
        && let Err(e) = crate::config::global_limits().check_can_add("users", user_count)
    {
        drop(user_write_guard);
        crate::config::log_limit_reached("users", &e);
        return Err(StatusCode::FORBIDDEN.into());
    }
    // A username that already has an account, approved or awaiting approval, is answered as a
    // new registration awaiting approval and nothing is stored, so the answer does not tell
    // whether the account exists.
    if let Some(existing_user) = auth_state
        .storage
        .load_user(&username)
        .await
        .map_err(|e| {
            error!("Failed to check whether user exists: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    {
        drop(user_write_guard);
        warn!(
            user_id = %existing_user.user_id,
            "Registration finished for the username of an existing account; nothing stored"
        );
        tokio::time::sleep_until(answer_at).await;
        return Ok(StatusCode::OK);
    }
    let user = auth_state
        .storage
        .prepare_user_with_passkey(username.as_str(), passkey, user_count == 0);

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
        info!("First user_id '{}' registered as Primary Administrator (cannot be deleted or demoted)", user.user_id);
    } else {
        info!("New user_id '{}' registered with status 'new' - requires approval", user.user_id);
    }
    drop(user_write_guard);

    info!("Successfully registered passkey for user_id: {}", user.user_id);

    info!("User registration complete - role: {:?}, status: {:?}, user_id: {}", user.role, user.status, user.user_id);

    crate::integrations::trigger_user_created(&user);
    tokio::spawn(announce_new_user(auth_state, metrics_store, user));
    tokio::time::sleep_until(answer_at).await;

    Ok(StatusCode::OK)
}

/// Records the new user in the metrics and notifies: the first user, an administrator, gets the
/// welcome, and a user awaiting approval is announced to every administrator.
async fn announce_new_user(
    auth_state: Arc<AuthState>,
    metrics_store: Option<Arc<MetricsStore>>,
    user: crate::auth::storage::UserData,
) {
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
                                user.username
                            ),
                            serde_json::json!({"username": user.username, "user_id": user.user_id, "action": crate::integrations::types::NotificationAction::UserApproval}),
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
}

/// Start passkey authentication
pub async fn login_start(
    State(auth_state): State<Arc<AuthState>>,
    Json(req): Json<LoginStartRequest>,
) -> Result<Json<LoginStartResponse>, StatusCode> {
    let user = auth_state
        .storage
        .load_user(&req.username)
        .await
        .map_err(|e| {
            error!("Failed to load the user signing in: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let is_approved = user
        .as_ref()
        .is_some_and(|user| user.status == crate::auth::UserStatus::Approved);
    let passkeys = user
        .map(|user| user.passkeys)
        .unwrap_or_default();

    let passkeys = if !is_approved {
        error!("Sign-in requested for a user that is not approved");
        Vec::new()
    } else if passkeys.is_empty() {
        error!("Sign-in requested for a user without passkeys");
        Vec::new()
    } else {
        passkeys
    };

    let (mut rcr, auth_state_data) = auth_state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| {
            error!("Failed to start passkey authentication: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    // A username with no passkey to sign in with is named decoy credentials, so the challenge
    // looks like one for an account; the challenge state holds no credential they could match.
    if passkeys.is_empty() {
        rcr.public_key
            .allow_credentials = auth_state
            .decoy_credentials
            .credentials_for(&req.username);
    }

    let challenge_id = auth_state
        .store_challenge(ChallengeState {
            registration_state: None,
            authentication_state: Some(auth_state_data),
            username: req.username.clone(),
            created_at: chrono::Utc::now(),
        })
        .await;

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

    let challenge_state = auth_state
        .take_challenge(&req.challenge_id)
        .await
        .ok_or_else(|| {
            error!("Challenge not found or expired: {}", req.challenge_id);
            StatusCode::BAD_REQUEST
        })?;

    let auth_state_data = challenge_state
        .authentication_state
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Get username from challenge state
    let username = challenge_state
        .username
        .clone();

    // Verify the credential
    if let Err(e) = auth_state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state_data)
    {
        error!("Failed to finish passkey authentication: {}", e);
        raise_failed_passkey_sign_in(&auth_state.storage, &username).await;
        return Err(StatusCode::UNAUTHORIZED.into());
    }

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
            crate::integrations::trigger_user_login_failed(
                crate::integrations::LoginMethod::Passkey,
                crate::integrations::LoginFailure::UnknownUser,
            );
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

    crate::integrations::trigger_user_login(&user, crate::integrations::LoginMethod::Passkey);
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

/// Raises `user.login_failed` for a passkey sign-in whose credential did not verify, classified by
/// the account its challenge named. The event carries that account as stored, never the username
/// the caller typed, and the caller's answer is the same whichever way it is classified.
async fn raise_failed_passkey_sign_in(
    storage: &super::storage::PasskeyStorage,
    username: &str,
) {
    match storage
        .load_user(username)
        .await
    {
        Ok(account) => crate::integrations::trigger_user_login_failed(
            crate::integrations::LoginMethod::Passkey,
            crate::integrations::LoginFailure::of_passkey_account(account.as_ref()),
        ),
        Err(e) => error!("Failed to look up the account of a failed passkey sign-in; no event raised: {}", e),
    }
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
        LoginFinishRequest, LoginFinishResponse, LoginStartRequest, RegisterStartRequest, login_finish, login_start,
        register_start,
    };
    use crate::auth::{
        AuthState,
        state::MAX_PENDING_CHALLENGES,
        storage::UserData,
        types::{UserRole, UserStatus},
    };
    use crate::integrations::delivery::dispatch::dispatched;
    use axum::{Json, extract::State, response::IntoResponse};
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
            crate::auth::decoy_credential::DecoyCredentialKey::generate().unwrap(),
        )
        .await
        .unwrap();

        (temp_dir, Arc::new(state))
    }

    async fn save_user(
        state: &AuthState,
        username: &str,
        status: UserStatus,
    ) -> String {
        let now = chrono::Utc::now();
        let user_id = uuid::Uuid::new_v4().to_string();
        state
            .storage
            .save_user(&UserData {
                user_id: user_id.clone(),
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
        user_id
    }

    async fn add_passkey(
        state: &AuthState,
        user_id: &str,
    ) {
        let passkey: webauthn_rs::prelude::Passkey = serde_json::from_value(serde_json::json!({
            "cred": {
                "cred_id": "AAECAwQFBgcICQoLDA0ODw",
                "cred": {
                    "type_": "ES256",
                    "key": {"EC_EC2": {
                        "curve": "SECP256R1",
                        "x": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                        "y": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
                    }}
                },
                "counter": 0,
                "transports": null,
                "user_verified": true,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {},
                "attestation": {"data": "None", "metadata": "None"},
                "attestation_format": "none"
            }
        }))
        .expect("a stored passkey");
        let mut user = state
            .storage
            .load_user_by_id(user_id)
            .await
            .unwrap()
            .unwrap();
        user.passkeys.push(passkey);
        state
            .storage
            .save_user(&user)
            .await
            .unwrap();
    }

    /// A well-formed assertion signed by no passkey the gateway holds.
    fn unheld_passkey_assertion(challenge_id: String) -> LoginFinishRequest {
        serde_json::from_value(serde_json::json!({
            "challenge_id": challenge_id,
            "credential": {
                "id": "AAECAwQFBgcICQoLDA0ODw",
                "rawId": "AAECAwQFBgcICQoLDA0ODw",
                "type": "public-key",
                "response": {
                    "authenticatorData": "AAAA",
                    "clientDataJSON": "AAAA",
                    "signature": "AAAA",
                    "userHandle": null
                },
                "extensions": {}
            }
        }))
        .expect("a well-formed assertion")
    }

    /// Starts a passkey sign-in for `username` and finishes it with a passkey the gateway does
    /// not hold, returning the status the caller gets.
    async fn fail_passkey_sign_in(
        state: &Arc<AuthState>,
        username: &str,
    ) -> axum::http::StatusCode {
        let Json(started) =
            login_start(State(state.clone()), Json(LoginStartRequest { username: username.to_string() }))
                .await
                .unwrap();
        login_finish(axum::Extension(None), State(state.clone()), Json(unheld_passkey_assertion(started.challenge_id)))
            .await
            .map(|response| {
                response
                    .into_response()
                    .status()
            })
            .unwrap_or_else(|error| error.into_response().status())
    }

    #[tokio::test]
    async fn a_failed_passkey_sign_in_raises_login_failed_naming_the_stored_account_and_its_reason() {
        let (_temp_dir, state) = test_auth_state().await;
        let approved = save_user(&state, "approved-user", UserStatus::Approved).await;
        let pending = save_user(&state, "pending-user", UserStatus::New).await;

        for (username, user_id, reason) in
            [("approved-user", &approved, "invalid_credential"), ("pending-user", &pending, "not_approved")]
        {
            let status = fail_passkey_sign_in(&state, username).await;

            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "passkey sign-in should be unauthorized");
            let raised = dispatched::values_of("user.login_failed", "USER_ID", user_id);
            assert_eq!(raised.len(), 1, "{raised:?}");
            assert_eq!(raised[0]["FAILURE_REASON"], reason);
            assert_eq!(raised[0]["LOGIN_METHOD"], "passkey");
            assert_eq!(raised[0]["USERNAME"], username);
        }
    }

    #[tokio::test]
    async fn a_failed_passkey_sign_in_for_an_unknown_account_raises_login_failed_naming_no_user() {
        let (_temp_dir, state) = test_auth_state().await;
        let username = format!("unknown-{}", uuid::Uuid::new_v4());

        let status = fail_passkey_sign_in(&state, &username).await;

        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
        let raised = dispatched::values_of("user.login_failed", "FAILURE_REASON", "unknown_user");
        assert!(!raised.is_empty());
        for values in raised {
            assert!(!values.contains_key("USER_ID"), "{values:?}");
            assert!(!values.contains_key("USERNAME"), "{values:?}");
            assert!(
                !values
                    .values()
                    .any(|value| value.contains(&username)),
                "{values:?}"
            );
        }
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
    async fn login_challenges_name_stable_decoys_whether_or_not_the_user_exists() {
        let (_temp_dir, state) = test_auth_state().await;
        save_user(&state, "pending-user", UserStatus::New).await;
        save_user(&state, "passkeyless-user", UserStatus::Approved).await;

        for username in ["missing-user", "pending-user", "passkeyless-user"] {
            let first = named_credentials(&state, username).await;
            let again = named_credentials(&state, username).await;

            assert_eq!(first, again, "{username}");
            assert_eq!(
                serde_json::Value::Array(first),
                serde_json::to_value(
                    state
                        .decoy_credentials
                        .credentials_for(username)
                )
                .unwrap(),
                "{username}"
            );
        }
        assert_ne!(named_credentials(&state, "missing-user").await, named_credentials(&state, "pending-user").await);
    }

    #[tokio::test]
    async fn a_login_challenge_names_the_passkeys_of_an_approved_user() {
        let (_temp_dir, state) = test_auth_state().await;
        let user_id = save_user(&state, "passkey-user", UserStatus::Approved).await;
        add_passkey(&state, &user_id).await;

        let named = named_credentials(&state, "passkey-user").await;

        assert_eq!(named.len(), 1, "{named:?}");
        assert_eq!(named[0]["id"], "AAECAwQFBgcICQoLDA0ODw");
    }

    /// The credentials a sign-in challenge for `username` names, as the browser receives them.
    async fn named_credentials(
        state: &Arc<AuthState>,
        username: &str,
    ) -> Vec<serde_json::Value> {
        let Json(response) =
            login_start(State(state.clone()), Json(LoginStartRequest { username: username.to_string() }))
                .await
                .unwrap();
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
        serde_json::to_value(&response.request_options).unwrap()["publicKey"]["allowCredentials"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    fn challenge_created(age: chrono::TimeDelta) -> crate::auth::state::ChallengeState {
        crate::auth::state::ChallengeState {
            registration_state: None,
            authentication_state: None,
            username: "alice".to_string(),
            created_at: chrono::Utc::now() - age,
        }
    }

    #[tokio::test]
    async fn a_challenge_is_taken_once_while_fresh_and_refused_once_expired() {
        let (_temp_dir, state) = test_auth_state().await;
        let fresh = state
            .store_challenge(challenge_created(chrono::TimeDelta::minutes(5)))
            .await;
        let expired = state
            .store_challenge(challenge_created(chrono::TimeDelta::minutes(7)))
            .await;

        assert!(
            state
                .take_challenge(&fresh)
                .await
                .is_some()
        );
        assert!(
            state
                .take_challenge(&fresh)
                .await
                .is_none()
        );
        assert!(
            state
                .take_challenge(&expired)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_full_challenge_store_drops_the_expired_challenges_first() {
        let (_temp_dir, state) = test_auth_state().await;
        let expired = state
            .store_challenge(challenge_created(chrono::TimeDelta::minutes(7)))
            .await;
        for _ in 1..MAX_PENDING_CHALLENGES {
            state
                .store_challenge(challenge_created(chrono::TimeDelta::minutes(1)))
                .await;
        }

        let newest = state
            .store_challenge(challenge_created(chrono::TimeDelta::zero()))
            .await;

        let stored = state.challenges.read().await;
        assert!(!stored.contains_key(&expired));
        assert!(stored.contains_key(&newest));
        assert_eq!(stored.len(), MAX_PENDING_CHALLENGES);
    }

    #[tokio::test]
    async fn a_full_challenge_store_of_fresh_challenges_drops_the_oldest() {
        let (_temp_dir, state) = test_auth_state().await;
        let oldest = state
            .store_challenge(challenge_created(chrono::TimeDelta::minutes(3)))
            .await;
        let older = state
            .store_challenge(challenge_created(chrono::TimeDelta::minutes(2)))
            .await;
        for _ in 2..MAX_PENDING_CHALLENGES {
            state
                .store_challenge(challenge_created(chrono::TimeDelta::minutes(1)))
                .await;
        }

        let newest = state
            .store_challenge(challenge_created(chrono::TimeDelta::zero()))
            .await;

        let stored = state.challenges.read().await;
        assert!(!stored.contains_key(&oldest));
        assert!(stored.contains_key(&older));
        assert!(stored.contains_key(&newest));
        assert_eq!(stored.len(), MAX_PENDING_CHALLENGES);
    }

    #[tokio::test]
    async fn existing_username_receives_a_registration_challenge_like_a_new_one() {
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
                    .is_some())
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
