//! Test Authentication Module
//!
//! Provides a bypass authentication endpoint for automated UI testing.
//! This endpoint is ONLY available when AG_TEST_MODE=true is set.
//! NEVER enable this in production environments.

use async_trait::async_trait;
use axum::{extract::State, http::HeaderMap, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use super::{
    SessionManager,
    session_finalizer::{AuthenticatedPrincipal, SessionFinalizationError, SessionFinalizer, SessionManagerFinalizer},
    storage::{PasskeyStorage, UserData},
    types::{UserRole, UserStatus},
};

const MIN_TEST_TOKEN_LEN: usize = 32;
const LEGACY_DEFAULT_TEST_TOKEN: &str = "test-token-12345";
const FAILED_LOGIN_WINDOW: Duration = Duration::from_secs(60);
const MAX_FAILED_LOGINS_PER_WINDOW: usize = 20;

pub(crate) struct TestAuthState {
    pub(crate) config: TestAuthConfig,
    user_provisioner: Arc<dyn SyntheticUserProvisioner>,
    session_finalizer: Arc<dyn SessionFinalizer>,
    failed_login_attempts: Mutex<VecDeque<Instant>>,
}

impl TestAuthState {
    pub(crate) fn new(
        storage: Arc<PasskeyStorage>,
        session_manager: Arc<SessionManager>,
        terms_manager: Arc<crate::terms::TermsManager>,
        config: TestAuthConfig,
    ) -> Self {
        let user_provisioner: Arc<dyn SyntheticUserProvisioner> =
            Arc::new(StorageBackedSyntheticUserProvisioner::new(storage, config.clone()));
        let session_finalizer: Arc<dyn SessionFinalizer> =
            Arc::new(SessionManagerFinalizer::new(session_manager, terms_manager));

        Self {
            config,
            user_provisioner,
            session_finalizer,
            failed_login_attempts: Mutex::new(VecDeque::new()),
        }
    }

    fn reject_if_rate_limited(&self) -> Result<(), StatusCode> {
        let now = Instant::now();
        let mut attempts = self
            .failed_login_attempts
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        while attempts
            .front()
            .is_some_and(|attempt| now.duration_since(*attempt) > FAILED_LOGIN_WINDOW)
        {
            attempts.pop_front();
        }

        if attempts.len() >= MAX_FAILED_LOGINS_PER_WINDOW {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        Ok(())
    }

    fn record_failed_login(&self) -> Result<(), StatusCode> {
        let mut attempts = self
            .failed_login_attempts
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        attempts.push_back(Instant::now());
        Ok(())
    }

    fn clear_failed_logins(&self) -> Result<(), StatusCode> {
        let mut attempts = self
            .failed_login_attempts
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        attempts.clear();
        Ok(())
    }
}

/// Configuration for test authentication mode
#[derive(Debug, Clone)]
pub struct TestAuthConfig {
    /// Whether test mode is enabled (from AG_TEST_MODE env var)
    pub enabled: bool,
    /// Secret token required for test login (from AG_TEST_TOKEN env var).
    pub test_token: String,
    /// Whether request bodies may choose the synthetic user's role (from AG_TEST_ALLOW_ROLE_OVERRIDE).
    pub allow_role_override: bool,
    /// Default test user details
    pub test_username: String,
    pub test_user_id: String,
}

impl Default for TestAuthConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

impl TestAuthConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        let mut enabled = std::env::var("AG_TEST_MODE")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        if enabled {
            warn!("⚠️  TEST MODE ENABLED - Test authentication endpoint is active. Do NOT use in production!");
        }

        let test_token = std::env::var("AG_TEST_TOKEN").unwrap_or_default();
        if enabled && !is_strong_test_token(&test_token) {
            warn!(
                "⚠️  TEST MODE DISABLED - AG_TEST_TOKEN must be explicitly set to a non-default token with at least {} characters",
                MIN_TEST_TOKEN_LEN
            );
            enabled = false;
        }

        Self {
            enabled,
            test_token,
            allow_role_override: parse_env_bool("AG_TEST_ALLOW_ROLE_OVERRIDE"),
            test_username: std::env::var("AG_TEST_USERNAME").unwrap_or_else(|_| "test-user".to_string()),
            test_user_id: std::env::var("AG_TEST_USER_ID").unwrap_or_else(|_| "test-user-001".to_string()),
        }
    }
}

fn parse_env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false)
}

fn is_strong_test_token(token: &str) -> bool {
    token.len() >= MIN_TEST_TOKEN_LEN && token != LEGACY_DEFAULT_TEST_TOKEN
}

fn requested_role(
    requested: Option<UserRole>,
    config: &TestAuthConfig,
) -> Result<UserRole, StatusCode> {
    match requested {
        Some(role) if config.allow_role_override => Ok(role),
        Some(_) => Err(StatusCode::FORBIDDEN),
        None => Ok(UserRole::User),
    }
}

/// Request body for test login
#[derive(Debug, Deserialize)]
pub struct TestLoginRequest {
    /// Optional custom username for the test session
    #[serde(default)]
    pub username: Option<String>,
    /// Optional role for the synthetic test session.
    #[serde(default)]
    pub role: Option<UserRole>,
}

/// Response from successful test login
#[derive(Debug, Serialize)]
pub struct TestLoginResponse {
    /// Session token to use for authenticated requests
    pub session_token: String,
    /// Username associated with the session
    pub username: String,
    /// Session expiration in seconds
    pub expires_in_seconds: u64,
    /// Whether the authenticated user must accept Terms before product access.
    pub consent_required: bool,
}

/// Error response for test login
#[derive(Debug, Serialize)]
#[allow(unused)]
pub struct TestLoginError {
    pub error: String,
    pub message: String,
}

#[async_trait]
pub(crate) trait SyntheticUserProvisioner: Send + Sync {
    async fn ensure_user(
        &self,
        username: &str,
        role: UserRole,
    ) -> Result<UserData, StatusCode>;
}

struct StorageBackedSyntheticUserProvisioner {
    storage: Arc<PasskeyStorage>,
    config: TestAuthConfig,
}

impl StorageBackedSyntheticUserProvisioner {
    fn new(
        storage: Arc<PasskeyStorage>,
        config: TestAuthConfig,
    ) -> Self {
        Self { storage, config }
    }
}

#[async_trait]
impl SyntheticUserProvisioner for StorageBackedSyntheticUserProvisioner {
    async fn ensure_user(
        &self,
        username: &str,
        role: UserRole,
    ) -> Result<UserData, StatusCode> {
        ensure_test_user(self.storage.as_ref(), &self.config, username, role).await
    }
}

fn build_test_user_id(
    config: &TestAuthConfig,
    username: &str,
) -> String {
    if username == config.test_username {
        return config.test_user_id.clone();
    }

    let slug = username
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let slug = slug.trim_matches('-');

    if slug.is_empty() {
        format!("test-user-{}", uuid::Uuid::new_v4())
    } else {
        format!("test-user-{}", slug)
    }
}

fn build_test_user_email(username: &str) -> String {
    let local_part = username
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>()
        .trim_matches('.')
        .to_string();

    if local_part.is_empty() {
        "ui.test@example.test".to_string()
    } else {
        format!("{}@example.test", local_part)
    }
}

async fn ensure_test_user(
    storage: &PasskeyStorage,
    config: &TestAuthConfig,
    username: &str,
    role: UserRole,
) -> Result<UserData, StatusCode> {
    let mut user = match storage
        .load_user(username)
        .await
        .map_err(|error| {
            warn!("[TEST MODE] Failed to load test user '{}': {}", username, error);
            StatusCode::INTERNAL_SERVER_ERROR
        })? {
        Some(existing_user) => existing_user,
        None => {
            let mut user_id = build_test_user_id(config, username);

            if let Some(existing_user) = storage
                .load_user_by_id(&user_id)
                .await
                .map_err(|error| {
                    warn!("[TEST MODE] Failed to check test user id '{}' for '{}': {}", user_id, username, error);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
                && existing_user.username != username
            {
                user_id = format!("{}-{}", user_id, uuid::Uuid::new_v4());
            }

            let now = chrono::Utc::now();
            UserData {
                user_id,
                username: username.to_string(),
                passkeys: Vec::new(),
                role: UserRole::Administrator,
                status: UserStatus::Approved,
                is_primary: false,
                first_name: Some("UI".to_string()),
                last_name: Some("Test".to_string()),
                email: Some(build_test_user_email(username)),
                department: Some("QA".to_string()),
                job_title: Some("Automation".to_string()),
                avatar_path: Some("avatars/default.png".to_string()),
                created_at: now,
                updated_at: now,
                last_logged_in: Some(now),
                saml_id: None,
            }
        }
    };

    let now = chrono::Utc::now();
    user.role = role;
    user.status = UserStatus::Approved;
    user.updated_at = now;
    user.last_logged_in = Some(now);

    if user.first_name.is_none() {
        user.first_name = Some("UI".to_string());
    }
    if user.last_name.is_none() {
        user.last_name = Some("Test".to_string());
    }
    if user.email.is_none() {
        user.email = Some(build_test_user_email(username));
    }
    if user.department.is_none() {
        user.department = Some("QA".to_string());
    }
    if user.job_title.is_none() {
        user.job_title = Some("Automation".to_string());
    }
    if user.avatar_path.is_none() {
        user.avatar_path = Some("avatars/default.png".to_string());
    }

    storage
        .save_user(&user)
        .await
        .map_err(|error| {
            warn!("[TEST MODE] Failed to persist test user '{}': {}", username, error);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(user)
}

/// Test login endpoint - only available when AG_TEST_MODE=true
///
/// This endpoint allows automated tests to obtain a valid session without
/// going through the WebAuthn passkey flow. It requires a valid test token
/// in the X-Test-Token header.
///
/// # Security
/// - Returns 404 when test mode is not enabled
/// - Requires valid X-Test-Token header
/// - Requires AG_TEST_ALLOW_ROLE_OVERRIDE=true before accepting a role in the request body
/// - All test logins are logged with TEST MODE marker
pub async fn test_login(
    State(test_auth_state): State<Arc<TestAuthState>>,
    headers: HeaderMap,
    Json(req): Json<TestLoginRequest>,
) -> Result<(HeaderMap, Json<TestLoginResponse>), SessionFinalizationError> {
    let config = &test_auth_state.config;

    // Check if test mode is enabled
    if !config.enabled {
        // Return 404 to not reveal the endpoint exists in production
        return Err(StatusCode::NOT_FOUND.into());
    }

    test_auth_state.reject_if_rate_limited()?;

    // Validate test token from header
    let provided_token = headers
        .get("X-Test-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if provided_token.is_empty() {
        warn!("[TEST MODE] Test login attempt without token");
        test_auth_state.record_failed_login()?;
        return Err(StatusCode::UNAUTHORIZED.into());
    }

    if provided_token != config.test_token {
        warn!("[TEST MODE] Invalid test token provided");
        test_auth_state.record_failed_login()?;
        return Err(StatusCode::UNAUTHORIZED.into());
    }

    let role = match requested_role(req.role, config) {
        Ok(role) => role,
        Err(status) => {
            warn!("[TEST MODE] Test login attempted to override role without explicit enablement");
            test_auth_state.record_failed_login()?;
            return Err(status.into());
        }
    };
    test_auth_state.clear_failed_logins()?;

    // Ensure the synthetic UI-test session maps to a real stored user so
    // dashboard profile and permission lookups behave like normal auth.
    let username = req
        .username
        .unwrap_or_else(|| config.test_username.clone());
    let user = test_auth_state
        .user_provisioner
        .ensure_user(&username, role)
        .await?;
    let finalized_session = test_auth_state
        .session_finalizer
        .finalize_session(AuthenticatedPrincipal::new(user.username.clone(), user.user_id.clone()))
        .await?;

    info!("[TEST MODE] Test login successful - user: {}, user_id: {}", user.username, user.user_id);

    Ok((
        finalized_session.headers,
        Json(TestLoginResponse {
            session_token: finalized_session.session_token,
            username: user.username,
            expires_in_seconds: test_auth_state
                .session_finalizer
                .session_timeout_seconds(),
            consent_required: finalized_session.consent_required,
        }),
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use lazy_static::lazy_static;
    use std::sync::Mutex;
    use tempfile::tempdir;

    use super::*;

    // required as each test modifies environment variables,
    // which impacts other tests so we use a global mutex
    // to serialize them
    lazy_static! {
        pub(crate) static ref TEST_LOCK: Mutex<bool> = Mutex::new(true);
    }

    #[test]
    fn test_config_default_disabled() {
        let _unused = TEST_LOCK.lock();

        // Clear env vars for clean test
        unsafe {
            std::env::remove_var("AG_TEST_MODE");
            std::env::remove_var("AG_TEST_TOKEN");
            std::env::remove_var("AG_TEST_USERNAME");
            std::env::remove_var("AG_TEST_USER_ID");
            std::env::remove_var("AG_TEST_ALLOW_ROLE_OVERRIDE");
        }

        let config = TestAuthConfig::from_env();
        assert!(!config.enabled);
        assert_eq!(config.test_token, "");
        assert_eq!(config.test_username, "test-user");
        assert_eq!(config.test_user_id, "test-user-001");
    }

    #[test]
    fn test_config_enabled_from_env() {
        let _unused = TEST_LOCK.lock();

        unsafe {
            std::env::set_var("AG_TEST_MODE", "true");
            std::env::set_var("AG_TEST_TOKEN", "custom-token-value-with-32-plus-chars");
            std::env::set_var("AG_TEST_USERNAME", "custom-user");
            std::env::set_var("AG_TEST_USER_ID", "custom-id");
        }

        let config = TestAuthConfig::from_env();
        assert!(config.enabled);
        assert_eq!(config.test_token, "custom-token-value-with-32-plus-chars");
        assert_eq!(config.test_username, "custom-user");
        assert_eq!(config.test_user_id, "custom-id");

        unsafe {
            std::env::remove_var("AG_TEST_MODE");
            std::env::remove_var("AG_TEST_TOKEN");
            std::env::remove_var("AG_TEST_USERNAME");
            std::env::remove_var("AG_TEST_USER_ID");
        }
    }

    #[test]
    fn test_config_enabled_with_1() {
        let _unused = TEST_LOCK.lock();

        unsafe {
            std::env::set_var("AG_TEST_MODE", "1");
            std::env::set_var("AG_TEST_TOKEN", "custom-token-value-with-32-plus-chars");
        }

        let config = TestAuthConfig::from_env();
        assert!(config.enabled);

        unsafe {
            std::env::remove_var("AG_TEST_MODE");
            std::env::remove_var("AG_TEST_TOKEN");
        }
    }

    #[test]
    fn test_config_disables_test_mode_without_explicit_strong_token() {
        let _unused = TEST_LOCK.lock();

        unsafe {
            std::env::set_var("AG_TEST_MODE", "true");
            std::env::remove_var("AG_TEST_TOKEN");
        }

        let config = TestAuthConfig::from_env();
        assert!(!config.enabled);

        unsafe {
            std::env::remove_var("AG_TEST_MODE");
        }
    }

    #[test]
    fn test_config_rejects_legacy_default_token() {
        let _unused = TEST_LOCK.lock();

        unsafe {
            std::env::set_var("AG_TEST_MODE", "true");
            std::env::set_var("AG_TEST_TOKEN", LEGACY_DEFAULT_TEST_TOKEN);
        }

        let config = TestAuthConfig::from_env();
        assert!(!config.enabled);

        unsafe {
            std::env::remove_var("AG_TEST_MODE");
            std::env::remove_var("AG_TEST_TOKEN");
        }
    }

    #[test]
    fn test_requested_role_requires_explicit_override_enablement() {
        let config = TestAuthConfig {
            enabled: true,
            test_token: "custom-token-value-with-32-plus-chars".to_string(),
            allow_role_override: false,
            test_username: "test-user".to_string(),
            test_user_id: "test-user-001".to_string(),
        };

        assert_eq!(requested_role(None, &config).unwrap(), UserRole::User);
        assert_eq!(requested_role(Some(UserRole::Administrator), &config), Err(StatusCode::FORBIDDEN));

        let config = TestAuthConfig {
            allow_role_override: true,
            ..config
        };
        assert_eq!(requested_role(Some(UserRole::Administrator), &config).unwrap(), UserRole::Administrator);
    }

    #[test]
    fn test_config_disabled_with_false() {
        let _unused = TEST_LOCK.lock();

        unsafe {
            std::env::set_var("AG_TEST_MODE", "false");
        }

        let config = TestAuthConfig::from_env();
        assert!(!config.enabled);

        unsafe {
            std::env::remove_var("AG_TEST_MODE");
        }
    }

    #[tokio::test]
    async fn test_rejects_test_login_after_failed_attempt_window_is_full() {
        let _unused = TEST_LOCK.lock();

        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("users");
        let avatars_path = temp_dir
            .path()
            .join("avatars");
        let storage = Arc::new(
            PasskeyStorage::new(
                storage_path
                    .to_string_lossy()
                    .into_owned(),
                avatars_path
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        let session_manager = Arc::new(SessionManager::new());
        let state = TestAuthState::new(
            storage,
            session_manager,
            std::sync::Arc::new(crate::terms::TermsManager::disabled()),
            TestAuthConfig {
                enabled: true,
                test_token: "custom-token-value-with-32-plus-chars".to_string(),
                allow_role_override: true,
                test_username: "test-user".to_string(),
                test_user_id: "test-user-001".to_string(),
            },
        );

        for _ in 0..MAX_FAILED_LOGINS_PER_WINDOW {
            state
                .record_failed_login()
                .unwrap();
        }

        assert_eq!(state.reject_if_rate_limited(), Err(StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test]
    async fn test_ensure_test_user_creates_approved_administrator() {
        let _unused = TEST_LOCK.lock();

        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("users");
        let avatars_path = temp_dir
            .path()
            .join("avatars");
        let storage = PasskeyStorage::new(
            storage_path
                .to_string_lossy()
                .into_owned(),
            avatars_path
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();

        let config = TestAuthConfig {
            enabled: true,
            test_token: "custom-token-value-with-32-plus-chars".to_string(),
            allow_role_override: true,
            test_username: "test-user".to_string(),
            test_user_id: "test-user-001".to_string(),
        };

        let user = ensure_test_user(&storage, &config, "test-user", UserRole::Administrator)
            .await
            .unwrap();

        assert_eq!(user.user_id, "test-user-001");
        assert_eq!(user.role, UserRole::Administrator);
        assert_eq!(user.status, UserStatus::Approved);
        assert_eq!(user.avatar_path.as_deref(), Some("avatars/default.png"));

        let stored_user = storage
            .load_user_by_id("test-user-001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_user.username, "test-user");
        assert_eq!(stored_user.role, UserRole::Administrator);
        assert_eq!(stored_user.status, UserStatus::Approved);
    }

    #[tokio::test]
    async fn test_ensure_test_user_upgrades_existing_user() {
        let _unused = TEST_LOCK.lock();

        let temp_dir = tempdir().unwrap();
        let storage_path = temp_dir.path().join("users");
        let avatars_path = temp_dir
            .path()
            .join("avatars");
        let storage = PasskeyStorage::new(
            storage_path
                .to_string_lossy()
                .into_owned(),
            avatars_path
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();

        let now = chrono::Utc::now();
        storage
            .save_user(&UserData {
                user_id: "test-user-001".to_string(),
                username: "test-user".to_string(),
                passkeys: Vec::new(),
                role: UserRole::User,
                status: UserStatus::New,
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

        let config = TestAuthConfig {
            enabled: true,
            test_token: "custom-token-value-with-32-plus-chars".to_string(),
            allow_role_override: true,
            test_username: "test-user".to_string(),
            test_user_id: "test-user-001".to_string(),
        };

        let user = ensure_test_user(&storage, &config, "test-user", UserRole::User)
            .await
            .unwrap();

        assert_eq!(user.role, UserRole::User);
        assert_eq!(user.status, UserStatus::Approved);
        assert_eq!(user.first_name.as_deref(), Some("UI"));
        assert_eq!(user.avatar_path.as_deref(), Some("avatars/default.png"));
        assert!(user.last_logged_in.is_some());
    }
}
