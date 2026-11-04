use axum::{Extension, http::StatusCode, response::Json};
use serde::Serialize;
use std::sync::Arc;
use tracing::error;

use crate::auth::{AuthMode, AuthState};

/// Response for auth mode query
#[derive(Debug, Serialize)]
pub struct AuthModeResponse {
    pub mode: String,
    /// No user exists yet, so the first passkey registration needs the setup token. Always
    /// `false` in SAML mode.
    pub setup_required: bool,
}

/// Get the current authentication mode
pub async fn get_auth_mode(
    auth_mode: Extension<AuthMode>,
    auth_state: Option<Extension<Arc<AuthState>>>,
) -> Result<Json<AuthModeResponse>, StatusCode> {
    let (mode_str, setup_required) = match (&*auth_mode, auth_state) {
        (AuthMode::Passkey, Some(Extension(auth_state))) => (
            "passkey",
            auth_state
                .setup_required()
                .await
                .map_err(|e| {
                    error!("Failed to list users for the auth mode: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?,
        ),
        (AuthMode::Passkey, None) => ("passkey", false),
        (AuthMode::Saml, _) => ("saml", false),
    };

    Ok(Json(AuthModeResponse {
        mode: mode_str.to_string(),
        setup_required,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::UserData;
    use crate::auth::types::{UserRole, UserStatus};

    async fn passkey_state(dir: &tempfile::TempDir) -> Arc<AuthState> {
        let path = |name: &str| {
            dir.path()
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        Arc::new(
            AuthState::new(
                "example.com".to_string(),
                url::Url::parse("https://example.com").unwrap(),
                path("users"),
                path("avatars"),
                30,
                path("sessions"),
                Arc::new(crate::terms::TermsManager::disabled()),
                None,
            )
            .await
            .unwrap(),
        )
    }

    async fn mode(
        auth_mode: AuthMode,
        auth_state: Option<Arc<AuthState>>,
    ) -> AuthModeResponse {
        get_auth_mode(Extension(auth_mode), auth_state.map(Extension))
            .await
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn passkey_mode_reports_setup_required_while_no_user_exists() {
        let dir = tempfile::tempdir().unwrap();

        let response = mode(AuthMode::Passkey, Some(passkey_state(&dir).await)).await;

        assert_eq!(response.mode, "passkey");
        assert!(response.setup_required);
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            serde_json::json!({"mode": "passkey", "setup_required": true})
        );
    }

    #[tokio::test]
    async fn passkey_mode_reports_setup_not_required_once_a_user_exists() {
        let dir = tempfile::tempdir().unwrap();
        let state = passkey_state(&dir).await;
        let now = chrono::Utc::now();
        state
            .storage
            .save_user(&UserData {
                user_id: uuid::Uuid::new_v4().to_string(),
                username: "first-admin".to_string(),
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

        let response = mode(AuthMode::Passkey, Some(state)).await;

        assert_eq!(response.mode, "passkey");
        assert!(!response.setup_required);
    }

    #[tokio::test]
    async fn saml_mode_reports_setup_not_required() {
        let dir = tempfile::tempdir().unwrap();

        let without_state = mode(AuthMode::Saml, None).await;
        let with_empty_state = mode(AuthMode::Saml, Some(passkey_state(&dir).await)).await;

        assert_eq!(without_state.mode, "saml");
        assert!(!without_state.setup_required);
        assert_eq!(with_empty_state.mode, "saml");
        assert!(!with_empty_state.setup_required);
    }
}
