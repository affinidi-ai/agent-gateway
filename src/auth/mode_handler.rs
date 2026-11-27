use axum::{http::StatusCode, response::Json};
use serde::Serialize;

use crate::auth::AuthMode;

/// The sign-in button's provider name, shown in OIDC mode.
#[derive(Debug, Clone)]
pub struct SignInLabel(pub String);

/// Response for auth mode query
#[derive(Debug, Serialize)]
pub struct AuthModeResponse {
    pub mode: String,
    pub label: Option<String>,
}

/// Get the current authentication mode, and in OIDC mode the provider name the sign-in button
/// shows.
pub async fn get_auth_mode(
    auth_mode: axum::Extension<AuthMode>,
    label: Option<axum::Extension<SignInLabel>>,
) -> Result<Json<AuthModeResponse>, StatusCode> {
    Ok(Json(AuthModeResponse {
        mode: auth_mode.as_str().to_string(),
        label: label.map(|axum::Extension(SignInLabel(label))| label),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_mode_answer_carries_the_sign_in_label_only_when_there_is_one() {
        let oidc = get_auth_mode(
            axum::Extension(AuthMode::Oidc),
            Some(axum::Extension(SignInLabel("Example IdP".to_string()))),
        )
        .await
        .unwrap();
        assert_eq!(oidc.mode, "oidc");
        assert_eq!(oidc.label.as_deref(), Some("Example IdP"));

        for (mode, name) in [(AuthMode::Saml, "saml"), (AuthMode::Passkey, "passkey")] {
            let answer = get_auth_mode(axum::Extension(mode), None)
                .await
                .unwrap();
            assert_eq!(answer.mode, name);
            assert_eq!(answer.label, None);
        }
    }

    #[test]
    fn the_oidc_mode_is_written_oidc_in_config_toml() {
        let mode: AuthMode = serde_json::from_str("\"oidc\"").unwrap();
        assert_eq!(mode, AuthMode::Oidc);
        assert!(serde_json::from_str::<AuthMode>("\"openid\"").is_err());
    }
}
