use axum::{http::StatusCode, response::Json};
use serde::Serialize;

use crate::auth::AuthMode;

/// Response for auth mode query
#[derive(Debug, Serialize)]
pub struct AuthModeResponse {
    pub mode: String,
}

/// Get the current authentication mode
pub async fn get_auth_mode(auth_mode: axum::Extension<AuthMode>) -> Result<Json<AuthModeResponse>, StatusCode> {
    let mode_str = match *auth_mode {
        AuthMode::Passkey => "passkey",
        AuthMode::Saml => "saml",
    };

    Ok(Json(AuthModeResponse { mode: mode_str.to_string() }))
}
