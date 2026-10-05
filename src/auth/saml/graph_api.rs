use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::path::Path;
use tracing::{info, warn};

use crate::auth::auth_config::GraphApiConfig;

/// OAuth token response from Azure AD
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: u64,
}

/// Microsoft Graph API client
pub struct GraphApiClient {
    config: GraphApiConfig,
    client: Client,
}

impl GraphApiClient {
    pub fn new(config: GraphApiConfig) -> Self {
        Self { config, client: Client::new() }
    }

    /// Get an access token for Microsoft Graph API using client credentials flow
    async fn get_access_token(&self) -> Result<String> {
        let token_url = format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", self.config.tenant_id);

        let params = [
            ("client_id", self.config.client_id.as_str()),
            (
                "client_secret",
                self.config
                    .client_secret
                    .as_str(),
            ),
            ("scope", "https://graph.microsoft.com/.default"),
            ("grant_type", "client_credentials"),
        ];

        let response = self
            .client
            .post(&token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(
                params
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&"),
            )
            .send()
            .await
            .context("Failed to request access token")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_default();
            warn!("Token request failed - Status: {}, Response: {}", status, error_text);
            anyhow::bail!("Token request failed with status {}: {}", status, error_text);
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .context("Failed to parse token response")?;

        Ok(token_response.access_token)
    }

    /// Fetch user avatar from Microsoft Graph API
    /// Returns the avatar as bytes if found, None if user has no avatar
    pub async fn fetch_user_avatar(
        &self,
        user_email: &str,
    ) -> Result<Option<Vec<u8>>> {
        // Get access token
        let access_token = self
            .get_access_token()
            .await
            .context("Failed to get access token")?;

        // Fetch user's photo
        let photo_url = format!("https://graph.microsoft.com/v1.0/users/{}/photo/$value", user_email);

        info!("Fetching avatar for user: {}", user_email);

        let response = self
            .client
            .get(&photo_url)
            .bearer_auth(&access_token)
            .send()
            .await
            .context("Failed to fetch user photo")?;

        match response.status().as_u16() {
            200 => {
                // Success - user has a photo
                let bytes = response
                    .bytes()
                    .await
                    .context("Failed to read photo bytes")?;
                info!("Successfully fetched avatar for {}: {} bytes", user_email, bytes.len());
                Ok(Some(bytes.to_vec()))
            }
            404 => {
                // User doesn't have a photo
                info!("User {} has no avatar in Azure AD", user_email);
                Ok(None)
            }
            status => {
                let error_text = response
                    .text()
                    .await
                    .unwrap_or_default();
                warn!("Failed to fetch avatar for {}: {} - {}", user_email, status, error_text);
                Ok(None)
            }
        }
    }

    /// Save avatar to filesystem
    pub async fn save_avatar(
        avatar_bytes: &[u8],
        user_id: &str,
        storage_path: &str,
    ) -> Result<String> {
        use tokio::fs;

        // Create avatars directory if it doesn't exist
        fs::create_dir_all(storage_path)
            .await
            .context("Failed to create avatars directory")?;

        // Determine image format from magic bytes (file signature)
        let extension = if avatar_bytes.starts_with(b"\x89PNG\r\n\x1A\n") {
            "png"
        } else if avatar_bytes.starts_with(b"\xFF\xD8\xFF") {
            "jpg"
        } else if avatar_bytes.starts_with(b"GIF87a") || avatar_bytes.starts_with(b"GIF89a") {
            "gif"
        } else if avatar_bytes.len() >= 12 && &avatar_bytes[0..4] == b"RIFF" && &avatar_bytes[8..12] == b"WEBP" {
            "webp"
        } else if avatar_bytes.starts_with(b"BM") {
            "bmp"
        } else {
            // Default to jpg for unknown formats
            warn!(
                "Unknown image format, defaulting to jpg. First bytes: {:02X?}",
                &avatar_bytes[..std::cmp::min(16, avatar_bytes.len())]
            );
            "jpg"
        };

        let filename = format!("{}.{}", user_id, extension);
        let file_path = Path::new(storage_path).join(&filename);

        // Write avatar to disk
        fs::write(&file_path, avatar_bytes)
            .await
            .context("Failed to write avatar file")?;

        info!("Saved avatar to: {}", file_path.display());

        Ok(filename)
    }
}
