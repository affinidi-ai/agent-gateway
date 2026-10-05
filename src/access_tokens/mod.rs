//! Management access tokens for non-interactive management API clients.

pub mod handlers;
pub mod router;
pub mod store;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use store::FsAccessTokenStore;

use crate::auth_manager::resource_scope::RequiredHeader;

pub const TOKEN_PREFIX: &str = "agpat_";
pub const MAX_DELEGATION_DEPTH: u32 = 3;

fn is_zero(value: &u32) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub token_hash: String,
    pub user_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_headers: Vec<RequiredHeader>,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_token_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub delegation_depth: u32,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    pub fn is_expired(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        self.expires_at
            .is_some_and(|expires_at| now >= expires_at)
    }

    pub fn is_active(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        self.revoked_at.is_none() && !self.is_expired(now)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessTokenMeta {
    pub id: String,
    pub name: String,
    pub description: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub resource_pattern: Option<String>,
    pub required_headers: Vec<RequiredHeader>,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_token_id: Option<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub delegation_depth: u32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub active: bool,
}

impl AccessTokenMeta {
    pub fn from_token(
        token: &AccessToken,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: token.id.clone(),
            name: token.name.clone(),
            description: token.description.clone(),
            user_id: token.user_id.clone(),
            scopes: token.scopes.clone(),
            resource_pattern: token.resource_pattern.clone(),
            required_headers: token.required_headers.clone(),
            created_by: token.created_by.clone(),
            parent_token_id: token.parent_token_id.clone(),
            delegation_depth: token.delegation_depth,
            created_at: token.created_at,
            last_used_at: token.last_used_at,
            expires_at: token.expires_at,
            revoked_at: token.revoked_at,
            active: token.is_active(now),
        }
    }
}

pub fn generate_token() -> (String, String) {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let id = format!("agat_{}", uuid::Uuid::new_v4().as_simple());
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let secret = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(bytes));
    (id, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_uses_canonical_wire_format() {
        let (id, secret) = generate_token();
        assert!(id.starts_with("agat_"));
        assert!(secret.starts_with(TOKEN_PREFIX));
        assert_eq!(secret.len(), TOKEN_PREFIX.len() + 43);
    }
}
