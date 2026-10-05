use axum::{Extension, Json, extract::State, http::StatusCode};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::storage::PasskeyStorage;
use crate::identity::state::IdentityApiState;
use crate::rbac::{Feature, RbacConfig};

const DEFAULT_TTL_SECONDS: i64 = 3600;

/// Claims that callers are never allowed to set in signed JWTs.
/// These are either reserved (iss, iat, exp, jti — overwritten by the handler)
/// or privileged (role, admin, scope, permissions, etc.).
const BLOCKED_CLAIMS: &[&str] = &[
    // Privileged claims — prevent privilege escalation
    "role",
    "admin",
    "scope",
    "permissions",
    "groups",
    "entitlements",
    "is_admin",
    "superadmin",
    // Reserved claims — overwritten by the handler; reject caller-supplied
    // values so there is no confusion about which value wins.
    "iss",
    "iat",
    "exp",
    "jti",
];

#[derive(Debug, Deserialize)]
pub struct SignJwtRequest {
    pub agent_did: String,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SignJwtResponse {
    pub jwt: String,
    pub agent_did: String,
    pub issued_at: String,
    pub expires_at: String,
}

/// RBAC guard for sign-jwt.
///
/// Minting a JWT signed by any agent DID's private key is an administrator-only
/// capability — without this gate any authenticated user could impersonate any
/// agent. Returns `Err((status, message))` when the caller is not authorised.
async fn require_sign_jwt_admin(
    user_id: &str,
    storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
) -> Result<(), (StatusCode, String)> {
    let user = storage
        .load_user_by_id(user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Authorization check failed: {e}")))?
        .ok_or((StatusCode::FORBIDDEN, "Insufficient permissions".to_string()))?;
    if !rbac_config.has_permission(&user.role, &Feature::SettingsEdit) {
        warn!(user_id = %user_id, "agents-api: sign-jwt rejected — insufficient permissions");
        return Err((StatusCode::FORBIDDEN, "Insufficient permissions".to_string()));
    }
    Ok(())
}

pub async fn sign_jwt(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<IdentityApiState>,
    Json(request): Json<SignJwtRequest>,
) -> Result<Json<SignJwtResponse>, (StatusCode, String)> {
    require_sign_jwt_admin(&user_id, &passkey_storage, &rbac_config).await?;

    let ttl = request
        .ttl_seconds
        .map(|t| t as i64)
        .unwrap_or(DEFAULT_TTL_SECONDS);

    info!(
        agent_did = %request.agent_did,
        ttl_seconds = ttl,
        payload_keys = ?request.payload.as_object().map(|o| o.keys().collect::<Vec<_>>()),
        "agents-api: sign-jwt request"
    );

    let now = Utc::now();
    let iat = now.timestamp();
    let exp = (now + Duration::seconds(ttl)).timestamp();
    let jti = Uuid::new_v4().to_string();

    let mut payload = request.payload;
    if let Some(obj) = payload.as_object_mut() {
        // Reject any blocked/privileged claims supplied by the caller
        let blocked: Vec<&str> = BLOCKED_CLAIMS
            .iter()
            .filter(|c| obj.contains_key(**c))
            .copied()
            .collect();
        if !blocked.is_empty() {
            return Err((StatusCode::BAD_REQUEST, format!("payload contains blocked claims: {}", blocked.join(", "))));
        }

        obj.insert("iss".to_string(), json!(request.agent_did));
        obj.insert("iat".to_string(), json!(iat));
        obj.insert("exp".to_string(), json!(exp));
        obj.insert("jti".to_string(), json!(jti));
    } else {
        return Err((StatusCode::BAD_REQUEST, "payload must be a JSON object".to_string()));
    }

    let jwt = state
        .vc_issuer
        .sign_jwt_with_agent_key(&request.agent_did, &payload)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, agent_did = %request.agent_did, "Failed to sign JWT");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to sign JWT: {}", e))
        })?;

    info!(
        agent_did = %request.agent_did,
        jwt_len = jwt.len(),
        jti = %jti,
        "agents-api: jwt signed successfully"
    );

    // Format timestamps as ISO 8601 strings
    let issued_at_iso = now.to_rfc3339();
    let expires_at_iso = (now + Duration::seconds(ttl)).to_rfc3339();

    Ok(Json(SignJwtResponse {
        jwt,
        agent_did: request.agent_did,
        issued_at: issued_at_iso,
        expires_at: expires_at_iso,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::UserData;
    use crate::auth::types::{UserRole, UserStatus};

    /// Build an in-memory PasskeyStorage seeded with a single Approved user of the given role.
    async fn storage_with_user(
        user_id: &str,
        role: UserRole,
    ) -> (Arc<PasskeyStorage>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = PasskeyStorage::new(
            tmp.path()
                .join("passkeys")
                .to_string_lossy()
                .to_string(),
            tmp.path()
                .join("avatars")
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("storage init");
        let now = Utc::now();
        let user = UserData {
            user_id: user_id.to_string(),
            username: format!("user-{user_id}"),
            passkeys: Vec::new(),
            role,
            status: UserStatus::Approved,
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
        };
        storage
            .save_user(&user)
            .await
            .expect("save user");
        (Arc::new(storage), tmp)
    }

    #[tokio::test]
    async fn sign_jwt_allows_administrator() {
        let (storage, _tmp) = storage_with_user("admin-1", UserRole::Administrator).await;
        let rbac = RbacConfig::default();
        assert!(
            require_sign_jwt_admin("admin-1", &storage, &rbac)
                .await
                .is_ok(),
            "administrator must be allowed"
        );
    }

    #[tokio::test]
    async fn sign_jwt_denies_regular_user() {
        let (storage, _tmp) = storage_with_user("user-1", UserRole::User).await;
        let rbac = RbacConfig::default();
        let err = require_sign_jwt_admin("user-1", &storage, &rbac)
            .await
            .expect_err("regular user must be denied — this is the impersonation fix");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sign_jwt_denies_poweruser() {
        let (storage, _tmp) = storage_with_user("pu-1", UserRole::PowerUser).await;
        let rbac = RbacConfig::default();
        let err = require_sign_jwt_admin("pu-1", &storage, &rbac)
            .await
            .expect_err("poweruser must be denied");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sign_jwt_denies_unknown_user() {
        let (storage, _tmp) = storage_with_user("admin-1", UserRole::Administrator).await;
        let rbac = RbacConfig::default();
        let err = require_sign_jwt_admin("ghost", &storage, &rbac)
            .await
            .expect_err("unknown user must be denied");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}
