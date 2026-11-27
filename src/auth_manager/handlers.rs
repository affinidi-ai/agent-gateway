use axum::extract::Multipart;
use axum::{Extension, Json, extract::Path, http::StatusCode};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use super::types::{DeleteUserResponse, UpdateProfileRequest, UpdateUserRequest, User};
use crate::auth::storage::{PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};
use crate::metrics::MetricsStore;
use crate::rbac::{Feature, RbacConfig};

/// Authorize a user-update request from `caller` against `target`.
///
/// Pure function: no I/O. Enforces RBAC plus defense-in-depth guards that
/// hold even when the RBAC config is misconfigured.
///
/// `approved_admin_count` is the current number of users with role
/// `Administrator` and status `Approved`, including `target` if applicable.
/// It is only consulted when the request would downgrade an administrator.
fn authorize_user_update(
    caller: &UserData,
    target: &UserData,
    req: &UpdateUserRequest,
    rbac_config: &RbacConfig,
    approved_admin_count: usize,
) -> Result<(), (StatusCode, String)> {
    let role_change = req
        .role
        .as_ref()
        .filter(|r| *r != &target.role);
    let status_change = req
        .status
        .as_ref()
        .filter(|s| *s != &target.status);
    let profile_change = req.first_name.is_some()
        || req.last_name.is_some()
        || req.email.is_some()
        || req.department.is_some()
        || req.job_title.is_some();

    // 1. Caller must have users.edit for any mutation.
    if !rbac_config.has_permission(&caller.role, &Feature::UsersEdit) {
        return Err((StatusCode::FORBIDDEN, "Insufficient permissions".to_string()));
    }

    // 1b. Defense-in-depth: role/status changes always require Administrator,
    //     even if the RBAC config is loosened or misconfigured.
    if (role_change.is_some() || status_change.is_some()) && caller.role != UserRole::Administrator {
        return Err((StatusCode::FORBIDDEN, "Only administrators can change user role or status".to_string()));
    }

    // 2. Status changes (including approvals) require users.approve.
    if status_change.is_some() && !rbac_config.has_permission(&caller.role, &Feature::UsersApprove) {
        return Err((StatusCode::FORBIDDEN, "Insufficient permissions to change user status".to_string()));
    }

    let is_self = caller.user_id == target.user_id;

    // 3. No self-modification of role or status, regardless of role.
    //    Profile-only self edits are allowed (handler also exposes /v1/profile).
    if is_self && (role_change.is_some() || status_change.is_some()) {
        return Err((StatusCode::FORBIDDEN, "Cannot change own role or status".to_string()));
    }

    // 4. Only Administrators can grant the Administrator role.
    if let Some(new_role) = role_change
        && *new_role == UserRole::Administrator
        && caller.role != UserRole::Administrator
    {
        return Err((StatusCode::FORBIDDEN, "Only administrators can grant the administrator role".to_string()));
    }

    // 5. Last-admin guard: cannot downgrade the only remaining approved admin.
    if target.role == UserRole::Administrator
        && target.status == UserStatus::Approved
        && let Some(new_role) = role_change
        && *new_role != UserRole::Administrator
        && approved_admin_count <= 1
    {
        return Err((StatusCode::CONFLICT, "Cannot downgrade the only remaining approved administrator".to_string()));
    }

    // 6. Last-admin guard: cannot disable the only remaining approved admin.
    if target.role == UserRole::Administrator
        && target.status == UserStatus::Approved
        && let Some(new_status) = status_change
        && *new_status != UserStatus::Approved
        && approved_admin_count <= 1
    {
        return Err((StatusCode::CONFLICT, "Cannot disable the only remaining approved administrator".to_string()));
    }

    // 7. Profile-field edits on another user also require users.edit (already
    //    enforced by check 1). Self profile edits via this endpoint are allowed
    //    so the existing UI flow continues to work.
    let _ = profile_change;

    Ok(())
}

/// Authorize a user-deletion request from `caller` against `target`.
///
/// Pure function: no I/O. The existing target-side guards (primary admin,
/// administrator role) remain in the handler for clarity and message
/// specificity.
fn authorize_user_delete(
    caller: &UserData,
    target: &UserData,
    rbac_config: &RbacConfig,
) -> Result<(), (StatusCode, String)> {
    if !rbac_config.has_permission(&caller.role, &Feature::UsersDelete) {
        return Err((StatusCode::FORBIDDEN, "Insufficient permissions".to_string()));
    }
    if caller.user_id == target.user_id {
        return Err((StatusCode::FORBIDDEN, "Cannot delete own account".to_string()));
    }
    Ok(())
}

/// Decide whether existing sessions for a user must be force-revoked after
/// a successful update. Pure function: no I/O.
///
/// Triggers:
/// 1. Account becomes non-Approved (Disabled / New) — previously valid
///    tokens must stop working so the account is effectively locked out.
/// 2. Role changes — outstanding tokens must not retain the prior role's
///    privileges (or, in the rare grant case, must re-authenticate to pick
///    up the new role for any cached identity).
fn should_revoke_user_sessions(
    before: &UserData,
    after: &UserData,
) -> bool {
    let became_inactive = before.status == UserStatus::Approved && after.status != UserStatus::Approved;
    let role_changed = before.role != after.role;
    became_inactive || role_changed
}

/// List all users (requires users.view permission)
pub async fn list_users(
    Extension(user_id): Extension<String>,
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<std::sync::Arc<RbacConfig>>,
) -> Result<Json<Vec<User>>, (StatusCode, String)> {
    // Check permission
    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load user: {}", e)))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "User not found".to_string()))?;

    if !rbac_config.has_permission(&user_data.role, &Feature::UsersView) {
        return Err((StatusCode::FORBIDDEN, "Insufficient permissions".to_string()));
    }

    let user_ids = storage
        .list_users()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list users: {}", e)))?;

    let mut users = Vec::with_capacity(user_ids.len());
    for user_id in user_ids {
        if let Ok(Some(user_data)) = storage
            .load_user_by_id(&user_id)
            .await
        {
            users.push(User::from(user_data));
        }
    }

    // Sort by created_at descending (newest first)
    users.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
    });

    Ok(Json(users))
}

fn spawn_record_user_event(
    metrics_store: Arc<MetricsStore>,
    action: String,
    user_role: crate::auth::UserRole,
) {
    tokio::spawn(async move {
        let role = user_role.to_string();
        metrics_store
            .record_user_event(&action, &role)
            .await;
    });
}

/// Get a specific user
pub async fn get_user(
    Extension(metrics_store): Extension<Option<Arc<MetricsStore>>>,
    Extension(caller_user_id): Extension<String>,
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<std::sync::Arc<RbacConfig>>,
    Extension(notif_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(user_id): Path<String>,
) -> Result<Json<User>, (StatusCode, String)> {
    // Allow self-read; otherwise require users.view (admin-only by default)
    if caller_user_id != user_id {
        let caller = storage
            .load_user_by_id(&caller_user_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load caller: {}", e)))?
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Caller not found".to_string()))?;

        if !rbac_config.has_permission(&caller.role, &Feature::UsersView) {
            return Err((StatusCode::FORBIDDEN, "Insufficient permissions".to_string()));
        }
    }

    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?
        .clone();

    crate::integrations::trigger_user_accessed(&user_data);
    if notif_store.is_some()
        && let Some(metrics_store) = metrics_store
    {
        spawn_record_user_event(metrics_store, "accessed".to_string(), user_data.role.clone());
    }

    Ok(Json(User::from(user_data)))
}

/// Update a user (role and/or status)
pub async fn update_user(
    Extension(metrics_store): Extension<Option<Arc<MetricsStore>>>,
    Extension(caller_user_id): Extension<String>,
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<std::sync::Arc<RbacConfig>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(session_manager): Extension<std::sync::Arc<crate::auth::session::SessionManager>>,
    Extension(pat_authenticator): Extension<Option<Arc<dyn crate::auth_manager::pat::PatAuthenticator>>>,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<User>, (StatusCode, String)> {
    // Load caller for authorization decisions
    let caller = storage
        .load_user_by_id(&caller_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load caller: {}", e)))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Caller not found".to_string()))?;

    // Load user before update to check if status is changing
    let user_before = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    // Count approved administrators (only relevant when downgrading/disabling
    // the target admin). Cheap enough at user-management scale; storage is an
    // in-memory cache.
    let approved_admin_count = count_approved_administrators(&storage)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to count administrators: {}", e)))?;

    // RBAC + defense-in-depth checks (pure decision).
    if let Err(e) = authorize_user_update(&caller, &user_before, &req, &rbac_config, approved_admin_count) {
        tracing::warn!(
            target: "audit",
            event = "user.update_denied",
            caller_user_id = %caller_user_id,
            caller_username = %caller.username,
            caller_role = ?caller.role,
            target_user_id = %user_id,
            target_username = %user_before.username,
            requested_status = ?req.status,
            requested_role = ?req.role,
            reason = %e.1,
            "Authorization denied for user update attempt",
        );
        return Err(e);
    }

    // Prevent modifications to primary user
    if user_before.is_primary {
        // Check if trying to change role
        if let Some(new_role) = &req.role
            && new_role != &user_before.role
        {
            return Err((StatusCode::FORBIDDEN, "Cannot change role of primary administrator".to_string()));
        }
        // Check if trying to change status
        if let Some(new_status) = &req.status
            && new_status != &user_before.status
        {
            return Err((StatusCode::FORBIDDEN, "Cannot change status of primary administrator".to_string()));
        }
    }

    let reapproved = user_before
        .deleted_at
        .is_some()
        && req.status == Some(UserStatus::Approved);
    if reapproved {
        revoke_access_tokens(pat_authenticator.as_deref(), &user_id).await?;
        session_manager
            .remove_sessions_for_user(&user_id)
            .await;
    }

    storage
        .update_user(&user_id, req.role.clone(), req.status.clone(), crate::config::global_limits())
        .await
        .map_err(|e| match e.downcast_ref::<crate::config::LimitExceeded>() {
            Some(limit) => {
                crate::config::log_limit_reached("users", limit);
                (StatusCode::FORBIDDEN, limit.message())
            }
            None => (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update user: {}", e)),
        })?;

    // Update profile fields if provided
    if req.first_name.is_some()
        || req.last_name.is_some()
        || req.email.is_some()
        || req.department.is_some()
        || req.job_title.is_some()
    {
        storage
            .update_profile(
                &user_id,
                req.first_name.clone(),
                req.last_name.clone(),
                req.email.clone(),
                req.department.clone(),
                req.job_title.clone(),
                None, // avatar_path not updated here
            )
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update profile: {}", e)))?;
    }

    // Load updated user data
    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load updated user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    // Revoke any active sessions when this update should force
    // re-authentication (status moved away from Approved or role changed).
    if should_revoke_user_sessions(&user_before, &user_data) {
        let revoked = session_manager
            .remove_sessions_for_user(&user_id)
            .await;
        tracing::info!(
            "Revoked {} active session(s) for user_id={} after update (status {:?}->{:?}, role {:?}->{:?})",
            revoked,
            user_id,
            user_before.status,
            user_data.status,
            user_before.role,
            user_data.role
        );
    }

    tracing::info!(
        target: "audit",
        event = "user.updated",
        approver_user_id = %caller_user_id,
        approver_username = %caller.username,
        approver_role = ?caller.role,
        target_user_id = %user_id,
        target_username = %user_data.username,
        status_before = ?user_before.status,
        status_after = ?user_data.status,
        role_before = ?user_before.role,
        role_after = ?user_data.role,
        "User record modified by {}",
        caller.username,
    );

    // If user was just approved, send welcome notification
    if user_before.status == crate::auth::UserStatus::New
        && user_data.status == crate::auth::UserStatus::Approved
        && user_data.role != crate::auth::UserRole::Administrator
    {
        tracing::info!("User approval detected - will send welcome notification to user_id: {}", user_id);
        if let Some(notif_store) = &notification_store {
            use crate::integrations::NotificationStore;
            match notif_store
                .send_user_welcome_notification(&user_data.user_id)
                .await
            {
                Ok(_) => tracing::info!("Sent welcome notification to newly approved user_id: {}", user_id),
                Err(e) => tracing::error!("Failed to send welcome notification to user_id {}: {}", user_id, e),
            }
            if let Some(metrics_store) = metrics_store.clone() {
                spawn_record_user_event(metrics_store, "approved".to_string(), user_data.role.clone());
            }
        } else {
            tracing::error!("Notification store not available - cannot send welcome notification");
        }
        crate::integrations::trigger_user_approved(&user_data);
    }
    if reapproved {
        crate::integrations::trigger_user_approved(&user_data);
    }

    crate::integrations::trigger_user_updated(&user_before, &user_data);
    if notification_store.is_some()
        && let Some(metrics_store) = metrics_store
    {
        spawn_record_user_event(metrics_store, "updated".to_string(), user_data.role.clone());
    }

    Ok(Json(User::from(user_data)))
}

/// Delete a user. Ends their sessions and revokes the access tokens they hold; a user who signs
/// in through an OpenID provider or SAML is kept as a disabled record (see
/// [`PasskeyStorage::delete_user`]), and the answer says which happened.
pub async fn delete_user(
    Extension(metrics_store): Extension<Option<Arc<MetricsStore>>>,
    Extension(caller_user_id): Extension<String>,
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<std::sync::Arc<RbacConfig>>,
    Extension(session_manager): Extension<std::sync::Arc<crate::auth::session::SessionManager>>,
    Extension(pat_authenticator): Extension<Option<Arc<dyn crate::auth_manager::pat::PatAuthenticator>>>,
    Path(user_id): Path<String>,
) -> Result<Json<DeleteUserResponse>, (StatusCode, String)> {
    // Load caller for authorization decisions
    let caller = storage
        .load_user_by_id(&caller_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load caller: {}", e)))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Caller not found".to_string()))?;

    // Check if user exists
    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    // RBAC + self-delete check (pure decision).
    authorize_user_delete(&caller, &user_data, &rbac_config)?;

    // Don't allow deleting primary user
    if user_data.is_primary {
        return Err((StatusCode::FORBIDDEN, "Cannot delete primary administrator".to_string()));
    }

    // Don't allow deleting administrators
    if user_data.role == crate::auth::UserRole::Administrator {
        return Err((StatusCode::FORBIDDEN, "Cannot delete administrator users".to_string()));
    }

    let revoked_tokens = revoke_access_tokens(pat_authenticator.as_deref(), &user_id).await?;

    let deleted = storage
        .delete_user(&user_data.user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete user: {}", e)))?;

    tracing::info!(
        target: "audit",
        event = "user.deleted",
        caller_user_id = %caller_user_id,
        target_user_id = %user_id,
        outcome = ?deleted.outcome,
        already_deleted = !deleted.changed,
        revoked_tokens,
        "User deleted"
    );

    if deleted.changed {
        crate::integrations::trigger_user_deleted(&user_data);
    }

    // Revoke any active sessions so the deleted account cannot continue
    // operating with previously issued bearer tokens.
    let revoked = session_manager
        .remove_sessions_for_user(&user_id)
        .await;
    if revoked > 0 {
        tracing::info!("Revoked {} active session(s) for deleted user_id={}", revoked, user_id);
    }
    if deleted.changed
        && let Some(metrics_store) = metrics_store
    {
        spawn_record_user_event(metrics_store, "deleted".to_string(), user_data.role.clone());
    }

    Ok(Json(DeleteUserResponse { outcome: deleted.outcome }))
}

/// Revoke the access tokens `user_id` holds through `authenticator`, when access tokens are on,
/// and return how many were revoked.
async fn revoke_access_tokens(
    authenticator: Option<&dyn crate::auth_manager::pat::PatAuthenticator>,
    user_id: &str,
) -> Result<usize, (StatusCode, String)> {
    let Some(authenticator) = authenticator else {
        return Ok(0);
    };
    authenticator
        .revoke_for_user(user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to revoke access tokens: {}", e)))
}

/// Get current user profile
pub async fn get_profile(
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(user_id): Extension<String>,
) -> Result<Json<User>, (StatusCode, String)> {
    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(User::from(user_data)))
}

/// Update current user profile
pub async fn update_profile(
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(user_id): Extension<String>,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<User>, (StatusCode, String)> {
    storage
        .update_profile(
            &user_id,
            req.first_name.clone(),
            req.last_name.clone(),
            req.email.clone(),
            req.department.clone(),
            req.job_title.clone(),
            None, // avatar_path handled separately via upload endpoint
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update profile: {}", e)))?;

    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load updated user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(User::from(user_data)))
}

/// Upload user avatar
pub async fn upload_avatar(
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(user_id): Extension<String>,
    mut multipart: Multipart,
) -> Result<Json<User>, (StatusCode, String)> {
    // Get user data
    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    let mut avatar_data: Option<Vec<u8>> = None;
    let mut file_extension = String::from("png");

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to read multipart field: {}", e)))?
    {
        if field.name() == Some("avatar") {
            let content_type = field
                .content_type()
                .unwrap_or("image/png")
                .to_string();
            file_extension = match content_type.as_str() {
                "image/jpeg" | "image/jpg" => "jpg",
                "image/png" => "png",
                "image/gif" => "gif",
                "image/webp" => "webp",
                _ => "png",
            }
            .to_string();

            avatar_data = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to read file data: {}", e)))?
                    .to_vec(),
            );
            break;
        }
    }

    let avatar_data = avatar_data.ok_or_else(|| (StatusCode::BAD_REQUEST, "No avatar file provided".to_string()))?;

    // Create avatars directory
    let avatars_dir = PathBuf::from(storage.avatars_path());
    fs::create_dir_all(&avatars_dir)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create avatars directory: {}", e)))?;

    // Save avatar file
    let filename = format!("{}.{}", user_data.user_id, file_extension);
    let avatar_path = avatars_dir.join(&filename);
    let mut file = fs::File::create(&avatar_path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create avatar file: {}", e)))?;

    file.write_all(&avatar_data)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write avatar file: {}", e)))?;

    let relative_avatar_path = format!("avatars/{}", filename);
    let linked = storage
        .set_avatar_if_approved(&user_id, relative_avatar_path.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update profile with avatar: {}", e)))?;
    if !linked {
        storage
            .remove_uploaded_avatar(&user_id, &relative_avatar_path)
            .await;
        return Err((StatusCode::FORBIDDEN, "User not approved".to_string()));
    }

    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load updated user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(User::from(user_data)))
}

/// Count users with role `Administrator` and status `Approved`.
async fn count_approved_administrators(storage: &PasskeyStorage) -> anyhow::Result<usize> {
    let ids = storage.list_users().await?;
    let mut count = 0usize;
    for id in ids {
        if let Some(u) = storage
            .load_user_by_id(&id)
            .await?
            && u.role == UserRole::Administrator
            && u.status == UserStatus::Approved
        {
            count += 1;
        }
    }
    Ok(count)
}

/// The user management and avatar routes with the extensions their handlers read, as the gateway
/// mounts them, for a caller already signed in as `caller_user_id`.
#[cfg(test)]
pub(crate) fn user_routes_for_tests(
    storage: Arc<PasskeyStorage>,
    sessions: Arc<crate::auth::session::SessionManager>,
    tokens: Option<Arc<dyn crate::auth_manager::pat::PatAuthenticator>>,
    caller_user_id: &str,
) -> axum::Router {
    axum::Router::new()
        .route("/v1/users/{user_id}", axum::routing::put(update_user).delete(delete_user))
        .route("/v1/profile/avatar", axum::routing::post(upload_avatar))
        .layer(Extension(tokens))
        .layer(Extension(sessions))
        .layer(Extension(storage))
        .layer(Extension(Arc::new(RbacConfig::default())))
        .layer(Extension(None::<Arc<crate::integrations::FileSystemNotificationStore>>))
        .layer(Extension(None::<Arc<MetricsStore>>))
        .layer(Extension(caller_user_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_user(
        id: &str,
        role: UserRole,
        status: UserStatus,
        is_primary: bool,
    ) -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: id.to_string(),
            username: format!("user-{}", id),
            passkeys: Vec::new(),
            role,
            status,
            is_primary,
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
            oidc: None,
            deleted_at: None,
        }
    }

    fn req() -> UpdateUserRequest {
        UpdateUserRequest {
            role: None,
            status: None,
            first_name: None,
            last_name: None,
            email: None,
            department: None,
            job_title: None,
        }
    }

    fn admin_only_rbac() -> RbacConfig {
        RbacConfig::default()
    }

    #[test]
    fn update_rejects_non_admin_caller() {
        let caller = mk_user("u", UserRole::User, UserStatus::Approved, false);
        let target = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::User);
        let err = authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 2).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn update_rejects_poweruser_caller_by_default_rbac() {
        let caller = mk_user("p", UserRole::PowerUser, UserStatus::Approved, false);
        let target = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::User);
        let err = authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 2).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn update_rejects_self_role_change_even_for_admin() {
        let caller = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = caller.clone();
        let mut r = req();
        r.role = Some(UserRole::User);
        let err = authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 2).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(err.1.contains("own role"));
    }

    #[test]
    fn update_rejects_self_status_change_even_for_admin() {
        let caller = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = caller.clone();
        let mut r = req();
        r.status = Some(UserStatus::Disabled);
        let err = authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 2).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn update_allows_self_profile_edit() {
        let caller = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = caller.clone();
        let mut r = req();
        r.first_name = Some("New".into());
        authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 2).unwrap();
    }

    #[test]
    fn update_only_admin_can_grant_admin_role() {
        let mut cfg = RbacConfig::default();
        cfg.permissions
            .insert("users.edit".into(), "poweruser".into());
        cfg.permissions
            .insert("users.approve".into(), "poweruser".into());
        let caller = mk_user("p", UserRole::PowerUser, UserStatus::Approved, false);
        let target = mk_user("t", UserRole::User, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::Administrator);
        let err = authorize_user_update(&caller, &target, &r, &cfg, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(
            err.1
                .to_lowercase()
                .contains("administrator")
        );
    }

    #[test]
    fn update_admin_can_grant_admin_role() {
        let caller = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = mk_user("t", UserRole::User, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::Administrator);
        authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 1).unwrap();
    }

    #[test]
    fn update_last_admin_cannot_be_downgraded() {
        let caller = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = mk_user("b", UserRole::Administrator, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::User);
        let err = authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 1).unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
    }

    #[test]
    fn update_last_admin_cannot_be_disabled() {
        let caller = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = mk_user("b", UserRole::Administrator, UserStatus::Approved, false);
        let mut r = req();
        r.status = Some(UserStatus::Disabled);
        let err = authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 1).unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
    }

    #[test]
    fn update_admin_downgrade_allowed_when_others_exist() {
        let caller = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = mk_user("b", UserRole::Administrator, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::User);
        authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 2).unwrap();
    }

    #[test]
    fn update_status_change_requires_users_approve() {
        let mut cfg = RbacConfig::default();
        cfg.permissions
            .insert("users.edit".into(), "poweruser".into());
        let caller = mk_user("p", UserRole::PowerUser, UserStatus::Approved, false);
        let target = mk_user("t", UserRole::User, UserStatus::New, false);
        let mut r = req();
        r.status = Some(UserStatus::Approved);
        let err = authorize_user_update(&caller, &target, &r, &cfg, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(
            err.1
                .to_lowercase()
                .contains("status")
        );
    }

    #[test]
    fn delete_rejects_non_admin_caller() {
        let caller = mk_user("u", UserRole::User, UserStatus::Approved, false);
        let target = mk_user("t", UserRole::User, UserStatus::Approved, false);
        let err = authorize_user_delete(&caller, &target, &admin_only_rbac()).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn delete_rejects_self_delete() {
        let caller = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = caller.clone();
        let err = authorize_user_delete(&caller, &target, &admin_only_rbac()).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(
            err.1
                .to_lowercase()
                .contains("own")
        );
    }

    #[test]
    fn delete_allows_admin_to_delete_user() {
        let caller = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = mk_user("u", UserRole::User, UserStatus::Approved, false);
        authorize_user_delete(&caller, &target, &admin_only_rbac()).unwrap();
    }

    #[test]
    fn revoke_when_status_flips_from_approved_to_disabled() {
        let before = mk_user("u", UserRole::User, UserStatus::Approved, false);
        let mut after = before.clone();
        after.status = UserStatus::Disabled;
        assert!(should_revoke_user_sessions(&before, &after));
    }

    #[test]
    fn revoke_when_status_flips_from_approved_to_new() {
        let before = mk_user("u", UserRole::User, UserStatus::Approved, false);
        let mut after = before.clone();
        after.status = UserStatus::New;
        assert!(should_revoke_user_sessions(&before, &after));
    }

    #[test]
    fn revoke_when_role_changes() {
        let before = mk_user("u", UserRole::User, UserStatus::Approved, false);
        let mut after = before.clone();
        after.role = UserRole::PowerUser;
        assert!(should_revoke_user_sessions(&before, &after));
    }

    #[test]
    fn revoke_when_admin_demoted_to_user() {
        let before = mk_user("u", UserRole::Administrator, UserStatus::Approved, false);
        let mut after = before.clone();
        after.role = UserRole::User;
        assert!(should_revoke_user_sessions(&before, &after));
    }

    #[test]
    fn no_revoke_when_only_profile_changes() {
        let before = mk_user("u", UserRole::User, UserStatus::Approved, false);
        let mut after = before.clone();
        after.first_name = Some("New".into());
        assert!(!should_revoke_user_sessions(&before, &after));
    }

    #[test]
    fn no_revoke_when_new_becomes_approved() {
        // Newly approved users could not previously authenticate — there
        // are no live sessions to revoke. Don't churn unnecessarily.
        let before = mk_user("u", UserRole::User, UserStatus::New, false);
        let mut after = before.clone();
        after.status = UserStatus::Approved;
        assert!(!should_revoke_user_sessions(&before, &after));
    }

    #[test]
    fn no_revoke_when_nothing_changes() {
        let before = mk_user("u", UserRole::User, UserStatus::Approved, false);
        let after = before.clone();
        assert!(!should_revoke_user_sessions(&before, &after));
    }

    // ── Privilege-escalation regression guards ─────────────────────────

    #[test]
    fn user_cannot_self_escalate_to_admin() {
        let victim = mk_user("8206ce69", UserRole::User, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::Administrator);

        let err = authorize_user_update(&victim, &victim, &r, &admin_only_rbac(), 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn user_cannot_escalate_another_user() {
        let caller = mk_user("u1", UserRole::User, UserStatus::Approved, false);
        let target = mk_user("u2", UserRole::User, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::Administrator);

        let err = authorize_user_update(&caller, &target, &r, &admin_only_rbac(), 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn user_cannot_change_own_status() {
        let victim = mk_user("u", UserRole::User, UserStatus::New, false);
        let mut r = req();
        r.status = Some(UserStatus::Approved);

        let err = authorize_user_update(&victim, &victim, &r, &admin_only_rbac(), 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn poweruser_cannot_change_role_even_with_loose_rbac() {
        let mut cfg = RbacConfig::default();
        cfg.permissions
            .insert("users.edit".into(), "poweruser".into());
        let caller = mk_user("p", UserRole::PowerUser, UserStatus::Approved, false);
        let target = mk_user("t", UserRole::User, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::PowerUser);

        let err = authorize_user_update(&caller, &target, &r, &cfg, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn empty_rbac_config_denies_role_change() {
        let cfg = RbacConfig {
            permissions: std::collections::HashMap::new(),
        };
        let caller = mk_user("u", UserRole::User, UserStatus::Approved, false);
        let target = mk_user("t", UserRole::User, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::Administrator);

        let err = authorize_user_update(&caller, &target, &r, &cfg, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn admin_can_still_promote_another_user() {
        let admin = mk_user("a", UserRole::Administrator, UserStatus::Approved, false);
        let target = mk_user("t", UserRole::User, UserStatus::Approved, false);
        let mut r = req();
        r.role = Some(UserRole::Administrator);

        authorize_user_update(&admin, &target, &r, &admin_only_rbac(), 1).unwrap();
    }

    // ── Non-admin cannot approve pending registrations ─────────────────

    #[test]
    fn user_cannot_approve_pending_registration() {
        let attacker = mk_user("victim3", UserRole::User, UserStatus::Approved, false);
        let pending = mk_user("victim4", UserRole::User, UserStatus::New, false);
        let mut r = req();
        r.status = Some(UserStatus::Approved);

        let err = authorize_user_update(&attacker, &pending, &r, &admin_only_rbac(), 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn user_cannot_approve_even_with_loose_rbac() {
        let mut cfg = RbacConfig {
            permissions: std::collections::HashMap::new(),
        };
        cfg.permissions
            .insert("users.edit".into(), "user".into());
        cfg.permissions
            .insert("users.approve".into(), "user".into());

        let attacker = mk_user("victim3", UserRole::User, UserStatus::Approved, false);
        let pending = mk_user("victim4", UserRole::User, UserStatus::New, false);
        let mut r = req();
        r.status = Some(UserStatus::Approved);

        let err = authorize_user_update(&attacker, &pending, &r, &cfg, 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        assert!(
            err.1
                .contains("Only administrators")
        );
    }

    #[test]
    fn poweruser_cannot_approve_pending_registration() {
        let caller = mk_user("pu", UserRole::PowerUser, UserStatus::Approved, false);
        let pending = mk_user("new_user", UserRole::User, UserStatus::New, false);
        let mut r = req();
        r.status = Some(UserStatus::Approved);

        let err = authorize_user_update(&caller, &pending, &r, &admin_only_rbac(), 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn admin_can_approve_pending_registration() {
        let admin = mk_user("admin1", UserRole::Administrator, UserStatus::Approved, false);
        let pending = mk_user("new_user", UserRole::User, UserStatus::New, false);
        let mut r = req();
        r.status = Some(UserStatus::Approved);

        authorize_user_update(&admin, &pending, &r, &admin_only_rbac(), 1).unwrap();
    }

    #[test]
    fn user_cannot_disable_another_user() {
        let attacker = mk_user("attacker", UserRole::User, UserStatus::Approved, false);
        let target = mk_user("target", UserRole::User, UserStatus::Approved, false);
        let mut r = req();
        r.status = Some(UserStatus::Disabled);

        let err = authorize_user_update(&attacker, &target, &r, &admin_only_rbac(), 1).unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    mod routes {
        use super::super::user_routes_for_tests;
        use super::*;
        use crate::access_tokens::FsAccessTokenStore;
        use crate::access_tokens::store::hash_secret;
        use crate::auth::session::SessionManager;
        use crate::auth::storage::OidcIdentity;
        use crate::auth_manager::pat::{PatAuthenticator, PatPrincipal};
        use axum::body::Body;
        use axum::http::Request;
        use serde_json::Value;
        use tower::ServiceExt;

        struct Fixture {
            storage: Arc<PasskeyStorage>,
            sessions: Arc<SessionManager>,
            dir: tempfile::TempDir,
        }

        const ADMIN: &str = "admin-1";

        async fn fixture() -> Fixture {
            let dir = tempfile::tempdir().unwrap();
            let storage = Arc::new(
                PasskeyStorage::new(
                    dir.path()
                        .join("users")
                        .to_string_lossy()
                        .into_owned(),
                    dir.path()
                        .join("avatars")
                        .to_string_lossy()
                        .into_owned(),
                )
                .await
                .unwrap(),
            );
            storage
                .save_user(&mk_user(ADMIN, UserRole::Administrator, UserStatus::Approved, true))
                .await
                .unwrap();
            Fixture {
                storage,
                sessions: Arc::new(SessionManager::new()),
                dir,
            }
        }

        impl Fixture {
            async fn member(
                &self,
                user_id: &str,
                status: UserStatus,
                signs_in_with_oidc: bool,
            ) -> UserData {
                let mut user = mk_user(user_id, UserRole::PowerUser, status, false);
                user.oidc = signs_in_with_oidc.then(|| OidcIdentity {
                    issuer: "https://idp.example.com".to_string(),
                    subject: format!("sub-{user_id}"),
                });
                self.storage
                    .save_user(&user)
                    .await
                    .unwrap();
                user
            }

            async fn send(
                &self,
                tokens: Option<Arc<dyn PatAuthenticator>>,
                caller: &str,
                request: Request<Body>,
            ) -> (StatusCode, Value) {
                let response = user_routes_for_tests(self.storage.clone(), self.sessions.clone(), tokens, caller)
                    .oneshot(request)
                    .await
                    .unwrap();
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
            }

            async fn delete(
                &self,
                tokens: Option<Arc<dyn PatAuthenticator>>,
                user_id: &str,
            ) -> (StatusCode, Value) {
                let request = Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/users/{user_id}"))
                    .body(Body::empty())
                    .unwrap();
                self.send(tokens, ADMIN, request)
                    .await
            }

            async fn set_status(
                &self,
                tokens: Option<Arc<dyn PatAuthenticator>>,
                user_id: &str,
                status: &str,
            ) -> StatusCode {
                let request = Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/users/{user_id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({ "status": status }).to_string()))
                    .unwrap();
                self.send(tokens, ADMIN, request)
                    .await
                    .0
            }

            async fn upload_avatar(
                &self,
                user_id: &str,
            ) -> StatusCode {
                let boundary = "avatar-boundary";
                let mut body = format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n"
                )
                .into_bytes();
                body.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
                body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
                let request = Request::builder()
                    .method("POST")
                    .uri("/v1/profile/avatar")
                    .header("content-type", format!("multipart/form-data; boundary={boundary}"))
                    .body(Body::from(body))
                    .unwrap();
                self.send(None, user_id, request)
                    .await
                    .0
            }

            async fn stored(
                &self,
                user_id: &str,
            ) -> Option<UserData> {
                self.storage
                    .load_user_by_id(user_id)
                    .await
                    .unwrap()
            }

            fn avatar_file(
                &self,
                user_id: &str,
            ) -> std::path::PathBuf {
                self.dir
                    .path()
                    .join("avatars")
                    .join(format!("{user_id}.png"))
            }
        }

        /// Records the users whose tokens were revoked, and fails the revocation when told to.
        struct RecordingTokens {
            revoked_for: std::sync::Mutex<Vec<String>>,
            fails: bool,
        }

        impl RecordingTokens {
            fn new(fails: bool) -> Arc<Self> {
                Arc::new(Self {
                    revoked_for: std::sync::Mutex::new(Vec::new()),
                    fails,
                })
            }

            fn revoked_for(&self) -> Vec<String> {
                self.revoked_for
                    .lock()
                    .unwrap()
                    .clone()
            }
        }

        #[async_trait::async_trait]
        impl PatAuthenticator for RecordingTokens {
            async fn authenticate(
                &self,
                _token: &str,
            ) -> Option<PatPrincipal> {
                None
            }

            async fn revoke_for_user(
                &self,
                user_id: &str,
            ) -> std::io::Result<usize> {
                if self.fails {
                    return Err(std::io::Error::other("token store unavailable"));
                }
                self.revoked_for
                    .lock()
                    .unwrap()
                    .push(user_id.to_string());
                Ok(1)
            }
        }

        #[tokio::test]
        async fn deleting_a_passkey_user_answers_removed_ends_their_sessions_and_removes_the_record() {
            let fixture = fixture().await;
            let member = fixture
                .member("member-1", UserStatus::Approved, false)
                .await;
            let session = fixture
                .sessions
                .create_session(member.username.clone(), member.user_id.clone())
                .await;

            let (status, body) = fixture
                .delete(None, "member-1")
                .await;

            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, serde_json::json!({ "outcome": "removed" }));
            assert!(
                fixture
                    .stored("member-1")
                    .await
                    .is_none()
            );
            assert!(
                fixture
                    .sessions
                    .validate_session(&session)
                    .await
                    .is_none()
            );
        }

        #[tokio::test]
        async fn deleting_an_oidc_user_answers_disabled_and_again_for_a_repeat() {
            let fixture = fixture().await;
            fixture
                .member("oidc-1", UserStatus::Approved, true)
                .await;

            let (first, first_body) = fixture
                .delete(None, "oidc-1")
                .await;
            let (repeat, repeat_body) = fixture
                .delete(None, "oidc-1")
                .await;

            assert_eq!((first, first_body["outcome"].as_str()), (StatusCode::OK, Some("disabled")));
            assert_eq!((repeat, repeat_body["outcome"].as_str()), (StatusCode::OK, Some("disabled")));
            let kept = fixture
                .stored("oidc-1")
                .await
                .unwrap();
            assert_eq!(kept.status, UserStatus::Disabled);
            assert!(kept.deleted_at.is_some());
        }

        #[tokio::test]
        async fn deleting_a_missing_user_answers_not_found_without_an_outcome() {
            let fixture = fixture().await;

            let (status, body) = fixture
                .delete(None, "ghost")
                .await;

            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(body.get("outcome").is_none());
        }

        #[tokio::test]
        async fn deleting_a_user_revokes_the_access_tokens_they_hold_and_no_others() {
            let fixture = fixture().await;
            fixture
                .member("member-1", UserStatus::Approved, true)
                .await;
            let tokens = Arc::new(
                FsAccessTokenStore::new(
                    fixture
                        .dir
                        .path()
                        .join("tokens"),
                )
                .await
                .unwrap(),
            );
            let mut secrets = Vec::new();
            for bound_to in ["member-1", ADMIN] {
                let (id, secret) = crate::access_tokens::generate_token();
                tokens
                    .create(crate::access_tokens::AccessToken {
                        id,
                        name: "service".to_string(),
                        description: String::new(),
                        token_hash: hash_secret(&secret),
                        user_id: bound_to.to_string(),
                        scopes: Vec::new(),
                        resource_pattern: None,
                        required_headers: Vec::new(),
                        created_by: ADMIN.to_string(),
                        parent_token_id: None,
                        delegation_depth: 0,
                        created_at: chrono::Utc::now(),
                        last_used_at: None,
                        expires_at: None,
                        revoked_at: None,
                        rotation_generation: 0,
                        rotated_at: None,
                        rotated_by: None,
                    })
                    .await
                    .unwrap();
                secrets.push(secret);
            }

            let (status, _) = fixture
                .delete(Some(tokens.clone()), "member-1")
                .await;

            assert_eq!(status, StatusCode::OK);
            assert!(
                tokens
                    .authenticate(&secrets[0])
                    .await
                    .is_none(),
                "the deleted user's token is revoked"
            );
            assert!(
                tokens
                    .authenticate(&secrets[1])
                    .await
                    .is_some(),
                "another user's token still works"
            );
        }

        #[tokio::test]
        async fn a_delete_whose_token_revocation_fails_answers_500_and_leaves_the_user_unchanged() {
            let fixture = fixture().await;
            fixture
                .member("oidc-1", UserStatus::Approved, true)
                .await;

            let (status, body) = fixture
                .delete(Some(RecordingTokens::new(true)), "oidc-1")
                .await;

            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(body.get("outcome").is_none());
            let stored = fixture
                .stored("oidc-1")
                .await
                .unwrap();
            assert_eq!(stored.status, UserStatus::Approved);
            assert!(stored.deleted_at.is_none());
        }

        #[tokio::test]
        async fn approving_a_kept_record_again_revokes_its_tokens_and_earlier_sessions() {
            let fixture = fixture().await;
            let member = fixture
                .member("oidc-1", UserStatus::Approved, true)
                .await;
            let earlier_session = fixture
                .sessions
                .create_session(member.username.clone(), member.user_id.clone())
                .await;
            fixture
                .storage
                .delete_user("oidc-1")
                .await
                .unwrap();
            let tokens = RecordingTokens::new(false);

            let status = fixture
                .set_status(Some(tokens.clone()), "oidc-1", "approved")
                .await;

            assert_eq!(status, StatusCode::OK);
            assert_eq!(tokens.revoked_for(), vec!["oidc-1".to_string()]);
            assert!(
                fixture
                    .sessions
                    .validate_session(&earlier_session)
                    .await
                    .is_none(),
                "a session from before the delete does not come back"
            );
            let approved = fixture
                .stored("oidc-1")
                .await
                .unwrap();
            assert_eq!(approved.status, UserStatus::Approved);
            assert!(approved.deleted_at.is_none());
        }

        #[tokio::test]
        async fn approving_a_disabled_user_who_was_not_deleted_revokes_nothing() {
            let fixture = fixture().await;
            fixture
                .member("disabled-1", UserStatus::Disabled, true)
                .await;
            let tokens = RecordingTokens::new(false);

            let status = fixture
                .set_status(Some(tokens.clone()), "disabled-1", "approved")
                .await;

            assert_eq!(status, StatusCode::OK);
            assert!(
                tokens
                    .revoked_for()
                    .is_empty()
            );
        }

        #[tokio::test]
        async fn an_approved_user_can_upload_an_avatar() {
            let fixture = fixture().await;
            fixture
                .member("member-1", UserStatus::Approved, false)
                .await;

            let status = fixture
                .upload_avatar("member-1")
                .await;

            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                fixture
                    .stored("member-1")
                    .await
                    .unwrap()
                    .avatar_path
                    .as_deref(),
                Some("avatars/member-1.png")
            );
            assert!(
                fixture
                    .avatar_file("member-1")
                    .exists()
            );
        }

        #[tokio::test]
        async fn an_avatar_uploaded_for_a_deleted_user_is_refused_and_its_file_removed() {
            let fixture = fixture().await;
            fixture
                .member("oidc-1", UserStatus::Approved, true)
                .await;
            fixture
                .storage
                .delete_user("oidc-1")
                .await
                .unwrap();

            let status = fixture
                .upload_avatar("oidc-1")
                .await;

            assert_eq!(status, StatusCode::FORBIDDEN);
            assert!(
                !fixture
                    .avatar_file("oidc-1")
                    .exists(),
                "the uploaded file does not stay"
            );
            assert!(
                fixture
                    .stored("oidc-1")
                    .await
                    .unwrap()
                    .avatar_path
                    .is_none()
            );
        }
    }
}
