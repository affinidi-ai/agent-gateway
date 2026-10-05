use axum::extract::Multipart;
use axum::{Extension, Json, extract::Path, http::StatusCode};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use super::types::{UpdateProfileRequest, UpdateUserRequest, User};
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
            users.push(User {
                username: user_data.username,
                user_id: user_data.user_id,
                role: user_data.role,
                status: user_data.status,
                is_primary: user_data.is_primary,
                created_at: user_data.created_at,
                updated_at: user_data.updated_at,
                first_name: user_data.first_name,
                last_name: user_data.last_name,
                email: user_data.email,
                department: user_data.department,
                job_title: user_data.job_title,
                avatar_path: user_data.avatar_path,
                last_logged_in: user_data.last_logged_in,
            });
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

    // Trigger user.accessed integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        let notif = notif.clone();
        let user_clone = user_data.clone();
        tokio::spawn(async move {
            crate::integrations::trigger_user_accessed(notif.as_ref(), &user_clone).await;
        });
        if let Some(metrics_store) = metrics_store {
            spawn_record_user_event(metrics_store, "accessed".to_string(), user_data.role.clone());
        }
    }

    Ok(Json(User {
        username: user_data.username,
        user_id: user_data.user_id,
        role: user_data.role,
        status: user_data.status,
        is_primary: user_data.is_primary,
        created_at: user_data.created_at,
        updated_at: user_data.updated_at,
        first_name: user_data.first_name,
        last_name: user_data.last_name,
        email: user_data.email,
        department: user_data.department,
        job_title: user_data.job_title,
        avatar_path: user_data.avatar_path,
        last_logged_in: user_data.last_logged_in,
    }))
}

/// Update a user (role and/or status)
pub async fn update_user(
    Extension(metrics_store): Extension<Option<Arc<MetricsStore>>>,
    Extension(caller_user_id): Extension<String>,
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<std::sync::Arc<RbacConfig>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(session_manager): Extension<std::sync::Arc<crate::auth::session::SessionManager>>,
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

    // Update the user
    storage
        .update_user(&user_before.username, req.role.clone(), req.status.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update user: {}", e)))?;

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
        tracing::info!(
            "User approval detected - will send welcome notification to {} (user_id: {})",
            user_data.username,
            user_id
        );
        if let Some(notif_store) = &notification_store {
            use crate::integrations::NotificationStore;
            match notif_store
                .send_user_welcome_notification(&user_data.user_id)
                .await
            {
                Ok(_) => tracing::info!(
                    "Sent welcome notification to newly approved user: {} (user_id: {})",
                    user_data.username,
                    user_id
                ),
                Err(e) => tracing::error!(
                    "Failed to send welcome notification to {} (user_id: {}): {}",
                    user_data.username,
                    user_id,
                    e
                ),
            }
            // Trigger user.approved integration
            let notif = notif_store.clone();
            let user_clone = user_data.clone();
            tokio::spawn(async move {
                crate::integrations::trigger_user_approved(notif.as_ref(), &user_clone).await;
            });
            if let Some(metrics_store) = metrics_store.clone() {
                spawn_record_user_event(metrics_store, "approved".to_string(), user_data.role.clone());
            }
        } else {
            tracing::error!("Notification store not available - cannot send welcome notification");
        }
    }

    // Trigger user.updated integration for any update
    if let Some(notif_store) = &notification_store {
        let notif = notif_store.clone();
        let old_user = user_before.clone();
        let new_user = user_data.clone();
        tokio::spawn(async move {
            crate::integrations::trigger_user_updated(notif.as_ref(), &old_user, &new_user).await;
        });
        if let Some(metrics_store) = metrics_store {
            spawn_record_user_event(metrics_store, "updated".to_string(), user_data.role.clone());
        }
    }

    Ok(Json(User {
        username: user_data.username,
        user_id: user_data.user_id,
        role: user_data.role,
        status: user_data.status,
        is_primary: user_data.is_primary,
        created_at: user_data.created_at,
        updated_at: user_data.updated_at,
        first_name: user_data.first_name,
        last_name: user_data.last_name,
        email: user_data.email,
        department: user_data.department,
        job_title: user_data.job_title,
        avatar_path: user_data.avatar_path,
        last_logged_in: user_data.last_logged_in,
    }))
}

/// Delete a user
pub async fn delete_user(
    Extension(metrics_store): Extension<Option<Arc<MetricsStore>>>,
    Extension(caller_user_id): Extension<String>,
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<std::sync::Arc<RbacConfig>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(session_manager): Extension<std::sync::Arc<crate::auth::session::SessionManager>>,
    Path(user_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
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

    // Trigger user.deleted integration before deletion
    if let Some(notif_store) = &notification_store {
        let notif = notif_store.clone();
        let user_clone = user_data.clone();
        tokio::spawn(async move {
            crate::integrations::trigger_user_deleted(notif.as_ref(), &user_clone).await;
        });
    }

    // Permanently delete the user
    storage
        .delete_user(&user_data.username)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete user: {}", e)))?;

    // Revoke any active sessions so the deleted account cannot continue
    // operating with previously issued bearer tokens.
    let revoked = session_manager
        .remove_sessions_for_user(&user_id)
        .await;
    if revoked > 0 {
        tracing::info!("Revoked {} active session(s) for deleted user_id={}", revoked, user_id);
    }
    if let Some(metrics_store) = metrics_store {
        spawn_record_user_event(metrics_store, "deleted".to_string(), user_data.role.clone());
    }

    Ok(StatusCode::NO_CONTENT)
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

    Ok(Json(User {
        username: user_data.username,
        user_id: user_data.user_id,
        role: user_data.role,
        status: user_data.status,
        is_primary: user_data.is_primary,
        created_at: user_data.created_at,
        updated_at: user_data.updated_at,
        first_name: user_data.first_name,
        last_name: user_data.last_name,
        email: user_data.email,
        department: user_data.department,
        job_title: user_data.job_title,
        avatar_path: user_data.avatar_path,
        last_logged_in: user_data.last_logged_in,
    }))
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

    Ok(Json(User {
        username: user_data.username,
        user_id: user_data.user_id,
        role: user_data.role,
        status: user_data.status,
        is_primary: user_data.is_primary,
        created_at: user_data.created_at,
        updated_at: user_data.updated_at,
        first_name: user_data.first_name,
        last_name: user_data.last_name,
        email: user_data.email,
        department: user_data.department,
        job_title: user_data.job_title,
        avatar_path: user_data.avatar_path,
        last_logged_in: user_data.last_logged_in,
    }))
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

    // Update user profile with avatar path
    let relative_avatar_path = format!("avatars/{}", filename);
    storage
        .update_profile(&user_id, None, None, None, None, None, Some(relative_avatar_path.clone()))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update profile with avatar: {}", e)))?;

    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load updated user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(User {
        username: user_data.username,
        user_id: user_data.user_id,
        role: user_data.role,
        status: user_data.status,
        is_primary: user_data.is_primary,
        created_at: user_data.created_at,
        updated_at: user_data.updated_at,
        first_name: user_data.first_name,
        last_name: user_data.last_name,
        email: user_data.email,
        department: user_data.department,
        job_title: user_data.job_title,
        avatar_path: user_data.avatar_path,
        last_logged_in: user_data.last_logged_in,
    }))
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
}
