use axum::{Extension, Json, extract::Path, http::StatusCode};

use super::NotificationStore;
use super::types::{CreateNotificationRequest, Notification, UpdateNotificationRequest, WelcomeTemplate};
use crate::auth::session::SessionManager;
use crate::auth_manager::middleware::extract_session_token_from_headers;

/// List all notifications for the current user
pub async fn list_notifications<S: NotificationStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(session_manager): Extension<std::sync::Arc<SessionManager>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<Notification>>, (StatusCode, String)> {
    // Get session token - if missing, return empty array
    let session_token = match extract_session_token_from_headers(&headers) {
        Some(token) => token,
        None => return Ok(Json(vec![])),
    };

    // Validate session and get user_id - if invalid, return empty array
    let (_username, user_id) = match session_manager
        .validate_session(&session_token)
        .await
    {
        Some(user) => user,
        None => {
            tracing::warn!("Invalid session token for notifications list");
            return Ok(Json(vec![]));
        }
    };

    tracing::info!("Listing notifications for user_id: {}", user_id);

    // Only return non-deleted notifications for this user
    let notifications = store
        .list_for_user(&user_id, false)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list notifications: {}", e)))?;

    tracing::info!("Found {} notifications for user_id: {}", notifications.len(), user_id);

    Ok(Json(notifications))
}

/// Get a notification by ID
pub async fn get_notification<S: NotificationStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(session_manager): Extension<std::sync::Arc<SessionManager>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Notification>, (StatusCode, String)> {
    let session_token = extract_session_token_from_headers(&headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing session token".to_string()))?;

    let (_username, user_id) = session_manager
        .validate_session(&session_token)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    let notification = store
        .get(&user_id, &id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get notification: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Notification not found".to_string()))?;

    Ok(Json(notification))
}

/// Create a new notification (admin only - for creating manual notifications)
pub async fn create_notification<S: NotificationStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(session_manager): Extension<std::sync::Arc<SessionManager>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CreateNotificationRequest>,
) -> Result<Json<Notification>, (StatusCode, String)> {
    let session_token = extract_session_token_from_headers(&headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing session token".to_string()))?;

    let (_username, user_id) = session_manager
        .validate_session(&session_token)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    let mut notification = Notification::new(
        crate::integrations::types::NotificationType::General,
        req.title,
        req.message,
        serde_json::json!({}),
    );
    notification.user_id = user_id;

    store
        .create(&notification)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store notification: {}", e)))?;

    Ok(Json(notification))
}

/// Update a notification (only status can be changed - mark as read)
pub async fn update_notification<S: NotificationStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(session_manager): Extension<std::sync::Arc<SessionManager>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<UpdateNotificationRequest>,
) -> Result<Json<Notification>, (StatusCode, String)> {
    let session_token = extract_session_token_from_headers(&headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing session token".to_string()))?;

    let (_username, user_id) = session_manager
        .validate_session(&session_token)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    let mut notification = store
        .get(&user_id, &id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get notification: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Notification not found".to_string()))?;

    // Only allow status changes (mark as read) - title and message are immutable
    if req.title.is_some() || req.message.is_some() {
        return Err((StatusCode::BAD_REQUEST, "Cannot modify notification title or message".to_string()));
    }

    if let Some(status) = req.status {
        notification.status = status;
    }

    notification.updated_at = chrono::Utc::now();

    store
        .update(&notification)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update notification: {}", e)))?;

    Ok(Json(notification))
}

/// Delete a notification (soft delete)
pub async fn delete_notification<S: NotificationStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(session_manager): Extension<std::sync::Arc<SessionManager>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let session_token = extract_session_token_from_headers(&headers)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing session token".to_string()))?;

    let (_username, user_id) = session_manager
        .validate_session(&session_token)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid session".to_string()))?;

    store
        .delete(&user_id, &id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete notification: {}", e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get count of unread notifications for the current user
pub async fn get_unread_count<S: NotificationStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(session_manager): Extension<std::sync::Arc<SessionManager>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Get session token - if missing, return 0
    let session_token = match extract_session_token_from_headers(&headers) {
        Some(token) => token,
        None => return Ok(Json(serde_json::json!({ "unread_count": 0 }))),
    };

    // Validate session and get user_id - if invalid, return 0
    let (_username, user_id) = match session_manager
        .validate_session(&session_token)
        .await
    {
        Some(user) => user,
        None => return Ok(Json(serde_json::json!({ "unread_count": 0 }))),
    };

    let count = store
        .count_unread(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to count unread notifications: {}", e)))?;

    Ok(Json(serde_json::json!({ "unread_count": count })))
}

/// Get the user welcome notification template (admin only)
pub async fn get_user_welcome_template<S: NotificationStore>(
    Extension(store): Extension<std::sync::Arc<S>>
) -> Result<Json<WelcomeTemplate>, (StatusCode, String)> {
    let template = store
        .get_user_welcome_template()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get welcome template: {}", e)))?;

    Ok(Json(template))
}

/// Set the user welcome notification template (admin only)
pub async fn set_user_welcome_template<S: NotificationStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Json(template): Json<WelcomeTemplate>,
) -> Result<StatusCode, (StatusCode, String)> {
    store
        .set_user_welcome_template(&template)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to set welcome template: {}", e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Send a welcome notification to a user (used during approval with custom message)
pub async fn send_user_welcome<S: NotificationStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Json(req): Json<serde_json::Value>,
) -> Result<StatusCode, (StatusCode, String)> {
    let user_id = req
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'user_id' field".to_string()))?;

    let title = req
        .get("title")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'title' field".to_string()))?;

    let message = req
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Missing 'message' field".to_string()))?;

    store
        .send_welcome_notification(user_id, title, message)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send welcome notification: {}", e)))?;

    Ok(StatusCode::NO_CONTENT)
}
