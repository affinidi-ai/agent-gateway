use serde::{Deserialize, Serialize};

/// Represents the type of notification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NotificationType {
    /// General notification
    General,
    /// Gateway connection request needing approval
    GatewayConnectionRequest,
    /// System notification
    System,
}

/// Represents a specific action associated with new user registration notification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationAction {
    /// New user awaiting approval
    UserApproval,
}

/// Represents the status of a notification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum NotificationStatus {
    /// New, unread notification
    #[default]
    New,
    /// Read notification
    Read,
    /// Deleted notification (soft delete)
    Deleted,
}

/// Represents a notification record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    /// Unique identifier for this notification
    pub id: String,

    /// User ID this notification is for
    pub user_id: String,

    /// Type of notification
    #[serde(default = "default_notification_type")]
    pub notification_type: NotificationType,

    /// Notification title
    pub title: String,

    /// Notification message body
    pub message: String,

    /// Additional metadata specific to the notification type
    #[serde(default)]
    pub metadata: serde_json::Value,

    /// Status of the notification
    pub status: NotificationStatus,

    /// Timestamp when this notification was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when this notification was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn default_notification_type() -> NotificationType {
    NotificationType::General
}

impl Notification {
    pub fn new(
        notification_type: NotificationType,
        title: String,
        message: String,
        metadata: serde_json::Value,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: "admin".to_string(), // Default to admin for now
            notification_type,
            title,
            message,
            metadata,
            status: NotificationStatus::New,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Request body for creating a new notification
#[derive(Debug, Deserialize)]
pub struct CreateNotificationRequest {
    pub title: String,
    pub message: String,
}

/// Request body for updating a notification
#[derive(Debug, Deserialize)]
pub struct UpdateNotificationRequest {
    pub title: Option<String>,
    pub message: Option<String>,
    pub status: Option<NotificationStatus>,
}

/// Welcome message template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeTemplate {
    pub title: String,
    pub message: String,
}
