//! Notification Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::types::{Notification, WelcomeTemplate};

/// Trait for storing notification records
#[async_trait]
pub trait NotificationStore: Send + Sync {
    /// Create a notification
    async fn create(
        &self,
        notification: &Notification,
    ) -> Result<()>;

    /// Get a notification by ID for a specific user
    async fn get(
        &self,
        user_id: &str,
        id: &str,
    ) -> Result<Option<Notification>>;

    /// List all notifications for a specific user (excluding deleted ones by default)
    async fn list_for_user(
        &self,
        user_id: &str,
        include_deleted: bool,
    ) -> Result<Vec<Notification>>;

    /// Delete a notification by ID for a specific user (soft delete - marks as deleted)
    async fn delete(
        &self,
        user_id: &str,
        id: &str,
    ) -> Result<()>;

    /// Update a notification
    async fn update(
        &self,
        notification: &Notification,
    ) -> Result<()>;

    /// Count unread notifications for a specific user (status = New)
    async fn count_unread(
        &self,
        user_id: &str,
    ) -> Result<usize>;

    /// Create welcome notification for first admin
    #[allow(dead_code)]
    async fn create_admin_welcome_notification(
        &self,
        user_id: &str,
    ) -> Result<()>;

    /// Create welcome notification for approved user using template
    async fn send_user_welcome_notification(
        &self,
        user_id: &str,
    ) -> Result<()>;

    /// Get user welcome message template (for new user approvals)
    async fn get_user_welcome_template(&self) -> Result<WelcomeTemplate>;

    /// Set user welcome message template (for new user approvals)
    async fn set_user_welcome_template(
        &self,
        template: &WelcomeTemplate,
    ) -> Result<()>;

    /// Send a welcome notification to a user (used when approving)
    async fn send_welcome_notification(
        &self,
        user_id: &str,
        title: &str,
        message: &str,
    ) -> Result<()>;
}
