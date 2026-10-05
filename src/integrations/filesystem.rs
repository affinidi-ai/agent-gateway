pub use super::NotificationStore;
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::info;

use super::types::{Notification, WelcomeTemplate};
use crate::auth::storage::PasskeyStorage;

/// Implement StorableEntity for Notification to use generic filesystem storage
impl StorableEntity for Notification {
    fn id(&self) -> &str {
        &self.id
    }
}

// Default admin welcome template
const DEFAULT_ADMIN_WELCOME: &str = include_str!("admin_welcome.json");

// Default user welcome template
const DEFAULT_USER_WELCOME: &str = include_str!("user_welcome.json");

/// Filesystem-based implementation of NotificationStore
pub struct FileSystemNotificationStore {
    storage: Box<dyn StorageBackend<Notification>>,
    admin_welcome_path: PathBuf,
    user_welcome_path: PathBuf,
}

impl FileSystemNotificationStore {
    /// Create a new FileSystemNotificationStore
    pub async fn new(
        storage_dir: PathBuf,
        templates_dir: PathBuf,
        _auth_storage: Option<&PasskeyStorage>,
    ) -> Result<Self> {
        // Create storage directory if it doesn't exist
        tokio::fs::create_dir_all(&storage_dir).await?;

        // Create templates directory if it doesn't exist
        tokio::fs::create_dir_all(&templates_dir).await?;

        let admin_welcome_path = templates_dir.join("admin_welcome.json");
        let user_welcome_path = templates_dir.join("user_welcome.json");

        // Initialize generic storage
        let storage = cached_storage(storage_dir, "notification").await?;

        let store = Self {
            storage,
            admin_welcome_path,
            user_welcome_path,
        };

        // Initialize default templates if they don't exist
        if !store
            .admin_welcome_path
            .exists()
        {
            tokio::fs::write(&store.admin_welcome_path, DEFAULT_ADMIN_WELCOME).await?;
        }
        if !store
            .user_welcome_path
            .exists()
        {
            tokio::fs::write(&store.user_welcome_path, DEFAULT_USER_WELCOME).await?;
        }

        Ok(store)
    }
}

#[async_trait]
impl NotificationStore for FileSystemNotificationStore {
    async fn create(
        &self,
        notification: &Notification,
    ) -> Result<()> {
        self.storage
            .save(notification)
            .await
    }

    async fn get(
        &self,
        user_id: &str,
        id: &str,
    ) -> Result<Option<Notification>> {
        if let Some(notification) = self.storage.get(id).await?
            && notification.user_id == user_id
        {
            return Ok(Some(notification));
        }
        Ok(None)
    }

    async fn list_for_user(
        &self,
        user_id: &str,
        include_deleted: bool,
    ) -> Result<Vec<Notification>> {
        let all_notifications = self
            .storage
            .list_all()
            .await?;

        info!("Storage contains {} notifications total", all_notifications.len());
        for notif in all_notifications.iter() {
            info!("  Notification {}: user_id={}, status={:?}", notif.id, notif.user_id, notif.status);
        }

        let mut notifications: Vec<Notification> = all_notifications
            .into_iter()
            .filter(|n| n.user_id == user_id)
            .collect();

        info!("Found {} notifications matching user_id: {}", notifications.len(), user_id);

        // Filter out deleted notifications if requested
        if !include_deleted {
            notifications.retain(|n| n.status != super::types::NotificationStatus::Deleted);
        }

        // Sort by created_at descending (newest first)
        notifications.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(notifications)
    }

    async fn delete(
        &self,
        user_id: &str,
        id: &str,
    ) -> Result<()> {
        if let Some(notification) = self.storage.get(id).await? {
            // Verify ownership
            if notification.user_id != user_id {
                return Err(anyhow::anyhow!("Unauthorized: notification belongs to different user"));
            }

            let mut notification = notification;
            // Soft delete - mark as deleted
            notification.status = super::types::NotificationStatus::Deleted;
            notification.updated_at = chrono::Utc::now();

            // Write to storage
            self.storage
                .save(&notification)
                .await?;
        }

        Ok(())
    }

    async fn update(
        &self,
        notification: &Notification,
    ) -> Result<()> {
        self.storage
            .save(notification)
            .await
    }

    async fn count_unread(
        &self,
        user_id: &str,
    ) -> Result<usize> {
        let all_notifications = self
            .storage
            .list_all()
            .await?;
        let count = all_notifications
            .iter()
            .filter(|n| n.user_id == user_id && n.status == super::types::NotificationStatus::New)
            .count();
        Ok(count)
    }

    async fn create_admin_welcome_notification(
        &self,
        user_id: &str,
    ) -> Result<()> {
        info!("Creating admin welcome notification for user_id: {}", user_id);

        // Load admin welcome template
        let content = tokio::fs::read_to_string(&self.admin_welcome_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read admin welcome template: {}", e))?;

        let template: WelcomeTemplate = serde_json::from_str(&content)?;

        info!("Admin welcome template loaded: title='{}', message length={}", template.title, template.message.len());

        let mut notification = Notification::new(
            crate::integrations::types::NotificationType::System,
            template.title,
            template.message,
            serde_json::json!({}),
        );
        notification.user_id = user_id.to_string();

        info!("Storing admin welcome notification with id: {}", notification.id);
        self.create(&notification)
            .await?;
        info!("Admin welcome notification stored successfully");
        Ok(())
    }

    async fn send_user_welcome_notification(
        &self,
        user_id: &str,
    ) -> Result<()> {
        info!("Creating user welcome notification for user_id: {}", user_id);

        // Load user welcome template
        let content = tokio::fs::read_to_string(&self.user_welcome_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read user welcome template: {}", e))?;

        let template: WelcomeTemplate = serde_json::from_str(&content)?;

        info!("User welcome template loaded: title='{}', message length={}", template.title, template.message.len());

        let mut notification = Notification::new(
            crate::integrations::types::NotificationType::System,
            template.title,
            template.message,
            serde_json::json!({}),
        );
        notification.user_id = user_id.to_string();

        info!("Storing user welcome notification with id: {}", notification.id);
        self.create(&notification)
            .await?;
        info!("User welcome notification stored successfully");
        Ok(())
    }

    async fn get_user_welcome_template(&self) -> Result<WelcomeTemplate> {
        let content = tokio::fs::read_to_string(&self.user_welcome_path).await?;
        let template: WelcomeTemplate = serde_json::from_str(&content)?;
        Ok(template)
    }

    async fn set_user_welcome_template(
        &self,
        template: &WelcomeTemplate,
    ) -> Result<()> {
        let content = serde_json::to_string_pretty(template)?;
        tokio::fs::write(&self.user_welcome_path, content).await?;
        Ok(())
    }

    async fn send_welcome_notification(
        &self,
        user_id: &str,
        title: &str,
        message: &str,
    ) -> Result<()> {
        let mut notification = Notification::new(
            crate::integrations::types::NotificationType::System,
            title.to_string(),
            message.to_string(),
            serde_json::json!({}),
        );
        notification.user_id = user_id.to_string();
        self.create(&notification)
            .await
    }
}
