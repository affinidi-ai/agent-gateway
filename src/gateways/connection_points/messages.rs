//! Message storage for incoming DIDComm messages received by connection points

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

/// A received DIDComm message with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceivedMessage {
    /// Unique message ID
    pub id: String,

    /// Connection point ID this message was received on
    pub connection_point_id: String,

    /// Gateway ID
    pub gateway_id: String,

    /// DIDComm message type
    pub message_type: String,

    /// Message ID from the DIDComm message
    pub didcomm_message_id: String,

    /// Thread ID from the DIDComm message (for correlation)
    pub didcomm_thid: Option<String>,

    /// Sender DID (from metadata)
    pub from_did: Option<String>,

    /// Recipient DID(s)
    pub to_dids: Vec<String>,

    /// DIDComm `created_time` of the envelope (seconds since the epoch), when the sender set it
    #[serde(default)]
    pub created_time: Option<u64>,

    /// DIDComm `expires_time` of the envelope (seconds since the epoch), when the sender set it
    #[serde(default)]
    pub expires_time: Option<u64>,

    /// Full DIDComm message body
    pub message_body: serde_json::Value,

    /// Message metadata from unpacking
    pub metadata: MessageMetadata,

    /// When this message was received
    pub received_at: DateTime<Utc>,

    /// Whether the message has been read/processed
    pub read: bool,

    /// Context data for message processing (not persisted)
    #[serde(skip)]
    pub context: std::collections::HashMap<String, serde_json::Value>,
}

/// Metadata from DIDComm message unpacking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    /// Whether the message was encrypted
    pub encrypted: bool,

    /// Whether the message was authenticated
    pub authenticated: bool,

    /// Sender's key ID (if available)
    pub from_key: Option<String>,

    /// Additional metadata fields
    pub extra: serde_json::Value,
}

impl ReceivedMessage {
    /// Create a new received message
    pub fn new(
        connection_point_id: String,
        gateway_id: String,
        message_type: String,
        didcomm_message_id: String,
        didcomm_thid: Option<String>,
        from_did: Option<String>,
        to_dids: Vec<String>,
        created_time: Option<u64>,
        expires_time: Option<u64>,
        message_body: serde_json::Value,
        metadata: MessageMetadata,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            connection_point_id,
            gateway_id,
            message_type,
            didcomm_message_id,
            didcomm_thid,
            from_did,
            to_dids,
            created_time,
            expires_time,
            message_body,
            metadata,
            received_at: Utc::now(),
            read: false,
            context: std::collections::HashMap::new(),
        }
    }

    /// Add context data for message processing
    #[allow(dead_code)]
    pub fn with_context(
        mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Self {
        self.context
            .insert(key.into(), value);
        self
    }

    /// Mark message as read
    pub fn mark_read(&mut self) {
        self.read = true;
    }
}

/// Storage for received messages
pub struct MessageStore {
    base_path: PathBuf,
}

impl MessageStore {
    /// Create a new message store
    pub async fn new(base_path: PathBuf) -> Result<Self> {
        fs::create_dir_all(&base_path).await?;
        Ok(Self { base_path })
    }

    /// Store a received message
    pub async fn store(
        &self,
        _message: &ReceivedMessage,
    ) -> Result<()> {
        // Filesystem persistence of messages was removed; this is now a no-op.
        Ok(())
    }

    /// Get a message by ID
    pub async fn get(
        &self,
        connection_point_id: &str,
        message_id: &str,
    ) -> Result<Option<ReceivedMessage>> {
        crate::storage::validate_storage_id(connection_point_id)
            .map_err(|e| anyhow::anyhow!("invalid connection_point_id: {e}"))?;
        crate::storage::validate_storage_id(message_id).map_err(|e| anyhow::anyhow!("invalid message_id: {e}"))?;

        let file_path = self
            .base_path
            .join(connection_point_id)
            .join(format!("{}.json", message_id));

        if !file_path.exists() {
            return Ok(None);
        }

        let contents = fs::read_to_string(file_path).await?;
        let message: ReceivedMessage = serde_json::from_str(&contents)?;
        Ok(Some(message))
    }

    /// List all messages for a connection point
    pub async fn list_by_connection_point(
        &self,
        connection_point_id: &str,
    ) -> Result<Vec<ReceivedMessage>> {
        crate::storage::validate_storage_id(connection_point_id)
            .map_err(|e| anyhow::anyhow!("invalid connection_point_id: {e}"))?;

        let cp_dir = self
            .base_path
            .join(connection_point_id);

        if !cp_dir.exists() {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        let mut entries = fs::read_dir(cp_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path
                .extension()
                .and_then(|s| s.to_str())
                == Some("json")
                && let Ok(contents) = fs::read_to_string(&path).await
                && let Ok(message) = serde_json::from_str::<ReceivedMessage>(&contents)
            {
                messages.push(message);
            }
        }

        // Sort by received_at descending (newest first)
        messages.sort_by(|a, b| {
            b.received_at
                .cmp(&a.received_at)
        });

        Ok(messages)
    }

    /// Mark a message as read
    pub async fn mark_read(
        &self,
        connection_point_id: &str,
        message_id: &str,
    ) -> Result<()> {
        if let Some(mut message) = self
            .get(connection_point_id, message_id)
            .await?
        {
            message.mark_read();
            self.store(&message).await?;
        }
        Ok(())
    }

    /// Delete a message
    pub async fn delete(
        &self,
        connection_point_id: &str,
        message_id: &str,
    ) -> Result<()> {
        crate::storage::validate_storage_id(connection_point_id)
            .map_err(|e| anyhow::anyhow!("invalid connection_point_id: {e}"))?;
        crate::storage::validate_storage_id(message_id).map_err(|e| anyhow::anyhow!("invalid message_id: {e}"))?;

        let file_path = self
            .base_path
            .join(connection_point_id)
            .join(format!("{}.json", message_id));

        if file_path.exists() {
            fs::remove_file(file_path).await?;
        }

        Ok(())
    }

    /// Delete all messages for a connection point
    #[allow(dead_code)]
    pub async fn delete_all(
        &self,
        connection_point_id: &str,
    ) -> Result<()> {
        crate::storage::validate_storage_id(connection_point_id)
            .map_err(|e| anyhow::anyhow!("invalid connection_point_id: {e}"))?;

        let cp_dir = self
            .base_path
            .join(connection_point_id);

        if cp_dir.exists() {
            fs::remove_dir_all(cp_dir).await?;
        }

        Ok(())
    }

    /// Get unread message count for a connection point
    pub async fn get_unread_count(
        &self,
        connection_point_id: &str,
    ) -> Result<usize> {
        let messages = self
            .list_by_connection_point(connection_point_id)
            .await?;
        Ok(messages
            .iter()
            .filter(|m| !m.read)
            .count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn make_store() -> (MessageStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = MessageStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        (store, dir)
    }

    // ============================================================================
    // Path traversal prevention tests
    // ============================================================================

    #[tokio::test]
    async fn test_get_rejects_traversal_in_connection_point_id() {
        let (store, _dir) = make_store().await;
        let err = store
            .get("../../etc", "msg-1")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid connection_point_id")
        );
    }

    #[tokio::test]
    async fn test_get_rejects_traversal_in_message_id() {
        let (store, _dir) = make_store().await;
        let err = store
            .get("cp-1", "../../etc/passwd")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid message_id")
        );
    }

    #[tokio::test]
    async fn test_get_rejects_absolute_connection_point_id() {
        let (store, _dir) = make_store().await;
        // Axum decodes %2F-prefixed paths to absolute paths like /_storage/gateways
        let err = store
            .get("/_storage/gateways", "msg-1")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid connection_point_id")
        );
    }

    #[tokio::test]
    async fn test_get_rejects_slash_encoded_message_id() {
        let (store, _dir) = make_store().await;
        let err = store
            .get("cp-1", "/etc/shadow")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid message_id")
        );
    }

    #[tokio::test]
    async fn test_list_rejects_traversal_in_connection_point_id() {
        let (store, _dir) = make_store().await;
        let err = store
            .list_by_connection_point("../secret")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid connection_point_id")
        );
    }

    #[tokio::test]
    async fn test_delete_rejects_traversal_in_connection_point_id() {
        let (store, _dir) = make_store().await;
        let err = store
            .delete("../../etc", "msg-1")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid connection_point_id")
        );
    }

    #[tokio::test]
    async fn test_delete_rejects_traversal_in_message_id() {
        let (store, _dir) = make_store().await;
        let err = store
            .delete("cp-1", "../../etc/crontab")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid message_id")
        );
    }

    #[tokio::test]
    async fn test_delete_all_rejects_traversal() {
        let (store, _dir) = make_store().await;
        let err = store
            .delete_all("../other-tenant")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid connection_point_id")
        );
    }

    #[tokio::test]
    async fn test_get_accepts_valid_ids() {
        let (store, _dir) = make_store().await;
        // Returns Ok(None) — file does not exist — but validation passes
        let result = store
            .get("cp-abc123", "msg-uuid-1234")
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
