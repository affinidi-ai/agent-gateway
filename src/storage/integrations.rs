use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::path::PathBuf;
use uuid::Uuid;

use crate::storage::filesystem::{StorableEntity, StorageBackend, uncached_storage};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Integration {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub integration_type: String,
    /// Category determines which runtime variables are available (general, connection_point, user, gateway, surface)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Connection/authentication configuration (SMTP settings, webhook URLs, etc.)
    pub configuration: JsonValue,
    /// Message content template (subject, body, text, etc. with ${VARIABLE} placeholders)
    pub content: JsonValue,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

impl StorableEntity for Integration {
    fn id(&self) -> &str {
        &self.id
    }

    /// The `channel` category and `CHANNEL_*` variables were renamed to
    /// `surface` / `SURFACE_*`: move stored integrations onto the new names so
    /// their category and templates keep working.
    fn migrate_raw_json(value: &mut JsonValue) -> Result<bool> {
        let mut changed = false;
        if let Some(category) = value.get_mut("category")
            && category.as_str() == Some("channel")
        {
            *category = JsonValue::String("surface".to_string());
            changed = true;
        }
        for field in ["content", "configuration"] {
            if let Some(template) = value.get_mut(field) {
                changed |= rename_surface_variables(template);
            }
        }
        Ok(changed)
    }
}

fn rename_surface_variables(value: &mut JsonValue) -> bool {
    match value {
        JsonValue::String(text) if text.contains("${CHANNEL_") => {
            *text = text.replace("${CHANNEL_", "${SURFACE_");
            true
        }
        JsonValue::Array(items) => items
            .iter_mut()
            .fold(false, |changed, item| rename_surface_variables(item) | changed),
        JsonValue::Object(map) => map
            .values_mut()
            .fold(false, |changed, item| rename_surface_variables(item) | changed),
        _ => false,
    }
}

impl Integration {
    pub fn new(
        name: String,
        description: String,
        integration_type: String,
        configuration: JsonValue,
        content: JsonValue,
        status: String,
        category: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            tenant_id: None,
            name,
            description,
            integration_type,
            category,
            configuration,
            content,
            status,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

pub struct IntegrationStorage {
    storage: Box<dyn StorageBackend<Integration>>,
    storage_path: PathBuf,
}

impl IntegrationStorage {
    pub async fn new(storage_path: PathBuf) -> Result<Self> {
        let storage = uncached_storage(storage_path.clone(), "integration").await?;
        Ok(Self { storage, storage_path })
    }

    #[allow(dead_code)]
    pub fn get_storage_path(&self) -> &PathBuf {
        &self.storage_path
    }

    pub async fn save(
        &self,
        integration: &Integration,
    ) -> Result<()> {
        self.storage
            .save(integration)
            .await?;

        // Invalidate cache for this integration
        tokio::spawn({
            let id = integration.id.clone();
            async move {
                crate::integrations::cache::invalidate_integration_cache(&id).await;
            }
        });

        Ok(())
    }

    pub async fn load(
        &self,
        id: &str,
    ) -> Result<Integration> {
        self.storage
            .get(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Integration not found: {}", id))
    }

    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        // Check existence first for a clear error
        if !self
            .storage
            .exists(id)
            .await?
        {
            anyhow::bail!("Integration not found: {}", id);
        }

        self.storage
            .delete(id)
            .await?;

        // Invalidate cache for this integration
        tokio::spawn({
            let id = id.to_string();
            async move {
                crate::integrations::cache::invalidate_integration_cache(&id).await;
            }
        });

        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<Integration>> {
        let mut integrations = self
            .storage
            .list_all()
            .await?;

        // Sort by created_at descending (newest first)
        integrations.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(integrations)
    }

    pub async fn update(
        &self,
        id: &str,
        integration: &Integration,
    ) -> Result<()> {
        // Verify the integration exists first
        if !self
            .storage
            .exists(id)
            .await?
        {
            anyhow::bail!("Integration not found: {}", id);
        }

        // Save will also invalidate cache
        self.save(integration).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn migrate_raw_json_moves_channel_integrations_to_surface() {
        let mut stored = serde_json::json!({
            "category": "channel",
            "content": {
                "text": "Surface ${CHANNEL_NAME} (${CHANNEL_ID}) at ${TIMESTAMP}",
                "nested": [{ "id": "${CHANNEL_ID}" }],
                "channel": "#alerts"
            },
            "configuration": { "url": "https://example.test/${CHANNEL_ID}" }
        });

        assert!(Integration::migrate_raw_json(&mut stored).unwrap());
        assert_eq!(
            stored,
            serde_json::json!({
                "category": "surface",
                "content": {
                    "text": "Surface ${SURFACE_NAME} (${SURFACE_ID}) at ${TIMESTAMP}",
                    "nested": [{ "id": "${SURFACE_ID}" }],
                    "channel": "#alerts"
                },
                "configuration": { "url": "https://example.test/${SURFACE_ID}" }
            })
        );
    }

    #[tokio::test]
    async fn the_store_migrates_a_stored_channel_integration_on_load_and_list() {
        let dir = tempdir().unwrap();
        let storage = IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let mut legacy = serde_json::to_value(Integration::new(
            "Legacy surface alerts".to_string(),
            String::new(),
            "webhook".to_string(),
            serde_json::json!({}),
            serde_json::json!({ "text": "${CHANNEL_NAME} changed" }),
            "active".to_string(),
            None,
        ))
        .unwrap();
        legacy["category"] = serde_json::json!("channel");
        let id = legacy["id"]
            .as_str()
            .unwrap()
            .to_string();
        let path = dir
            .path()
            .join(format!("{id}.json"));
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();

        let loaded = storage
            .load(&id)
            .await
            .unwrap();
        assert_eq!(loaded.category.as_deref(), Some("surface"));
        assert_eq!(loaded.content["text"], "${SURFACE_NAME} changed");

        let listed = storage.list().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].category.as_deref(), Some("surface"));

        let on_disk: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(on_disk["category"], "surface", "the migrated record is persisted");
        assert_eq!(on_disk["content"]["text"], "${SURFACE_NAME} changed");
    }

    #[test]
    fn migrate_raw_json_leaves_other_integrations_untouched() {
        let original = serde_json::json!({
            "category": "gateway",
            "content": { "text": "${GATEWAY_NAME} on channel #ops", "channel": "#ops" },
            "configuration": {}
        });
        let mut stored = original.clone();

        assert!(!Integration::migrate_raw_json(&mut stored).unwrap());
        assert_eq!(stored, original);
    }

    #[test]
    fn test_notifier_creation() {
        let config = serde_json::json!({
            "to": ["admin@example.com"],
            "from": "gateway@example.com"
        });

        let integration = Integration::new(
            "Test Integration".to_string(),
            "Test description".to_string(),
            "email".to_string(),
            config.clone(),
            serde_json::json!({}),
            "active".to_string(),
            None,
        );

        assert_eq!(integration.name, "Test Integration");
        assert_eq!(integration.integration_type, "email");
        assert_eq!(integration.configuration, config);
        assert!(!integration.id.is_empty());
    }

    #[tokio::test]
    async fn test_storage_operations() {
        let dir = tempdir().unwrap();
        let storage = IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .unwrap();

        let config = serde_json::json!({"key": "value"});
        let integration = Integration::new(
            "Test".to_string(),
            "Desc".to_string(),
            "email".to_string(),
            config,
            serde_json::json!({}),
            "active".to_string(),
            None,
        );

        // Save
        storage
            .save(&integration)
            .await
            .unwrap();

        // Load
        let loaded = storage
            .load(&integration.id)
            .await
            .unwrap();
        assert_eq!(loaded.name, integration.name);

        // List
        let all = storage.list().await.unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        storage
            .delete(&integration.id)
            .await
            .unwrap();
        assert!(
            storage
                .load(&integration.id)
                .await
                .is_err()
        );
    }
}
