//! Filesystem-backed storage for Agent Surface configurations

use super::AgentSurfaceStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::info;

use crate::audit::context::current_actor;
use crate::audit::policy_changes;
use crate::config::agent_surface::AgentSurface;
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// Filesystem-based implementation of AgentSurfaceStore with in-memory cache
pub struct FileSystemAgentSurfaceStore {
    storage: Box<dyn StorageBackend<AgentSurface>>,
    /// Held from reading a surface before a write to the write itself, so the
    /// policy changes a write records are relative to the surface it replaced.
    writes: tokio::sync::Mutex<()>,
}

impl FileSystemAgentSurfaceStore {
    /// Create a new FileSystemAgentSurfaceStore with in-memory cache
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        info!("Loading agent surfaces from: {}", storage_dir.display());
        let storage = cached_storage(storage_dir, "agent_surface").await?;
        let count = storage
            .list_all()
            .await?
            .len();
        info!("Loaded {} agent surface(s)", count);
        Ok(Self {
            storage,
            writes: tokio::sync::Mutex::new(()),
        })
    }

    pub fn subscribe(
        &self
    ) -> Option<tokio::sync::broadcast::Receiver<crate::storage::filesystem::StorageEvent<AgentSurface>>> {
        self.storage.subscribe()
    }

    /// Reconcile the in-memory cache with the shared-storage directory, so a
    /// node promoted from standby recompiles surface policies from the active
    /// writer's latest surfaces rather than a stale boot snapshot.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }

    /// The stored surface a management request is about to change, so its
    /// policy attachments can be compared after the write. Not read outside
    /// one, or inside one under `without_actor` (a config reload), so `None`
    /// means either a new surface or a write that records nothing;
    /// `surface_written` checks the actor again and records nothing for the
    /// second.
    async fn before_change(
        &self,
        surface_id: &str,
    ) -> Option<AgentSurface> {
        current_actor()?;
        self.storage
            .get(surface_id)
            .await
            .ok()
            .flatten()
    }
}

#[async_trait]
impl AgentSurfaceStore for FileSystemAgentSurfaceStore {
    async fn save(
        &self,
        surface: &AgentSurface,
    ) -> Result<()> {
        let write = self.writes.lock().await;
        let before = self
            .before_change(&surface.surface_id)
            .await;
        self.storage
            .save(surface)
            .await?;
        drop(write);
        crate::mcp::subscriptions::invalidate_access(crate::mcp::subscriptions::AccessScope::Surface(
            surface.surface_id.clone(),
        ));
        policy_changes::surface_written(before.as_ref(), Some(surface)).await;
        Ok(())
    }

    async fn get(
        &self,
        surface_id: &str,
    ) -> Result<Option<AgentSurface>> {
        self.storage
            .get(surface_id)
            .await
    }

    async fn list_all(&self) -> Result<Vec<AgentSurface>> {
        self.storage.list_all().await
    }

    async fn delete(
        &self,
        surface_id: &str,
    ) -> Result<()> {
        let write = self.writes.lock().await;
        let before = self
            .before_change(surface_id)
            .await;
        self.storage
            .delete(surface_id)
            .await?;
        drop(write);
        crate::mcp::subscriptions::invalidate_access(crate::mcp::subscriptions::AccessScope::Surface(
            surface_id.to_string(),
        ));
        policy_changes::surface_written(before.as_ref(), None).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::context::in_management_request;
    use crate::audit::events::Actor;
    use crate::audit::producer::capture;
    use crate::delegation_vault::audit::action_category;

    fn surface(policy: &str) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": "s-1",
            "name": "Orders",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/orders", "protocol": "a2a" },
            "target": { "endpoint": "https://upstream", "policy": { "policy_definition_id": policy } },
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn a_management_request_records_the_policies_its_writes_attach_and_detach() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemAgentSurfaceStore::new(dir.path().to_path_buf())
            .await
            .unwrap();

        let ((), records) = capture(in_management_request(Actor::user("u-1"), async {
            store
                .save(&surface("a"))
                .await
                .unwrap();
            store
                .save(&surface("b"))
                .await
                .unwrap();
            store
                .delete("s-1")
                .await
                .unwrap();
        }))
        .await;

        let changes: Vec<_> = records
            .iter()
            .map(|record| {
                let json = serde_json::to_value(&record.event).unwrap();
                let category = action_category(&record.event);
                (category, json[category]["policy_definition_id"].clone())
            })
            .collect();
        assert_eq!(
            changes,
            vec![
                ("policy_attached", serde_json::json!("a")),
                ("policy_detached", serde_json::json!("a")),
                ("policy_attached", serde_json::json!("b")),
                ("policy_detached", serde_json::json!("b")),
            ]
        );
    }

    #[tokio::test]
    async fn writes_outside_a_management_request_record_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemAgentSurfaceStore::new(dir.path().to_path_buf())
            .await
            .unwrap();

        let ((), records) = capture(async {
            store
                .save(&surface("a"))
                .await
                .unwrap();
        })
        .await;

        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn the_gateways_own_writes_inside_a_management_request_record_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemAgentSurfaceStore::new(dir.path().to_path_buf())
            .await
            .unwrap();

        let ((), records) = capture(in_management_request(
            Actor::user("u-1"),
            crate::audit::context::without_actor(async {
                store
                    .save(&surface("a"))
                    .await
                    .unwrap();
            }),
        ))
        .await;

        assert!(records.is_empty(), "a config reload's writes are not user changes: {records:?}");
    }

    #[tokio::test]
    async fn concurrent_writes_to_one_surface_record_a_chain_of_changes() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemAgentSurfaceStore::new(dir.path().to_path_buf())
            .await
            .unwrap();

        let ((), records) = capture(in_management_request(Actor::user("u-1"), async {
            store
                .save(&surface("a"))
                .await
                .unwrap();
            let (b, c) = (surface("b"), surface("c"));
            let (first, second) = tokio::join!(store.save(&b), store.save(&c));
            first.unwrap();
            second.unwrap();
        }))
        .await;

        let ids = |category: &str| -> Vec<String> {
            records
                .iter()
                .filter(|record| action_category(&record.event) == category)
                .map(|record| {
                    serde_json::to_value(&record.event).unwrap()[category]["policy_definition_id"]
                        .as_str()
                        .unwrap()
                        .to_string()
                })
                .collect()
        };
        let (attached, detached) = (ids("policy_attached"), ids("policy_detached"));
        assert_eq!(attached.len(), 3, "{records:?}");
        assert_eq!(detached.len(), 2, "{records:?}");
        assert_eq!(detached[0], "a", "the first write replaced the stored policy");
        assert_eq!(detached[1], attached[1], "the second write replaced the first one's policy");
    }
}
