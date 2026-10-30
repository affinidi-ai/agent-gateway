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
    /// Held from reading a surface before a write until the write's policy
    /// changes are recorded, so they are relative to the surface it replaced
    /// and the records of concurrent writes come in write order.
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
        policy_changes::surface_written(before.as_ref(), Some(surface)).await;
        drop(write);
        crate::mcp::subscriptions::invalidate_access(crate::mcp::subscriptions::AccessScope::Surface(
            surface.surface_id.clone(),
        ));
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
        policy_changes::surface_written(before.as_ref(), None).await;
        drop(write);
        crate::mcp::subscriptions::invalidate_access(crate::mcp::subscriptions::AccessScope::Surface(
            surface_id.to_string(),
        ));
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
    use serde_json::json;

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

        assert_recorded_in_write_order(&records);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_writes_to_one_surface_record_their_changes_in_write_order() {
        let dir = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(
            FileSystemAgentSurfaceStore::new(dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let ((), mut records) = capture(in_management_request(Actor::user("u-1"), async {
            store
                .save(&surface("a"))
                .await
                .unwrap();
        }))
        .await;

        let write = |policy: &'static str| {
            let store = store.clone();
            in_management_request(Actor::user("u-1"), async move {
                store
                    .save(&surface(policy))
                    .await
                    .unwrap();
            })
        };
        records.extend(crate::audit::producer::capture_spawned(vec![write("b"), write("c")]).await);

        assert_recorded_in_write_order(&records);
    }

    /// `records` are those of creating a surface naming policy `a`, then two
    /// writes naming `b` and `c` in either order: each write's detach names
    /// the policy the write before it attached, and records come in write order.
    fn assert_recorded_in_write_order(records: &[crate::delegation_vault::audit::DelegationAuditEvent]) {
        let changes: Vec<(&str, String)> = records
            .iter()
            .map(|record| {
                let category = action_category(&record.event);
                let id = serde_json::to_value(&record.event).unwrap()[category]["policy_definition_id"]
                    .as_str()
                    .unwrap()
                    .to_string();
                (category, id)
            })
            .collect();
        let second = changes
            .get(2)
            .map(|(_, id)| id.clone())
            .unwrap_or_default();
        let third = if second == "b" {
            "c"
        } else {
            "b"
        };
        assert_eq!(
            changes,
            vec![
                ("policy_attached", "a".to_string()),
                ("policy_detached", "a".to_string()),
                ("policy_attached", second.clone()),
                ("policy_detached", second),
                ("policy_attached", third.to_string()),
            ]
        );
    }

    fn surface_json(
        id: &str,
        auth: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "surface_id": id, "name": id,
            "access_point": {"listen_address": "127.0.0.1:0", "route": format!("/{id}"), "protocol": "a2a"},
            "target": {"endpoint": "https://agent.example", "auth": auth}
        })
    }

    fn unreadable_surfaces() -> u64 {
        crate::metrics::backends::prometheus::STORAGE_LOAD_ERRORS
            .with_label_values(&["agent_surface", "unreadable_record"])
            .get()
    }

    /// A node of an earlier release does not know a newer Target Authentication method.
    /// Its loader drops the whole surface, not just the authentication, and counts it.
    #[tokio::test]
    async fn a_surface_with_a_target_authentication_method_the_release_does_not_know_is_dropped_whole() {
        let directory = tempfile::tempdir().unwrap();
        let known = surface_json("known", json!({"method": {"static_secret": {"secret_id": "S", "header_name": "X"}}}));
        let unknown = surface_json("unknown", json!({"method": {"a_method_from_a_newer_release": {}}}));
        std::fs::write(
            directory
                .path()
                .join("known.json"),
            known.to_string(),
        )
        .unwrap();
        std::fs::write(
            directory
                .path()
                .join("unknown.json"),
            unknown.to_string(),
        )
        .unwrap();
        let before = unreadable_surfaces();

        let store = FileSystemAgentSurfaceStore::new(directory.path().to_path_buf())
            .await
            .unwrap();
        assert_eq!(unreadable_surfaces(), before + 1, "the load counts the one unreadable record");

        let ids: Vec<String> = store
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .map(|surface| surface.surface_id)
            .collect();
        assert_eq!(ids, vec!["known".to_string()]);
        assert!(
            store
                .get("unknown")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_surface_this_release_wrote_loads_without_an_authentication_block() {
        let directory = tempfile::tempdir().unwrap();
        let mut bare = surface_json("bare", json!(null));
        bare["target"]
            .as_object_mut()
            .unwrap()
            .remove("auth");
        std::fs::write(
            directory
                .path()
                .join("bare.json"),
            bare.to_string(),
        )
        .unwrap();

        let store = FileSystemAgentSurfaceStore::new(directory.path().to_path_buf())
            .await
            .unwrap();

        let surface = store
            .get("bare")
            .await
            .unwrap()
            .expect("loads");
        assert!(
            surface
                .target_auth()
                .is_none()
        );
    }
}
