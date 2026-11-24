pub use super::ConnectionPointStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::info;

use super::types::GatewayConnectionPoint;
use crate::storage::filesystem::{StorageBackend, cached_storage};
use crate::storage::id_locks::{IdLockGuard, IdLocks};

/// File system implementation of ConnectionPointStore with in-memory cache
///
/// This implementation uses the generic `CachedFilesystemStorage` for all
/// file operations and caching, eliminating code duplication.
pub struct FileSystemConnectionPointStore {
    base_path: PathBuf,
    storage: Box<dyn StorageBackend<GatewayConnectionPoint>>,
    event_hook: std::sync::OnceLock<std::sync::Arc<crate::event_hook::EventHook>>,
    id_locks: IdLocks,
}

impl FileSystemConnectionPointStore {
    pub async fn new(base_path: PathBuf) -> Result<Self> {
        let storage = cached_storage(base_path.clone(), "connection_point").await?;
        info!(
            "Loaded {} connection point(s) from {}",
            storage
                .list_all()
                .await?
                .len(),
            base_path.display()
        );
        Ok(Self {
            base_path,
            storage,
            event_hook: std::sync::OnceLock::new(),
            id_locks: IdLocks::default(),
        })
    }

    async fn lock_id<'a>(
        &'a self,
        id: &'a str,
    ) -> IdLockGuard<'a> {
        self.id_locks.lock(id).await
    }

    pub fn set_event_hook(
        &self,
        hook: std::sync::Arc<crate::event_hook::EventHook>,
    ) {
        let _ = self.event_hook.set(hook);
    }

    /// Reconcile the in-memory cache with the current on-disk state.
    ///
    /// Picks up connection points added to storage while the process was
    /// stopped or restarted.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }

    /// Clean up orphaned connection point key directories — a `{id}/` folder with no
    /// `{id}.json` or `{id}.json.enc` config sibling at the base level. These are leftover
    /// DID secret folders from failed or incomplete connection attempts.
    ///
    /// A permanent connection point an acceptance or a paused pairing minted ahead of
    /// the pairing has keys but no record of its own until the pairing completes; its
    /// directory is kept while a stored connection point still names it, as its
    /// `reserved_permanent` or as the `secure_cp_id` an acceptance keeps in its
    /// `oob_message`.
    pub async fn cleanup_orphaned_directories(&self) -> Result<usize> {
        // Keys are removed only after every stored record was read: an unreadable one may
        // name the directory as its reservation.
        let reserved: std::collections::HashSet<String> = self
            .list_all_checked()
            .await?
            .into_iter()
            .flat_map(|point| {
                let acceptance = point
                    .oob_message
                    .get("secure_cp_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string);
                point
                    .reserved_permanent
                    .map(|reserved| reserved.cp_id)
                    .into_iter()
                    .chain(acceptance)
            })
            .collect();
        self.remove_orphaned_directories(&reserved)
            .await
    }

    /// Removes the key directories with no config sibling that no name in `reserved` keeps.
    async fn remove_orphaned_directories(
        &self,
        reserved: &std::collections::HashSet<String>,
    ) -> Result<usize> {
        use tracing::{info, warn};

        let mut cleaned = 0;
        let mut dir = tokio::fs::read_dir(&self.base_path).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            let dir_name = entry.file_name();

            // Skip the special "pending" directory and JSON files
            if dir_name == "pending"
                || path
                    .extension()
                    .and_then(|s| s.to_str())
                    == Some("json")
            {
                continue;
            }

            // Only process directories
            if path.is_dir() {
                let dir_name_str = dir_name.to_string_lossy();

                // A connection point's config lives at the base level as `{id}.json`
                // (plaintext) or `{id}.json.enc` (whole-file encryption at rest). Either
                // one proves the sibling `{id}/` key directory is a live connection point,
                // not an orphan. Checking only `{id}.json` would delete every valid key
                // directory once encryption at rest is enabled.
                let config_json = self
                    .base_path
                    .join(format!("{}.json", dir_name_str));
                let config_json_enc = self
                    .base_path
                    .join(format!("{}.json.enc", dir_name_str));

                if !config_json.exists() && !config_json_enc.exists() && !reserved.contains(dir_name_str.as_ref()) {
                    info!("Cleaning up orphaned connection point directory: {:?}", dir_name);

                    match tokio::fs::remove_dir_all(&path).await {
                        Ok(_) => {
                            cleaned += 1;
                        }
                        Err(e) => {
                            warn!("Failed to remove orphaned directory {:?}: {}", dir_name, e);
                        }
                    }
                }
            }
        }

        if cleaned > 0 {
            info!(
                "✓ Cleaned up {} orphaned connection point director{}",
                cleaned,
                if cleaned == 1 {
                    "y"
                } else {
                    "ies"
                }
            );
        }

        Ok(cleaned)
    }

    /// The store's record changes, including those another node made that the
    /// shared-storage refresh picked up.
    pub fn subscribe(
        &self
    ) -> Option<tokio::sync::broadcast::Receiver<crate::storage::filesystem::StorageEvent<GatewayConnectionPoint>>>
    {
        self.storage.subscribe()
    }

    /// Ends the running Fabric streams the stored Connection Point records no
    /// longer admit. When the records cannot be listed, every stream ends, as
    /// no new one could be admitted either.
    pub async fn revoke_streams_not_admitted(&self) {
        match self.storage.list_all().await {
            Ok(connection_points) => crate::proxy::fabric_stream::revoke(
                crate::proxy::fabric_stream::Revocation::ConnectionPointsOutside(&connection_points),
            ),
            Err(error) => {
                tracing::warn!(%error, "Could not list Connection Point records; ending every Fabric stream");
                crate::proxy::fabric_stream::revoke(crate::proxy::fabric_stream::Revocation::ConnectionPointsOutside(
                    &[],
                ));
            }
        }
    }

    /// Saves `connection_point` and ends the running Fabric streams the change
    /// revokes. When the previous record cannot be read, the running streams
    /// are checked against the stored records instead.
    async fn save_and_revoke(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()> {
        let previous = self
            .storage
            .get(&connection_point.id)
            .await;
        self.storage
            .save(connection_point)
            .await?;
        self.revoke_change(previous, Some(connection_point))
            .await;
        Ok(())
    }

    async fn revoke_change(
        &self,
        previous: Result<Option<GatewayConnectionPoint>>,
        current: Option<&GatewayConnectionPoint>,
    ) {
        match &previous {
            Ok(Some(previous)) => {
                if let Some(revocation) =
                    crate::proxy::fabric_stream::Revocation::of_connection_point_change(previous, current)
                {
                    crate::proxy::fabric_stream::revoke(revocation);
                }
            }
            Ok(None) => {}
            Err(_) => {
                self.revoke_streams_not_admitted()
                    .await
            }
        }
    }
}

#[async_trait]
impl ConnectionPointStore for FileSystemConnectionPointStore {
    async fn create(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()> {
        let _guard = self
            .lock_id(&connection_point.id)
            .await;
        self.save_and_revoke(connection_point)
            .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<GatewayConnectionPoint>> {
        self.storage.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<GatewayConnectionPoint>> {
        let mut connection_points = self
            .storage
            .list_all()
            .await?;

        // Sort by creation date (newest first)
        connection_points.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(connection_points)
    }

    async fn list_by_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayConnectionPoint>> {
        let mut connection_points = self
            .storage
            .list_all()
            .await?;
        connection_points.retain(|cp| cp.gateway_id == gateway_id);

        // Sort by creation date (newest first)
        connection_points.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(connection_points)
    }

    async fn update(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()> {
        let _guard = self
            .lock_id(&connection_point.id)
            .await;
        self.save_and_revoke(connection_point)
            .await
    }

    async fn update_if_exists(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<bool> {
        let _guard = self
            .lock_id(&connection_point.id)
            .await;
        if self
            .storage
            .get(&connection_point.id)
            .await?
            .is_none()
        {
            return Ok(false);
        }
        self.save_and_revoke(connection_point)
            .await?;
        Ok(true)
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        let _guard = self.lock_id(id).await;
        let previous = self.storage.get(id).await;
        self.storage
            .delete(id)
            .await?;
        // A reservation never paired leaves keys with no record of their own: remove them,
        // and report its DID failed unless the pairing consumed it.
        if let Ok(Some(record)) = &previous
            && let Some(reserved) = &record.reserved_permanent
            && matches!(
                self.storage
                    .get(&reserved.cp_id)
                    .await,
                Ok(None)
            )
        {
            match tokio::fs::remove_dir_all(
                self.base_path
                    .join(&reserved.cp_id),
            )
            .await
            {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(
                    connection_point_id = %reserved.cp_id,
                    %e,
                    "Could not remove the keys of a reservation that was never paired"
                ),
            }
            if !reserved.consumed
                && let Some(hook) = self.event_hook.get()
            {
                hook.emit(
                    crate::event_hook::EventKind::CreationFailed,
                    crate::event_hook::ConnectionPointPayload::reserved(record, reserved),
                );
            }
        }
        if let Some(hook) = self.event_hook.get() {
            match &previous {
                Ok(Some(record)) if record.is_announced() => hook.emit(
                    crate::event_hook::EventKind::Deleted,
                    crate::event_hook::ConnectionPointPayload::from_record(record, None),
                ),
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    connection_point_id = id,
                    %error,
                    "Connection point deleted, but its record could not be read first, so no connection_point.deleted event is sent"
                ),
            }
        }
        self.revoke_change(previous, None)
            .await;
        Ok(())
    }

    async fn create_reserved(
        &self,
        connection_point: &GatewayConnectionPoint,
        reserving_id: &str,
    ) -> Result<()> {
        // `delete` holds this lock while it checks for the permanent record and removes
        // the reservation's keys, so the two cannot interleave.
        let _reserving = self
            .lock_id(reserving_id)
            .await;
        if self
            .storage
            .get(reserving_id)
            .await?
            .is_none()
        {
            anyhow::bail!("connection point {reserving_id} that reserved this permanent DID was deleted");
        }
        self.create(connection_point)
            .await
    }

    async fn list_all_checked(&self) -> Result<Vec<GatewayConnectionPoint>> {
        let points = self.list_all().await?;
        let listed: std::collections::HashSet<&str> = points
            .iter()
            .map(|point| point.id.as_str())
            .collect();
        // A record file the cache left out is either unreadable, which is an error
        // here, or was deleted or added since the list was read.
        let mut dir = tokio::fs::read_dir(&self.base_path).await?;
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(id) = name
                .strip_suffix(".json.enc")
                .or_else(|| name.strip_suffix(".json"))
            else {
                continue;
            };
            if !listed.contains(id) {
                self.storage
                    .get_checked(id)
                    .await?;
            }
        }
        Ok(points)
    }

    async fn list_by_gateway_checked(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayConnectionPoint>> {
        let mut points = self
            .list_all_checked()
            .await?;
        points.retain(|point| point.gateway_id == gateway_id);
        Ok(points)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
    use tempfile::TempDir;

    fn sample_cp() -> GatewayConnectionPoint {
        let mut cp = GatewayConnectionPoint::new(
            "gw-1".to_string(),
            "did:example:mediator".to_string(),
            "did:example:cp".to_string(),
            "CP".to_string(),
            "desc".to_string(),
            "oob-1".to_string(),
            "https://oob.example".to_string(),
            serde_json::json!({}),
            None,
            ConnectionPointType::User,
            "secret".to_string(),
        );
        cp.mediator_did = Some("did:example:mediator".to_string());
        cp
    }

    #[tokio::test]
    async fn refresh_from_disk_picks_up_connection_point_added_after_construction() {
        let dir = TempDir::new().unwrap();

        // A node that booted first: its cache is empty.
        let cached_reader = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        assert!(
            cached_reader
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );

        // Another node (or a later API write) persists a connection point to the same dir.
        let writer = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let cp = sample_cp();
        let cp_id = cp.id.clone();
        writer
            .create(&cp)
            .await
            .unwrap();

        // The first store's boot cache still does not see it.
        assert!(
            cached_reader
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );

        // After refresh, the first store sees exactly that connection point.
        cached_reader
            .refresh_from_disk()
            .await
            .unwrap();
        let seen = cached_reader
            .list_all()
            .await
            .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].id, cp_id);
    }

    #[tokio::test]
    async fn cleanup_keeps_key_dir_with_encrypted_config_and_removes_true_orphan() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();

        // A live connection point under encryption at rest: config persisted as
        // `{id}.json.enc`, private keys in the sibling `{id}/` directory.
        let live_id = "live-cp";
        let live_keys = dir.path().join(live_id);
        tokio::fs::create_dir_all(&live_keys)
            .await
            .unwrap();
        tokio::fs::write(live_keys.join("key_0.json"), b"{}")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path()
                .join(format!("{}.json.enc", live_id)),
            b"ciphertext",
        )
        .await
        .unwrap();

        // A live connection point with a plaintext config (encryption disabled).
        let plain_id = "plain-cp";
        let plain_keys = dir.path().join(plain_id);
        tokio::fs::create_dir_all(&plain_keys)
            .await
            .unwrap();
        tokio::fs::write(plain_keys.join("key_0.json"), b"{}")
            .await
            .unwrap();
        tokio::fs::write(
            dir.path()
                .join(format!("{}.json", plain_id)),
            b"{}",
        )
        .await
        .unwrap();

        // A genuine orphan: a key directory with no config sibling at all.
        let orphan_id = "orphan-cp";
        let orphan_keys = dir.path().join(orphan_id);
        tokio::fs::create_dir_all(&orphan_keys)
            .await
            .unwrap();
        tokio::fs::write(orphan_keys.join("key_0.json"), b"{}")
            .await
            .unwrap();

        // The configs above are placeholders the store cannot read, so the full cleanup
        // would refuse to run; this checks which directories count as orphans.
        let cleaned = store
            .remove_orphaned_directories(&std::collections::HashSet::new())
            .await
            .unwrap();

        assert_eq!(cleaned, 1, "only the true orphan should be removed");
        assert!(live_keys.exists(), "key dir with an encrypted config must be kept");
        assert!(plain_keys.exists(), "key dir with a plaintext config must be kept");
        assert!(!orphan_keys.exists(), "key dir with no config sibling must be removed");
    }

    #[tokio::test]
    async fn cleanup_after_a_restart_keeps_the_keys_a_paused_pairing_reserved() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let mut paused = sample_cp();
        paused.awaiting_mediator_access = true;
        paused.reserved_permanent = Some(super::super::types::ReservedPermanent {
            cp_id: "reserved-cp".to_string(),
            did: "did:peer:2.reserved".to_string(),
            mediator_id: "med-1".to_string(),
            mediator_did: "did:example:mediator".to_string(),
            consumed: false,
        });
        store
            .create(&paused)
            .await
            .unwrap();
        let reserved_keys = dir.path().join("reserved-cp");
        tokio::fs::create_dir_all(&reserved_keys)
            .await
            .unwrap();
        tokio::fs::write(reserved_keys.join("key_0.json"), b"{}")
            .await
            .unwrap();
        let orphan_keys = dir.path().join("orphan-cp");
        tokio::fs::create_dir_all(&orphan_keys)
            .await
            .unwrap();
        drop(store);

        let restarted = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let cleaned = restarted
            .cleanup_orphaned_directories()
            .await
            .unwrap();

        assert_eq!(cleaned, 1, "only the true orphan should be removed");
        assert!(
            reserved_keys
                .join("key_0.json")
                .exists(),
            "the reserved permanent keys must survive a restart"
        );
        assert!(!orphan_keys.exists());
    }

    #[tokio::test]
    async fn update_if_exists_after_a_delete_does_not_resurrect_the_record() {
        let dir = TempDir::new().unwrap();
        let cps = dir.path().join("cps");
        let store = FileSystemConnectionPointStore::new(cps.clone())
            .await
            .unwrap();
        let cp = sample_cp();
        store
            .create(&cp)
            .await
            .unwrap();
        let stale = store
            .get(&cp.id)
            .await
            .unwrap()
            .unwrap();
        store
            .delete(&cp.id)
            .await
            .unwrap();

        assert!(
            !store
                .update_if_exists(&stale)
                .await
                .unwrap(),
            "nothing is written for a deleted record"
        );
        assert!(
            store
                .get(&cp.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
        let reloaded = FileSystemConnectionPointStore::new(cps)
            .await
            .unwrap();
        assert!(
            reloaded
                .get(&cp.id)
                .await
                .unwrap()
                .is_none(),
            "nothing was written to disk"
        );
    }

    #[tokio::test]
    async fn concurrent_conditional_updates_and_a_delete_leave_the_record_gone() {
        let dir = TempDir::new().unwrap();
        let store = std::sync::Arc::new(
            FileSystemConnectionPointStore::new(dir.path().join("cps"))
                .await
                .unwrap(),
        );
        let cp = sample_cp();
        store
            .create(&cp)
            .await
            .unwrap();
        let mut updaters = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let cp = cp.clone();
            updaters.push(tokio::spawn(async move {
                for _ in 0..20 {
                    let _ = store
                        .update_if_exists(&cp)
                        .await;
                    tokio::task::yield_now().await;
                }
            }));
        }
        store
            .delete(&cp.id)
            .await
            .unwrap();
        for updater in updaters {
            updater.await.unwrap();
        }
        assert!(
            store
                .get(&cp.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn update_if_exists_writes_an_existing_record() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        let mut cp = sample_cp();
        store
            .create(&cp)
            .await
            .unwrap();
        cp.name = "renamed".to_string();
        assert!(
            store
                .update_if_exists(&cp)
                .await
                .unwrap()
        );
        assert_eq!(
            store
                .get(&cp.id)
                .await
                .unwrap()
                .unwrap()
                .name,
            "renamed"
        );
    }

    fn hook_for(url: String) -> std::sync::Arc<crate::event_hook::EventHook> {
        crate::event_hook::EventHook::new(crate::event_hook::EventHookSettings {
            hook_url: Some(url),
            ..Default::default()
        })
        .unwrap()
    }

    async fn deleted_events(
        captured: &std::sync::Mutex<Vec<crate::event_hook::tests_support::Captured>>
    ) -> Vec<serde_json::Value> {
        for _ in 0..100 {
            if !captured
                .lock()
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        captured
            .lock()
            .unwrap()
            .iter()
            .map(|request| serde_json::from_str(&request.body).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn deleting_a_record_reports_deleted_with_its_did_and_recorded_mediator() {
        let (url, captured) = crate::event_hook::tests_support::serve(204, "").await;
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        store.set_event_hook(hook_for(url));
        let mut cp = sample_cp();
        cp.mediator_did = Some("did:web:recorded.example".to_string());
        store
            .create(&cp)
            .await
            .unwrap();
        store
            .delete(&cp.id)
            .await
            .unwrap();

        let events = deleted_events(&captured).await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event"], "connection_point.deleted");
        let payload = &events[0]["connection_point"];
        assert_eq!(payload["id"], cp.id);
        assert_eq!(payload["did"], cp.connection_point_did);
        assert_eq!(payload["mediator_did"], "did:web:recorded.example");
    }

    #[tokio::test]
    async fn deleting_a_missing_record_reports_nothing() {
        let (url, captured) = crate::event_hook::tests_support::serve(204, "").await;
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        store.set_event_hook(hook_for(url));
        let _ = store
            .delete("no-such-record")
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            captured
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_failed_delete_reports_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let (url, captured) = crate::event_hook::tests_support::serve(204, "").await;
        let dir = TempDir::new().unwrap();
        let cps = dir.path().join("cps");
        let store = FileSystemConnectionPointStore::new(cps.clone())
            .await
            .unwrap();
        store.set_event_hook(hook_for(url));
        let cp = sample_cp();
        store
            .create(&cp)
            .await
            .unwrap();
        std::fs::set_permissions(&cps, std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = store.delete(&cp.id).await;
        std::fs::set_permissions(&cps, std::fs::Permissions::from_mode(0o755)).unwrap();
        if result.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            captured
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    struct UnreadableStorage(Box<dyn StorageBackend<GatewayConnectionPoint>>);

    #[async_trait]
    impl StorageBackend<GatewayConnectionPoint> for UnreadableStorage {
        async fn save(
            &self,
            entity: &GatewayConnectionPoint,
        ) -> Result<()> {
            self.0.save(entity).await
        }

        async fn get(
            &self,
            _: &str,
        ) -> Result<Option<GatewayConnectionPoint>> {
            anyhow::bail!("record unreadable")
        }

        async fn list_all(&self) -> Result<Vec<GatewayConnectionPoint>> {
            self.0.list_all().await
        }

        async fn delete(
            &self,
            id: &str,
        ) -> Result<()> {
            self.0.delete(id).await
        }
    }

    #[derive(Clone, Default)]
    struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(
            &mut self,
            buf: &[u8],
        ) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap()
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
        type Writer = LogBuffer;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn a_delete_whose_record_could_not_be_read_succeeds_warns_and_sends_nothing() {
        let (url, captured) = crate::event_hook::tests_support::serve(204, "").await;
        let dir = TempDir::new().unwrap();
        let cps = dir.path().join("cps");
        let inner = FileSystemConnectionPointStore::new(cps.clone())
            .await
            .unwrap();
        let cp = sample_cp();
        inner
            .create(&cp)
            .await
            .unwrap();
        let store = FileSystemConnectionPointStore {
            base_path: cps,
            storage: Box::new(UnreadableStorage(inner.storage)),
            event_hook: std::sync::OnceLock::new(),
            id_locks: IdLocks::default(),
        };
        store.set_event_hook(hook_for(url));

        let logs = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let _logging = tracing::subscriber::set_default(subscriber);
        store
            .delete(&cp.id)
            .await
            .expect("the delete itself succeeds");

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            captured
                .lock()
                .unwrap()
                .is_empty()
        );
        let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("WARN"), "{logged}");
        assert!(logged.contains(&cp.id), "{logged}");
        assert!(logged.contains("could not be read first"), "{logged}");
    }

    #[tokio::test]
    async fn concurrent_creates_and_deletes_of_one_id_leave_a_consistent_store() {
        let dir = TempDir::new().unwrap();
        let store = std::sync::Arc::new(
            FileSystemConnectionPointStore::new(dir.path().join("cps"))
                .await
                .unwrap(),
        );
        let cp = sample_cp();
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (creator, deleter, record) = (store.clone(), store.clone(), cp.clone());
            tasks.push(tokio::spawn(async move {
                creator
                    .create(&record)
                    .await
                    .unwrap()
            }));
            let id = cp.id.clone();
            tasks.push(tokio::spawn(async move {
                let _ = deleter.delete(&id).await;
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        store
            .delete(&cp.id)
            .await
            .unwrap();
        assert!(
            store
                .get(&cp.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !dir.path()
                .join("cps")
                .join(format!("{}.json", cp.id))
                .exists()
        );
    }

    #[tokio::test]
    async fn cleanup_after_a_restart_keeps_the_permanent_keys_of_an_unpaused_acceptance() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let mut temporary = sample_cp();
        temporary.oob_message = serde_json::json!({ "secure_cp_id": "acceptance-permanent" });
        store
            .create(&temporary)
            .await
            .unwrap();
        let permanent_keys = dir
            .path()
            .join("acceptance-permanent");
        tokio::fs::create_dir_all(&permanent_keys)
            .await
            .unwrap();
        tokio::fs::write(permanent_keys.join("key_0.json"), b"{}")
            .await
            .unwrap();
        drop(store);

        let restarted = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let cleaned = restarted
            .cleanup_orphaned_directories()
            .await
            .unwrap();

        assert_eq!(cleaned, 0);
        assert!(
            permanent_keys
                .join("key_0.json")
                .exists(),
            "the permanent keys a pending acceptance named must survive a restart"
        );
    }

    #[tokio::test]
    async fn deleting_a_paused_record_reports_creation_failed_for_the_dids_it_reserved() {
        let (url, captured) = crate::event_hook::tests_support::serve(204, "").await;
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        store.set_event_hook(hook_for(url));
        let mut paused = sample_cp();
        paused.awaiting_mediator_access = true;
        paused.reserved_permanent = Some(super::super::types::ReservedPermanent {
            cp_id: "reserved-cp".to_string(),
            did: "did:peer:2.reserved".to_string(),
            mediator_id: "med-1".to_string(),
            mediator_did: "did:example:mediator".to_string(),
            consumed: false,
        });
        store
            .create(&paused)
            .await
            .unwrap();
        store
            .delete(&paused.id)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let failed: Vec<serde_json::Value> = captured
            .lock()
            .unwrap()
            .iter()
            .map(|event| serde_json::from_str::<serde_json::Value>(&event.body).unwrap())
            .filter(|event| event["event"] == "connection_point.creation_failed")
            .collect();
        assert_eq!(failed.len(), 1, "one creation_failed for the reserved DID");
        assert_eq!(failed[0]["connection_point"]["did"], "did:peer:2.reserved");
    }

    #[tokio::test]
    async fn deleting_a_record_whose_reservation_was_consumed_reports_nothing_for_it() {
        let (url, captured) = crate::event_hook::tests_support::serve(204, "").await;
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        store.set_event_hook(hook_for(url));
        let mut used = sample_cp();
        used.reserved_permanent = Some(super::super::types::ReservedPermanent {
            cp_id: "paired-then-deleted".to_string(),
            did: "did:peer:2.reserved".to_string(),
            mediator_id: "med-1".to_string(),
            mediator_did: "did:example:mediator".to_string(),
            consumed: false,
        });
        store
            .create(&used)
            .await
            .unwrap();
        crate::gateways::mediator_access::mark_reservation_consumed(&store, &used.id).await;
        assert!(
            store
                .get(&used.id)
                .await
                .unwrap()
                .unwrap()
                .reserved_permanent
                .unwrap()
                .consumed
        );

        store
            .delete(&used.id)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let failed = captured
            .lock()
            .unwrap()
            .iter()
            .filter(|event| {
                event
                    .body
                    .contains("connection_point.creation_failed")
            })
            .count();
        assert_eq!(failed, 0, "a consumed reservation is owned by its paired record");
    }

    #[tokio::test]
    async fn deleting_an_unpaired_paused_record_removes_its_reserved_keys() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let mut paused = sample_cp();
        paused.awaiting_mediator_access = true;
        paused.reserved_permanent = Some(super::super::types::ReservedPermanent {
            cp_id: "never-paired".to_string(),
            did: "did:peer:2.reserved".to_string(),
            mediator_id: "med-1".to_string(),
            mediator_did: "did:example:mediator".to_string(),
            consumed: false,
        });
        store
            .create(&paused)
            .await
            .unwrap();
        let keys = dir
            .path()
            .join("never-paired");
        tokio::fs::create_dir_all(&keys)
            .await
            .unwrap();
        tokio::fs::write(keys.join("key_0.json"), b"{}")
            .await
            .unwrap();

        store
            .delete(&paused.id)
            .await
            .unwrap();

        assert!(!keys.exists(), "the reserved keys go with the reservation");
    }

    #[tokio::test]
    async fn deleting_a_record_the_management_api_did_not_create_reports_nothing() {
        let (url, captured) = crate::event_hook::tests_support::serve(204, "").await;
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        store.set_event_hook(hook_for(url));
        let mut temporary = sample_cp();
        temporary.mediator_did = None;
        store
            .create(&temporary)
            .await
            .unwrap();
        store
            .delete(&temporary.id)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            captured
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn updating_a_record_that_was_never_stored_creates_it() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        let cp = sample_cp();
        store
            .update(&cp)
            .await
            .unwrap();
        assert!(
            store
                .get(&cp.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn operations_on_the_same_id_wait_for_each_other() {
        let dir = TempDir::new().unwrap();
        let store = std::sync::Arc::new(
            FileSystemConnectionPointStore::new(dir.path().join("cps"))
                .await
                .unwrap(),
        );
        let cp = sample_cp();
        let held = store.lock_id(&cp.id).await;
        let writer = {
            let (store, cp) = (store.clone(), cp.clone());
            tokio::spawn(async move { store.create(&cp).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!writer.is_finished());
        assert!(
            store
                .get(&cp.id)
                .await
                .unwrap()
                .is_none()
        );
        drop(held);
        writer.await.unwrap().unwrap();
        assert!(
            store
                .get(&cp.id)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_reserved_point_is_stored_only_while_its_reserving_point_is() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        let mut paused = sample_cp();
        paused.awaiting_mediator_access = true;
        paused.reserved_permanent = Some(super::super::types::ReservedPermanent {
            cp_id: "reserved-cp".to_string(),
            did: "did:peer:2.reserved".to_string(),
            mediator_id: "med-1".to_string(),
            mediator_did: "did:example:mediator".to_string(),
            consumed: false,
        });
        store
            .create(&paused)
            .await
            .unwrap();
        let mut permanent = sample_cp();
        permanent.id = "reserved-cp".to_string();

        store
            .create_reserved(&permanent, &paused.id)
            .await
            .expect("stored while the reserving point is");
        store
            .delete(&permanent.id)
            .await
            .unwrap();
        store
            .delete(&paused.id)
            .await
            .unwrap();

        store
            .create_reserved(&permanent, &paused.id)
            .await
            .expect_err("its reserving point, and with it the keys, are gone");
        assert!(
            store
                .get(&permanent.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn keys_are_kept_while_a_stored_connection_point_cannot_be_read() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("cps");
        let store = FileSystemConnectionPointStore::new(base.clone())
            .await
            .unwrap();
        store
            .create(&sample_cp())
            .await
            .unwrap();
        // An unreadable record may name these keys as its reservation.
        tokio::fs::write(base.join("unreadable.json"), b"not json")
            .await
            .unwrap();
        tokio::fs::create_dir_all(base.join("reserved-cp"))
            .await
            .unwrap();

        assert_eq!(
            store
                .list_all()
                .await
                .unwrap()
                .len(),
            1
        );
        store
            .list_all_checked()
            .await
            .expect_err("a stored record could not be read");
        store
            .list_by_gateway_checked("gw-1")
            .await
            .expect_err("the unreadable record may be this gateway's");
        store
            .cleanup_orphaned_directories()
            .await
            .expect_err("no cleanup without a complete read");
        assert!(
            base.join("reserved-cp")
                .is_dir()
        );

        tokio::fs::remove_file(base.join("unreadable.json"))
            .await
            .unwrap();
        assert_eq!(
            store
                .list_all_checked()
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .cleanup_orphaned_directories()
                .await
                .unwrap(),
            1
        );
    }
}
