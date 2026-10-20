pub use super::ConnectionPointStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use tracing::info;

use super::types::GatewayConnectionPoint;
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// File system implementation of ConnectionPointStore with in-memory cache
///
/// This implementation uses the generic `CachedFilesystemStorage` for all
/// file operations and caching, eliminating code duplication.
pub struct FileSystemConnectionPointStore {
    base_path: PathBuf,
    storage: Box<dyn StorageBackend<GatewayConnectionPoint>>,
    event_hook: std::sync::OnceLock<std::sync::Arc<crate::event_hook::EventHook>>,
    id_locks: dashmap::DashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>,
    deleted: std::sync::Mutex<RecentlyDeleted>,
}

const DELETED_MEMORY_CAPACITY: usize = 1024;
const DELETED_MEMORY_TTL: std::time::Duration = std::time::Duration::from_secs(600);

struct RecentlyDeleted {
    entries: std::collections::VecDeque<(String, std::time::Instant)>,
    capacity: usize,
    ttl: std::time::Duration,
}

impl RecentlyDeleted {
    fn new(
        capacity: usize,
        ttl: std::time::Duration,
    ) -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
            capacity,
            ttl,
        }
    }

    fn expire(
        &mut self,
        now: std::time::Instant,
    ) {
        while self
            .entries
            .front()
            .is_some_and(|(_, at)| now.duration_since(*at) >= self.ttl)
        {
            self.entries.pop_front();
        }
    }

    fn record(
        &mut self,
        id: &str,
        now: std::time::Instant,
    ) {
        self.expire(now);
        self.entries
            .push_back((id.to_string(), now));
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
    }

    fn contains(
        &mut self,
        id: &str,
        now: std::time::Instant,
    ) -> bool {
        self.expire(now);
        self.entries
            .iter()
            .any(|(entry, _)| entry == id)
    }

    fn forget(
        &mut self,
        id: &str,
    ) {
        self.entries
            .retain(|(entry, _)| entry != id);
    }
}

struct IdLockGuard<'a> {
    locks: &'a dashmap::DashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>,
    id: &'a str,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for IdLockGuard<'_> {
    fn drop(&mut self) {
        self.guard.take();
        self.locks
            .remove_if(self.id, |_, lock| std::sync::Arc::strong_count(lock) == 1);
    }
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
            id_locks: dashmap::DashMap::new(),
            deleted: std::sync::Mutex::new(RecentlyDeleted::new(DELETED_MEMORY_CAPACITY, DELETED_MEMORY_TTL)),
        })
    }

    async fn lock_id<'a>(
        &'a self,
        id: &'a str,
    ) -> IdLockGuard<'a> {
        let mut guard = IdLockGuard {
            locks: &self.id_locks,
            id,
            guard: None,
        };
        let lock = self
            .id_locks
            .entry(id.to_string())
            .or_default()
            .clone();
        guard.guard = Some(lock.lock_owned().await);
        guard
    }

    fn deleted_memory(&self) -> std::sync::MutexGuard<'_, RecentlyDeleted> {
        self.deleted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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
    pub async fn cleanup_orphaned_directories(&self) -> Result<usize> {
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

                if !config_json.exists() && !config_json_enc.exists() {
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
            .await?;
        self.deleted_memory()
            .forget(&connection_point.id);
        Ok(())
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
        if self
            .deleted_memory()
            .contains(&connection_point.id, std::time::Instant::now())
        {
            return Err(super::store::ConnectionPointGone(connection_point.id.clone()).into());
        }
        self.save_and_revoke(connection_point)
            .await
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
        self.deleted_memory()
            .record(id, std::time::Instant::now());
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

        let cleaned = store
            .cleanup_orphaned_directories()
            .await
            .unwrap();

        assert_eq!(cleaned, 1, "only the true orphan should be removed");
        assert!(live_keys.exists(), "key dir with an encrypted config must be kept");
        assert!(plain_keys.exists(), "key dir with a plaintext config must be kept");
        assert!(!orphan_keys.exists(), "key dir with no config sibling must be removed");
    }

    #[tokio::test]
    async fn an_update_after_a_delete_does_not_resurrect_the_record() {
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

        let refusal = store
            .update(&stale)
            .await
            .expect_err("updating a deleted record is refused");
        assert_eq!(
            refusal
                .downcast_ref::<super::super::store::ConnectionPointGone>()
                .map(|gone| gone.0.as_str()),
            Some(cp.id.as_str()),
            "the refusal is the typed 'gone' error"
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
    async fn concurrent_updates_and_a_delete_leave_the_record_gone() {
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
                    let _ = store.update(&cp).await;
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
    async fn updating_an_existing_record_still_persists_the_change() {
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
        store
            .update(&cp)
            .await
            .unwrap();
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
            id_locks: dashmap::DashMap::new(),
            deleted: std::sync::Mutex::new(RecentlyDeleted::new(DELETED_MEMORY_CAPACITY, DELETED_MEMORY_TTL)),
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
    async fn creating_a_deleted_id_again_lifts_the_update_refusal() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        let cp = sample_cp();
        store
            .create(&cp)
            .await
            .unwrap();
        store
            .delete(&cp.id)
            .await
            .unwrap();
        store
            .create(&cp)
            .await
            .unwrap();
        store
            .update(&cp)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_held_lock_on_one_id_does_not_block_another_and_is_released_afterwards() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        let held = store.lock_id("a").await;
        let other = tokio::time::timeout(std::time::Duration::from_secs(2), store.lock_id("b"))
            .await
            .expect("an unrelated id is not blocked");
        assert_eq!(store.id_locks.len(), 2);
        drop(other);
        drop(held);
        assert!(store.id_locks.is_empty(), "idle locks are removed");
    }

    #[tokio::test]
    async fn a_lock_future_dropped_while_waiting_leaves_no_entry() {
        let dir = TempDir::new().unwrap();
        let store = std::sync::Arc::new(
            FileSystemConnectionPointStore::new(dir.path().join("cps"))
                .await
                .unwrap(),
        );
        let held = store.lock_id("a").await;

        let timed_out = tokio::time::timeout(std::time::Duration::from_millis(50), store.lock_id("a")).await;
        assert!(timed_out.is_err());

        let waiter = {
            let store = store.clone();
            tokio::spawn(async move {
                let _guard = store.lock_id("a").await;
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        waiter.abort();
        let _ = waiter.await;

        assert_eq!(store.id_locks.len(), 1, "the entry still held is kept");
        drop(held);
        assert!(store.id_locks.is_empty());
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

    #[test]
    fn recently_deleted_ids_expire_and_are_bounded() {
        let start = std::time::Instant::now();
        let mut memory = RecentlyDeleted::new(2, std::time::Duration::from_secs(10));
        memory.record("a", start);
        assert!(memory.contains("a", start + std::time::Duration::from_secs(9)));
        assert!(!memory.contains("a", start + std::time::Duration::from_secs(10)));

        memory.record("a", start);
        memory.record("b", start);
        memory.record("c", start);
        assert!(!memory.contains("a", start), "the oldest entry is evicted past the capacity");
        assert!(memory.contains("b", start));
        assert!(memory.contains("c", start));
    }
}
