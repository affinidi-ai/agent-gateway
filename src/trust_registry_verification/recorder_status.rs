//! Last known Trust Recorder outcome per managed agent and surface.
//!
//! The recorder runs on every response, so the outcome is held in memory and
//! written to disk only when it changes. The status carries codes, counts and
//! timestamps only, never registry error text.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use tracing::warn;

use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};

static GLOBAL_RECORDER_STATUS_STORE: OnceCell<Arc<TrustRecorderStatusStore>> = OnceCell::const_new();

pub fn init_global_store(store: Arc<TrustRecorderStatusStore>) {
    let _ = GLOBAL_RECORDER_STATUS_STORE.set(store);
}

pub fn global_store() -> Option<Arc<TrustRecorderStatusStore>> {
    GLOBAL_RECORDER_STATUS_STORE
        .get()
        .cloned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecorderState {
    Recorded,
    Partial,
    Failed,
    Skipped,
    NotAttempted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecorderReason {
    RegistryNotFound,
    RegistryNotConnected,
    NoSurfaceIssuer,
    NoResponse,
    Rejected,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryStatus {
    pub trust_registry_id: String,
    pub state: RecorderState,
    pub reason: Option<RecorderReason>,
    pub created: u32,
    pub already_existed: u32,
    pub failed: u32,
}

impl EntryStatus {
    pub fn skipped(
        trust_registry_id: &str,
        reason: RecorderReason,
    ) -> Self {
        Self {
            trust_registry_id: trust_registry_id.to_string(),
            state: RecorderState::Skipped,
            reason: Some(reason),
            created: 0,
            already_existed: 0,
            failed: 0,
        }
    }

    pub fn from_counts(
        trust_registry_id: &str,
        created: u32,
        already_existed: u32,
        failed: u32,
        first_failure: Option<RecorderReason>,
    ) -> Self {
        let written = created + already_existed;
        let state = match (written > 0, failed > 0) {
            (true, false) => RecorderState::Recorded,
            (true, true) => RecorderState::Partial,
            (false, _) => RecorderState::Failed,
        };
        let reason = (failed > 0).then(|| first_failure.unwrap_or(RecorderReason::Error));
        Self {
            trust_registry_id: trust_registry_id.to_string(),
            state,
            reason,
            created,
            already_existed,
            failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecorderStatus {
    pub state: RecorderState,
    pub reason: Option<RecorderReason>,
    pub last_attempt_at: Option<String>,
    pub entries: Vec<EntryStatus>,
}

impl RecorderStatus {
    pub fn not_attempted() -> Self {
        Self {
            state: RecorderState::NotAttempted,
            reason: None,
            last_attempt_at: None,
            entries: Vec::new(),
        }
    }

    pub fn from_entries(
        entries: Vec<EntryStatus>,
        last_attempt_at: Option<String>,
    ) -> Self {
        let (state, reason) = overall(&entries);
        Self {
            state,
            reason,
            last_attempt_at,
            entries,
        }
    }
}

fn overall(entries: &[EntryStatus]) -> (RecorderState, Option<RecorderReason>) {
    let Some(first) = entries.first() else {
        return (RecorderState::NotAttempted, None);
    };
    if entries
        .iter()
        .all(|e| e.state == first.state)
    {
        return (first.state, reason_for(entries, first.state));
    }
    let has = |state: RecorderState| {
        entries
            .iter()
            .any(|e| e.state == state)
    };
    if has(RecorderState::Recorded) || has(RecorderState::Partial) {
        return (RecorderState::Partial, None);
    }
    let state = if has(RecorderState::Failed) {
        RecorderState::Failed
    } else {
        RecorderState::Skipped
    };
    (state, reason_for(entries, state))
}

fn reason_for(
    entries: &[EntryStatus],
    state: RecorderState,
) -> Option<RecorderReason> {
    if !matches!(state, RecorderState::Failed | RecorderState::Skipped) {
        return None;
    }
    entries
        .iter()
        .find(|e| e.state == state)
        .and_then(|e| e.reason)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRecord {
    id: String,
    surface_id: String,
    agent_did: String,
    status: RecorderStatus,
    changed_at: String,
}

impl StorableEntity for StatusRecord {
    fn id(&self) -> &str {
        &self.id
    }
}

fn record_key(
    surface_id: &str,
    agent_did: &str,
) -> String {
    let digest = Sha256::digest(format!("{surface_id}\n{agent_did}").as_bytes());
    format!("{digest:x}")
}

/// How long a cleared surface is remembered, which only has to outlast one recorder run.
const CLEARED_MEMORY: chrono::Duration = chrono::Duration::hours(1);

pub struct TrustRecorderStatusStore {
    backend: Box<dyn StorageBackend<StatusRecord>>,
    last_attempts: DashMap<String, DateTime<Utc>>,
    cleared_surfaces: DashMap<String, DateTime<Utc>>,
}

impl TrustRecorderStatusStore {
    pub async fn open(dir: PathBuf) -> Result<Self> {
        Ok(Self {
            backend: cached_storage(dir, "trust recorder status").await?,
            last_attempts: DashMap::new(),
            cleared_surfaces: DashMap::new(),
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            backend: crate::storage::filesystem::in_memory_storage(),
            last_attempts: DashMap::new(),
            cleared_surfaces: DashMap::new(),
        }
    }

    #[cfg(test)]
    fn with_backend(backend: Box<dyn StorageBackend<StatusRecord>>) -> Self {
        Self {
            backend,
            last_attempts: DashMap::new(),
            cleared_surfaces: DashMap::new(),
        }
    }

    /// Stores the outcome of a recorder run that began at `started_at`. Returns `true`
    /// when the outcome differs from the stored one and was persisted. An outcome of a
    /// run that began before its surface was cleared is dropped, so a run still waiting on
    /// a trust registry cannot bring back a status for a deleted or reconfigured surface.
    pub async fn record(
        &self,
        surface_id: &str,
        agent_did: &str,
        entries: Vec<EntryStatus>,
        started_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        if entries.is_empty() || self.cleared_since(surface_id, started_at) {
            return Ok(false);
        }
        let key = record_key(surface_id, agent_did);
        self.last_attempts
            .insert(key.clone(), now);
        let status = RecorderStatus::from_entries(entries, None);
        let unchanged = self
            .backend
            .get(&key)
            .await?
            .is_some_and(|stored| stored.status == status);
        if unchanged {
            return Ok(false);
        }
        self.backend
            .save(&StatusRecord {
                id: key.clone(),
                surface_id: surface_id.to_string(),
                agent_did: agent_did.to_string(),
                status,
                changed_at: now.to_rfc3339(),
            })
            .await?;
        if self.cleared_since(surface_id, started_at) {
            self.last_attempts
                .remove(&key);
            self.delete_record(&key).await;
            return Ok(false);
        }
        Ok(true)
    }

    pub async fn status_for(
        &self,
        surface_id: &str,
        agent_did: &str,
    ) -> Option<RecorderStatus> {
        let key = record_key(surface_id, agent_did);
        let record = match self.backend.get(&key).await {
            Ok(record) => record?,
            Err(e) => {
                warn!(surface_id = %surface_id, error = %e, "Trust Recorder status store: reading a status failed");
                return None;
            }
        };
        Some(self.with_last_attempt(record))
    }

    pub async fn latest_for_surface(
        &self,
        surface_id: &str,
    ) -> Option<RecorderStatus> {
        let records = self.list_records().await?;
        records
            .into_iter()
            .filter(|r| r.surface_id == surface_id)
            .map(|r| self.with_last_attempt(r))
            .max_by(|a, b| {
                a.last_attempt_at
                    .cmp(&b.last_attempt_at)
            })
    }

    pub async fn changed_dids_since(
        &self,
        since: DateTime<Utc>,
    ) -> HashSet<String> {
        let Some(records) = self.list_records().await else {
            return HashSet::new();
        };
        records
            .into_iter()
            .filter(|r| {
                DateTime::parse_from_rfc3339(&r.changed_at).is_ok_and(|changed| changed.with_timezone(&Utc) > since)
            })
            .map(|r| r.agent_did)
            .collect()
    }

    /// Drops every status of the surface, and the outcome of any run that began before now.
    pub async fn clear_surface(
        &self,
        surface_id: &str,
    ) {
        let now = Utc::now();
        self.cleared_surfaces
            .retain(|_, cleared_at| now - *cleared_at < CLEARED_MEMORY);
        self.cleared_surfaces
            .insert(surface_id.to_string(), now);
        let Some(records) = self.list_records().await else {
            return;
        };
        for record in records
            .into_iter()
            .filter(|r| r.surface_id == surface_id)
        {
            self.last_attempts
                .remove(&record.id);
            self.delete_record(&record.id)
                .await;
        }
    }

    fn cleared_since(
        &self,
        surface_id: &str,
        since: DateTime<Utc>,
    ) -> bool {
        self.cleared_surfaces
            .get(surface_id)
            .is_some_and(|cleared_at| *cleared_at >= since)
    }

    async fn list_records(&self) -> Option<Vec<StatusRecord>> {
        match self.backend.list_all().await {
            Ok(records) => Some(records),
            Err(e) => {
                warn!(error = %e, "Trust Recorder status store: listing statuses failed");
                None
            }
        }
    }

    async fn delete_record(
        &self,
        id: &str,
    ) {
        if let Err(e) = self.backend.delete(id).await {
            warn!(error = %e, "Trust Recorder status store: deleting a status failed");
        }
    }

    fn with_last_attempt(
        &self,
        record: StatusRecord,
    ) -> RecorderStatus {
        let persisted = DateTime::parse_from_rfc3339(&record.changed_at)
            .ok()
            .map(|t| t.with_timezone(&Utc));
        let in_memory = self
            .last_attempts
            .get(&record.id)
            .map(|t| *t);
        let last = in_memory
            .into_iter()
            .chain(persisted)
            .max();
        RecorderStatus {
            last_attempt_at: last.map(|t| t.to_rfc3339()),
            ..record.status
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000 + secs, 0)
            .unwrap()
    }

    fn written(
        registry: &str,
        created: u32,
        existed: u32,
    ) -> EntryStatus {
        EntryStatus::from_counts(registry, created, existed, 0, None)
    }

    fn failed(
        registry: &str,
        reason: RecorderReason,
    ) -> EntryStatus {
        EntryStatus::from_counts(registry, 0, 0, 2, Some(reason))
    }

    #[test]
    fn entry_with_only_writes_is_recorded_and_has_no_reason() {
        let entry = written("tr-1", 1, 2);
        assert_eq!(entry.state, RecorderState::Recorded);
        assert_eq!(entry.reason, None);
        assert_eq!((entry.created, entry.already_existed, entry.failed), (1, 2, 0));
    }

    #[test]
    fn entry_with_writes_and_failures_is_partial_and_keeps_the_failure_reason() {
        let entry = EntryStatus::from_counts("tr-1", 1, 0, 1, Some(RecorderReason::Rejected));
        assert_eq!(entry.state, RecorderState::Partial);
        assert_eq!(entry.reason, Some(RecorderReason::Rejected));
    }

    #[test]
    fn entry_with_only_failures_is_failed_and_defaults_the_reason_to_error() {
        let entry = EntryStatus::from_counts("tr-1", 0, 0, 3, None);
        assert_eq!(entry.state, RecorderState::Failed);
        assert_eq!(entry.reason, Some(RecorderReason::Error));
    }

    #[test]
    fn skipped_entry_carries_its_reason_and_zero_counts() {
        let entry = EntryStatus::skipped("tr-1", RecorderReason::NoSurfaceIssuer);
        assert_eq!(entry.state, RecorderState::Skipped);
        assert_eq!(entry.reason, Some(RecorderReason::NoSurfaceIssuer));
        assert_eq!((entry.created, entry.already_existed, entry.failed), (0, 0, 0));
    }

    #[test]
    fn overall_status_without_entries_is_not_attempted() {
        let status = RecorderStatus::from_entries(vec![], None);
        assert_eq!(status.state, RecorderState::NotAttempted);
        assert_eq!(status.reason, None);
    }

    #[test]
    fn overall_status_of_identical_entry_states_keeps_that_state() {
        let status = RecorderStatus::from_entries(vec![written("a", 1, 0), written("b", 0, 1)], None);
        assert_eq!((status.state, status.reason), (RecorderState::Recorded, None));

        let status = RecorderStatus::from_entries(
            vec![failed("a", RecorderReason::NoResponse), failed("b", RecorderReason::Rejected)],
            None,
        );
        assert_eq!((status.state, status.reason), (RecorderState::Failed, Some(RecorderReason::NoResponse)));

        let status = RecorderStatus::from_entries(
            vec![
                EntryStatus::skipped("a", RecorderReason::RegistryNotConnected),
                EntryStatus::skipped("b", RecorderReason::NoSurfaceIssuer),
            ],
            None,
        );
        assert_eq!((status.state, status.reason), (RecorderState::Skipped, Some(RecorderReason::RegistryNotConnected)));
    }

    #[test]
    fn overall_status_mixing_written_and_unwritten_entries_is_partial_without_a_reason() {
        let status =
            RecorderStatus::from_entries(vec![written("a", 1, 0), failed("b", RecorderReason::NoResponse)], None);
        assert_eq!((status.state, status.reason), (RecorderState::Partial, None));

        let status = RecorderStatus::from_entries(
            vec![written("a", 1, 0), EntryStatus::skipped("b", RecorderReason::RegistryNotFound)],
            None,
        );
        assert_eq!((status.state, status.reason), (RecorderState::Partial, None));
    }

    #[test]
    fn overall_status_mixing_failed_and_skipped_entries_is_failed_with_the_failure_reason() {
        let status = RecorderStatus::from_entries(
            vec![
                EntryStatus::skipped("a", RecorderReason::RegistryNotConnected),
                failed("b", RecorderReason::Rejected),
            ],
            None,
        );
        assert_eq!((status.state, status.reason), (RecorderState::Failed, Some(RecorderReason::Rejected)));
    }

    #[test]
    fn serialized_status_uses_the_snake_case_contract_the_dashboard_reads() {
        let status = RecorderStatus::from_entries(
            vec![EntryStatus::from_counts("tr-1", 1, 2, 3, Some(RecorderReason::NoResponse))],
            Some("2026-10-16T10:00:00+00:00".to_string()),
        );
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({
                "state": "partial",
                "reason": null,
                "last_attempt_at": "2026-10-16T10:00:00+00:00",
                "entries": [{
                    "trust_registry_id": "tr-1",
                    "state": "partial",
                    "reason": "no_response",
                    "created": 1,
                    "already_existed": 2,
                    "failed": 3
                }]
            })
        );
        let not_attempted = serde_json::to_value(RecorderStatus::not_attempted()).unwrap();
        assert_eq!(not_attempted["state"], "not_attempted");
    }

    #[tokio::test]
    async fn recording_an_outcome_makes_it_readable_with_the_attempt_time() {
        let store = TrustRecorderStatusStore::in_memory();
        assert!(
            store
                .record("surface-1", "did:example:agent", vec![written("tr-1", 1, 0)], at(0), at(0))
                .await
                .unwrap()
        );

        let status = store
            .status_for("surface-1", "did:example:agent")
            .await
            .unwrap();
        assert_eq!(status.state, RecorderState::Recorded);
        assert_eq!(status.last_attempt_at, Some(at(0).to_rfc3339()));
        assert_eq!(status.entries, vec![written("tr-1", 1, 0)]);
    }

    #[tokio::test]
    async fn status_is_scoped_to_the_surface_and_the_agent() {
        let store = TrustRecorderStatusStore::in_memory();
        store
            .record("surface-1", "did:example:agent", vec![written("tr-1", 1, 0)], at(0), at(0))
            .await
            .unwrap();

        assert!(
            store
                .status_for("surface-2", "did:example:agent")
                .await
                .is_none()
        );
        assert!(
            store
                .status_for("surface-1", "did:example:other")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn repeating_an_unchanged_outcome_does_not_persist_but_moves_the_attempt_time() {
        let store = TrustRecorderStatusStore::in_memory();
        let entries = vec![written("tr-1", 0, 1)];
        assert!(
            store
                .record("surface-1", "did:example:agent", entries.clone(), at(0), at(0))
                .await
                .unwrap()
        );

        assert!(
            !store
                .record("surface-1", "did:example:agent", entries, at(60), at(60))
                .await
                .unwrap()
        );

        let status = store
            .status_for("surface-1", "did:example:agent")
            .await
            .unwrap();
        assert_eq!(status.last_attempt_at, Some(at(60).to_rfc3339()));
        assert!(
            store
                .changed_dids_since(at(30))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_changed_outcome_is_persisted_and_reported_as_changed() {
        let store = TrustRecorderStatusStore::in_memory();
        store
            .record("surface-1", "did:example:agent", vec![written("tr-1", 1, 0)], at(0), at(0))
            .await
            .unwrap();

        assert!(
            store
                .record(
                    "surface-1",
                    "did:example:agent",
                    vec![failed("tr-1", RecorderReason::NoResponse)],
                    at(60),
                    at(60),
                )
                .await
                .unwrap()
        );

        let status = store
            .status_for("surface-1", "did:example:agent")
            .await
            .unwrap();
        assert_eq!((status.state, status.reason), (RecorderState::Failed, Some(RecorderReason::NoResponse)));
        assert_eq!(
            store
                .changed_dids_since(at(30))
                .await,
            HashSet::from(["did:example:agent".to_string()])
        );
    }

    #[tokio::test]
    async fn recording_no_entries_stores_nothing() {
        let store = TrustRecorderStatusStore::in_memory();
        assert!(
            !store
                .record("surface-1", "did:example:agent", vec![], at(0), at(0))
                .await
                .unwrap()
        );
        assert!(
            store
                .status_for("surface-1", "did:example:agent")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_latest_status_of_a_surface_is_the_one_attempted_most_recently() {
        let store = TrustRecorderStatusStore::in_memory();
        store
            .record("surface-1", "did:example:old", vec![written("tr-1", 1, 0)], at(0), at(0))
            .await
            .unwrap();
        store
            .record("surface-1", "did:example:new", vec![failed("tr-1", RecorderReason::Rejected)], at(120), at(120))
            .await
            .unwrap();
        store
            .record("surface-2", "did:example:other", vec![written("tr-1", 1, 0)], at(300), at(300))
            .await
            .unwrap();

        let latest = store
            .latest_for_surface("surface-1")
            .await
            .unwrap();
        assert_eq!(latest.state, RecorderState::Failed);
        assert_eq!(latest.last_attempt_at, Some(at(120).to_rfc3339()));
        assert!(
            store
                .latest_for_surface("surface-9")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn removing_a_surface_removes_only_its_statuses() {
        let store = TrustRecorderStatusStore::in_memory();
        for (surface, did) in [("s1", "did:a"), ("s1", "did:b"), ("s2", "did:a")] {
            store
                .record(surface, did, vec![written("tr-1", 1, 0)], at(0), at(0))
                .await
                .unwrap();
        }

        store
            .clear_surface("s1")
            .await;
        assert!(
            store
                .status_for("s1", "did:a")
                .await
                .is_none()
        );
        assert!(
            store
                .status_for("s1", "did:b")
                .await
                .is_none()
        );
        assert!(
            store
                .status_for("s2", "did:a")
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn the_status_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("trust_recorder_status");
        {
            let store = TrustRecorderStatusStore::open(path.clone())
                .await
                .unwrap();
            store
                .record("surface-1", "did:example:agent", vec![written("tr-1", 2, 0)], at(0), at(0))
                .await
                .unwrap();
        }

        let reopened = TrustRecorderStatusStore::open(path)
            .await
            .unwrap();
        let status = reopened
            .status_for("surface-1", "did:example:agent")
            .await
            .unwrap();
        assert_eq!(status.state, RecorderState::Recorded);
        assert_eq!(status.entries, vec![written("tr-1", 2, 0)]);
        assert_eq!(status.last_attempt_at, Some(at(0).to_rfc3339()));
    }

    #[tokio::test]
    async fn storage_keys_are_filesystem_safe_for_dids_and_surface_ids() {
        let store = TrustRecorderStatusStore::in_memory();
        let did = "did:web:gw.example.com:ids:../../etc/passwd";
        store
            .record("surface/with:odd chars", did, vec![written("tr-1", 1, 0)], at(0), at(0))
            .await
            .unwrap();
        assert!(
            store
                .status_for("surface/with:odd chars", did)
                .await
                .is_some()
        );
        let key = record_key("surface/with:odd chars", did);
        assert_eq!(key.len(), 64);
        assert!(
            key.chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[tokio::test]
    async fn a_run_that_began_before_its_surface_was_cleared_is_dropped() {
        let store = TrustRecorderStatusStore::in_memory();
        let started_at = Utc::now();
        store
            .clear_surface("s1")
            .await;

        let stored = store
            .record("s1", "did:a", vec![written("tr-1", 1, 0)], started_at, Utc::now())
            .await
            .unwrap();

        assert!(!stored);
        assert!(
            store
                .status_for("s1", "did:a")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_run_that_begins_after_the_clear_is_recorded() {
        let store = TrustRecorderStatusStore::in_memory();
        store
            .clear_surface("s1")
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let stored = store
            .record("s1", "did:a", vec![written("tr-1", 1, 0)], Utc::now(), Utc::now())
            .await
            .unwrap();

        assert!(stored);
        assert!(
            store
                .status_for("s1", "did:a")
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn clearing_a_surface_does_not_hold_back_runs_of_other_surfaces() {
        let store = TrustRecorderStatusStore::in_memory();
        let started_at = Utc::now();
        store
            .clear_surface("s1")
            .await;

        assert!(
            store
                .record("s2", "did:a", vec![written("tr-1", 1, 0)], started_at, Utc::now())
                .await
                .unwrap()
        );
    }

    struct ScriptedBackend {
        inner: Box<dyn StorageBackend<StatusRecord>>,
        fail_reads: Arc<std::sync::atomic::AtomicBool>,
        fail_deletes: Arc<std::sync::atomic::AtomicBool>,
        pause_save: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
    }

    impl ScriptedBackend {
        fn new() -> Self {
            Self {
                inner: crate::storage::filesystem::in_memory_storage(),
                fail_reads: Arc::default(),
                fail_deletes: Arc::default(),
                pause_save: None,
            }
        }

        fn failing(flag: &std::sync::atomic::AtomicBool) -> Result<()> {
            if flag.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("disk unavailable");
            }
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend<StatusRecord> for ScriptedBackend {
        async fn save(
            &self,
            entity: &StatusRecord,
        ) -> Result<()> {
            if let Some((saving, proceed)) = &self.pause_save {
                saving.notify_one();
                proceed.notified().await;
            }
            self.inner.save(entity).await
        }

        async fn get(
            &self,
            id: &str,
        ) -> Result<Option<StatusRecord>> {
            Self::failing(&self.fail_reads)?;
            self.inner.get(id).await
        }

        async fn list_all(&self) -> Result<Vec<StatusRecord>> {
            Self::failing(&self.fail_reads)?;
            self.inner.list_all().await
        }

        async fn delete(
            &self,
            id: &str,
        ) -> Result<()> {
            Self::failing(&self.fail_deletes)?;
            self.inner.delete(id).await
        }
    }

    #[tokio::test]
    async fn an_outcome_saved_while_its_surface_is_being_cleared_is_removed_again() {
        let saving = Arc::new(tokio::sync::Notify::new());
        let proceed = Arc::new(tokio::sync::Notify::new());
        let mut backend = ScriptedBackend::new();
        backend.pause_save = Some((saving.clone(), proceed.clone()));
        let store = Arc::new(TrustRecorderStatusStore::with_backend(Box::new(backend)));

        let started_at = Utc::now();
        let run = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .record("s1", "did:a", vec![written("tr-1", 1, 0)], started_at, Utc::now())
                    .await
            })
        };
        saving.notified().await;
        store
            .clear_surface("s1")
            .await;
        proceed.notify_one();

        assert!(!run.await.unwrap().unwrap());
        assert!(
            store
                .status_for("s1", "did:a")
                .await
                .is_none()
        );
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Captured {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Message(String);
            impl tracing::field::Visit for Message {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0
                .lock()
                .unwrap()
                .push((*event.metadata().level(), message.0));
        }
    }

    fn warnings(captured: &Captured) -> Vec<String> {
        captured
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(level, _)| *level == tracing::Level::WARN)
            .map(|(_, message)| message.clone())
            .collect()
    }

    #[tokio::test]
    async fn a_failing_disk_is_logged_and_reads_as_missing_instead_of_as_not_attempted_silently() {
        use tracing_subscriber::layer::SubscriberExt;
        let captured = Captured::default();
        let _guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));
        let backend = ScriptedBackend::new();
        let (fail_reads, fail_deletes) = (backend.fail_reads.clone(), backend.fail_deletes.clone());
        let store = TrustRecorderStatusStore::with_backend(Box::new(backend));
        store
            .record("s1", "did:a", vec![written("tr-1", 1, 0)], at(0), at(0))
            .await
            .unwrap();

        fail_reads.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            store
                .status_for("s1", "did:a")
                .await
                .is_none()
        );
        assert!(
            store
                .latest_for_surface("s1")
                .await
                .is_none()
        );
        assert!(
            store
                .changed_dids_since(at(-60))
                .await
                .is_empty()
        );
        store
            .clear_surface("s1")
            .await;
        assert_eq!(
            warnings(&captured),
            vec![
                "Trust Recorder status store: reading a status failed",
                "Trust Recorder status store: listing statuses failed",
                "Trust Recorder status store: listing statuses failed",
                "Trust Recorder status store: listing statuses failed",
            ]
        );

        fail_reads.store(false, std::sync::atomic::Ordering::SeqCst);
        fail_deletes.store(true, std::sync::atomic::Ordering::SeqCst);
        store
            .clear_surface("s1")
            .await;
        assert_eq!(
            warnings(&captured)
                .last()
                .map(String::as_str),
            Some("Trust Recorder status store: deleting a status failed")
        );
    }
}
