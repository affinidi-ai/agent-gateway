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

pub struct TrustRecorderStatusStore {
    backend: Box<dyn StorageBackend<StatusRecord>>,
    last_attempts: DashMap<String, DateTime<Utc>>,
}

impl TrustRecorderStatusStore {
    pub async fn open(dir: PathBuf) -> Result<Self> {
        Ok(Self {
            backend: cached_storage(dir, "trust recorder status").await?,
            last_attempts: DashMap::new(),
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            backend: crate::storage::filesystem::in_memory_storage(),
            last_attempts: DashMap::new(),
        }
    }

    /// Returns `true` when the outcome differs from the stored one and was persisted.
    pub async fn record(
        &self,
        surface_id: &str,
        agent_did: &str,
        entries: Vec<EntryStatus>,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        if entries.is_empty() {
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
                id: key,
                surface_id: surface_id.to_string(),
                agent_did: agent_did.to_string(),
                status,
                changed_at: now.to_rfc3339(),
            })
            .await?;
        Ok(true)
    }

    pub async fn status_for(
        &self,
        surface_id: &str,
        agent_did: &str,
    ) -> Option<RecorderStatus> {
        let key = record_key(surface_id, agent_did);
        let record = self
            .backend
            .get(&key)
            .await
            .ok()
            .flatten()?;
        Some(self.with_last_attempt(record))
    }

    pub async fn latest_for_surface(
        &self,
        surface_id: &str,
    ) -> Option<RecorderStatus> {
        let records = self
            .backend
            .list_all()
            .await
            .ok()?;
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
        let Ok(records) = self.backend.list_all().await else {
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

    pub async fn remove_surface(
        &self,
        surface_id: &str,
    ) {
        let Ok(records) = self.backend.list_all().await else {
            return;
        };
        for record in records
            .into_iter()
            .filter(|r| r.surface_id == surface_id)
        {
            self.last_attempts
                .remove(&record.id);
            let _ = self
                .backend
                .delete(&record.id)
                .await;
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
                .record("surface-1", "did:example:agent", vec![written("tr-1", 1, 0)], at(0))
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
            .record("surface-1", "did:example:agent", vec![written("tr-1", 1, 0)], at(0))
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
                .record("surface-1", "did:example:agent", entries.clone(), at(0))
                .await
                .unwrap()
        );

        assert!(
            !store
                .record("surface-1", "did:example:agent", entries, at(60))
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
            .record("surface-1", "did:example:agent", vec![written("tr-1", 1, 0)], at(0))
            .await
            .unwrap();

        assert!(
            store
                .record("surface-1", "did:example:agent", vec![failed("tr-1", RecorderReason::NoResponse)], at(60),)
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
                .record("surface-1", "did:example:agent", vec![], at(0))
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
            .record("surface-1", "did:example:old", vec![written("tr-1", 1, 0)], at(0))
            .await
            .unwrap();
        store
            .record("surface-1", "did:example:new", vec![failed("tr-1", RecorderReason::Rejected)], at(120))
            .await
            .unwrap();
        store
            .record("surface-2", "did:example:other", vec![written("tr-1", 1, 0)], at(300))
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
                .record(surface, did, vec![written("tr-1", 1, 0)], at(0))
                .await
                .unwrap();
        }

        store
            .remove_surface("s1")
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
                .record("surface-1", "did:example:agent", vec![written("tr-1", 2, 0)], at(0))
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
            .record("surface/with:odd chars", did, vec![written("tr-1", 1, 0)], at(0))
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
}
