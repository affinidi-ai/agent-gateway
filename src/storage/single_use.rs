//! Durable single-use records: a key recorded once is refused again until its
//! expiry, across restarts and, with DynamoDB, across nodes.
//!
//! Each [`Namespace`] keeps its own keys. An in-memory map sits in front of
//! the backend: it refuses a duplicate without a backend call and is pruned of
//! expired keys. With the disk backend it holds every live key, read back from
//! the journals at startup; with DynamoDB it caches the keys this node has seen
//! and the table decides the rest.
//!
//! The disk backend keeps one append-only journal per namespace. Every record
//! and forget line is synced before the call returns. At startup the journals
//! are read back, expired and forgotten keys dropped, and each journal is
//! atomically rewritten with only its live keys; a journal that outgrows its
//! live keys is rewritten the same way while the gateway runs.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use serde::{Deserialize, Serialize};

const PRUNE_INTERVAL_SECS: u64 = 60;
const COMPACT_SLACK: usize = 4096;
const DYNAMODB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const EXPIRES_AT: &str = "expires_at";

/// What a key is single-use for. Keys of different namespaces never collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Namespace {
    IdJag,
    McpIdJag,
    FabricEnvelope,
    VoidedEvidence,
}

impl Namespace {
    const ALL: [Self; 4] = [Self::IdJag, Self::McpIdJag, Self::FabricEnvelope, Self::VoidedEvidence];

    pub fn name(self) -> &'static str {
        match self {
            Self::IdJag => "id-jag",
            Self::McpIdJag => "mcp-id-jag",
            Self::FabricEnvelope => "fabric-envelope",
            Self::VoidedEvidence => "voided-evidence",
        }
    }

    fn record_type(self) -> &'static str {
        match self {
            Self::IdJag => "SingleUseIdJag",
            Self::McpIdJag => "SingleUseMcpIdJag",
            Self::FabricEnvelope => "SingleUseFabricEnvelope",
            Self::VoidedEvidence => "SingleUseVoidedEvidence",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SingleUseError {
    #[error("the single-use store is not open")]
    Unavailable,
    #[error("the single-use store failed: {0}")]
    Storage(String),
    #[error("{0}")]
    Config(String),
}

/// `single_use_store` in `gateway.json`: where single-use records are kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum SingleUseStoreConfig {
    Disk {},
    Dynamodb { table: String },
}

impl Default for SingleUseStoreConfig {
    fn default() -> Self {
        Self::Disk {}
    }
}

impl SingleUseStoreConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn validate(&self) -> Result<(), SingleUseError> {
        match self {
            Self::Disk {} => Ok(()),
            Self::Dynamodb { table } if is_valid_table_name(table) => Ok(()),
            Self::Dynamodb { .. } => Err(SingleUseError::Config(
                "single_use_store.table must be a DynamoDB table name of 3 to 255 letters, digits, '_', '-' or '.'"
                    .into(),
            )),
        }
    }

    /// Refuses a configuration whose continuations are shared through DynamoDB
    /// while single-use records stay on this node's disk: another node would
    /// accept continuation evidence of an authorization voided here.
    pub fn check_shared_with(
        &self,
        continuations: Option<&crate::mcp::continuations::config::ContinuationStorageConfig>,
    ) -> Result<(), SingleUseError> {
        match (self, continuations) {
            (Self::Disk {}, Some(crate::mcp::continuations::config::ContinuationStorageConfig::Dynamodb { .. })) => {
                Err(SingleUseError::Config(
                    "mcp.continuations.storage uses DynamoDB but single_use_store keeps records on this node's disk, \
                     so voided payment evidence would not be shared between nodes; set single_use_store to \
                     {\"backend\":\"dynamodb\",\"table\":\"...\"}"
                        .into(),
                ))
            }
            _ => Ok(()),
        }
    }
}

pub fn is_valid_table_name(table: &str) -> bool {
    (3..=255).contains(&table.len())
        && table
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

type Slot = (Namespace, [u8; 32]);

pub struct SingleUseStore {
    memory: DashMap<Slot, u64>,
    forgetting: DashMap<Slot, Arc<tokio::sync::Mutex<()>>>,
    next_prune_at: AtomicU64,
    backend: Backend,
}

enum Backend {
    Disk(HashMap<Namespace, tokio::sync::Mutex<Journal>>),
    Dynamodb {
        client: aws_sdk_dynamodb::Client,
        table: String,
    },
    #[cfg(test)]
    Memory {
        fail: bool,
    },
}

impl std::fmt::Debug for SingleUseStore {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        formatter.write_str(match self.backend {
            Backend::Disk(_) => "SingleUseStore::Disk",
            Backend::Dynamodb { .. } => "SingleUseStore::Dynamodb",
            #[cfg(test)]
            Backend::Memory { .. } => "SingleUseStore::Memory",
        })
    }
}

impl SingleUseStore {
    fn with_backend(backend: Backend) -> Self {
        Self {
            memory: DashMap::new(),
            forgetting: DashMap::new(),
            next_prune_at: AtomicU64::new(0),
            backend,
        }
    }

    /// Opens the store `config` selects; disk journals live in `dir`.
    pub async fn open(
        config: &SingleUseStoreConfig,
        dir: &Path,
        dynamodb: Option<aws_sdk_dynamodb::Client>,
        now: u64,
    ) -> Result<Self, SingleUseError> {
        config.validate()?;
        match config {
            SingleUseStoreConfig::Disk {} => Self::open_disk(dir, now).await,
            SingleUseStoreConfig::Dynamodb { table } => Ok(Self::with_backend(Backend::Dynamodb {
                client: dynamodb.ok_or(SingleUseError::Unavailable)?,
                table: table.clone(),
            })),
        }
    }

    async fn open_disk(
        dir: &Path,
        now: u64,
    ) -> Result<Self, SingleUseError> {
        crate::audit::journal::create_owner_only_dir(dir).map_err(storage_error)?;
        let memory = DashMap::new();
        let mut journals = HashMap::new();
        for namespace in Namespace::ALL {
            let path = dir.join(format!("{}.jsonl", namespace.name()));
            let live = read_journal(&path, now).map_err(storage_error)?;
            let journal = Journal::rewrite(path, &live).await?;
            for (key, expires_at) in live {
                memory.insert((namespace, key), expires_at);
            }
            journals.insert(namespace, tokio::sync::Mutex::new(journal));
        }
        Ok(Self {
            memory,
            ..Self::with_backend(Backend::Disk(journals))
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self::with_backend(Backend::Memory { fail: false })
    }

    #[cfg(test)]
    pub fn failing() -> Self {
        Self::with_backend(Backend::Memory { fail: true })
    }

    /// Records `key` until `expires_at`: `true` when this is its first use,
    /// `false` when it is recorded and has not expired.
    pub async fn record_unique(
        &self,
        namespace: Namespace,
        key: &[u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<bool, SingleUseError> {
        let slot = (namespace, *key);
        self.wait_for_forget(&slot)
            .await;
        self.prune(now);
        match self.memory.entry(slot) {
            Entry::Occupied(recorded) if *recorded.get() > now => return Ok(false),
            Entry::Occupied(mut expired) => {
                expired.insert(expires_at);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(expires_at);
            }
        }
        let persisted = match &self.backend {
            Backend::Disk(journals) => self
                .append(journals, namespace, &JournalLine::recorded(key, expires_at), now)
                .await
                .map(|()| true),
            Backend::Dynamodb { client, table } => {
                dynamodb_record(client, table, namespace, key, expires_at, now).await
            }
            #[cfg(test)]
            Backend::Memory { fail } => {
                if *fail {
                    Err(SingleUseError::Storage("test store refuses writes".into()))
                } else {
                    Ok(true)
                }
            }
        };
        if persisted.is_err() {
            self.memory
                .remove_if(&slot, |_, recorded| *recorded == expires_at);
        }
        persisted
    }

    /// Whether `key` is recorded and has not expired.
    pub async fn is_recorded(
        &self,
        namespace: Namespace,
        key: &[u8; 32],
        now: u64,
    ) -> Result<bool, SingleUseError> {
        let slot = (namespace, *key);
        self.wait_for_forget(&slot)
            .await;
        if self.holds(namespace, key, now) {
            return Ok(true);
        }
        match &self.backend {
            Backend::Dynamodb { client, table } => {
                let expires_at = dynamodb_expiry(client, table, namespace, key).await?;
                match expires_at {
                    Some(expires_at) if expires_at > now => {
                        self.memory
                            .insert(slot, expires_at);
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    /// Whether this node holds `key` as recorded and unexpired, without asking
    /// the backend. With the disk backend this is the whole answer.
    pub fn holds(
        &self,
        namespace: Namespace,
        key: &[u8; 32],
        now: u64,
    ) -> bool {
        self.memory
            .get(&(namespace, *key))
            .is_some_and(|expires_at| *expires_at > now)
    }

    /// Forgets `key`, so its next use is a first use: at once on this node,
    /// and in the backend as soon as a task can run, without blocking. A later
    /// call for the same key waits for that backend forget first, so it never
    /// sees the key as still recorded.
    pub fn forget_in_background(
        self: &Arc<Self>,
        namespace: Namespace,
        key: &[u8; 32],
    ) {
        let slot = (namespace, *key);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.memory.remove(&slot);
            tracing::warn!(
                namespace = namespace.name(),
                "A single-use record was forgotten outside a runtime; it stays recorded in the store"
            );
            return;
        };
        let pending = Arc::new(tokio::sync::Mutex::new(()));
        let Ok(held) = Arc::clone(&pending).try_lock_owned() else {
            return;
        };
        self.forgetting
            .insert(slot, Arc::clone(&pending));
        self.memory.remove(&slot);
        let store = Arc::clone(self);
        runtime.spawn(async move {
            if let Err(error) = store
                .forget_in_backend(namespace, &slot.1)
                .await
            {
                tracing::error!(namespace = namespace.name(), %error, "Failed to forget a single-use record");
            }
            store
                .forgetting
                .remove_if(&slot, |_, waiting| Arc::ptr_eq(waiting, &pending));
            drop(held);
        });
    }

    async fn wait_for_forget(
        &self,
        slot: &Slot,
    ) {
        let pending = self
            .forgetting
            .get(slot)
            .map(|pending| Arc::clone(&pending));
        if let Some(pending) = pending {
            let _ = pending.lock().await;
        }
    }

    async fn forget_in_backend(
        &self,
        namespace: Namespace,
        key: &[u8; 32],
    ) -> Result<(), SingleUseError> {
        match &self.backend {
            Backend::Disk(journals) => {
                self.append(journals, namespace, &JournalLine::forgotten(key), 0)
                    .await
            }
            Backend::Dynamodb { client, table } => dynamodb_forget(client, table, namespace, key).await,
            #[cfg(test)]
            Backend::Memory { .. } => Ok(()),
        }
    }

    fn prune(
        &self,
        now: u64,
    ) {
        let due = self
            .next_prune_at
            .load(Ordering::Acquire);
        if now >= due
            && self
                .next_prune_at
                .compare_exchange(due, now + PRUNE_INTERVAL_SECS, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.memory
                .retain(|_, expires_at| *expires_at > now);
        }
    }

    /// Writes `line` to the namespace's journal and syncs it. A journal that
    /// has outgrown its live keys is first rewritten with only those.
    async fn append(
        &self,
        journals: &HashMap<Namespace, tokio::sync::Mutex<Journal>>,
        namespace: Namespace,
        line: &JournalLine,
        now: u64,
    ) -> Result<(), SingleUseError> {
        let journal = journals
            .get(&namespace)
            .ok_or(SingleUseError::Unavailable)?;
        let mut journal = journal.lock().await;
        if journal.lines >= journal.compact_at {
            let live: Vec<([u8; 32], u64)> = self
                .memory
                .iter()
                .filter(|entry| entry.key().0 == namespace && *entry.value() > now)
                .map(|entry| (entry.key().1, *entry.value()))
                .collect();
            match Journal::rewrite(journal.path.clone(), &live).await {
                Ok(rewritten) => *journal = rewritten,
                Err(error) => tracing::warn!(
                    namespace = namespace.name(),
                    %error,
                    "Failed to compact a single-use journal"
                ),
            }
        }
        let mut encoded = serde_json::to_vec(line).map_err(storage_error)?;
        encoded.push(b'\n');
        (&*journal.file)
            .write_all(&encoded)
            .map_err(storage_error)?;
        journal.lines += 1;
        let file = Arc::clone(&journal.file);
        drop(journal);
        tokio::task::spawn_blocking(move || file.sync_data())
            .await
            .map_err(storage_error)?
            .map_err(storage_error)
    }
}

fn storage_error(error: impl std::fmt::Display) -> SingleUseError {
    SingleUseError::Storage(error.to_string())
}

#[derive(Serialize, Deserialize)]
struct JournalLine {
    key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    forgotten: bool,
}

impl JournalLine {
    fn recorded(
        key: &[u8; 32],
        expires_at: u64,
    ) -> Self {
        Self {
            key: hex::encode(key),
            expires_at: Some(expires_at),
            forgotten: false,
        }
    }

    fn forgotten(key: &[u8; 32]) -> Self {
        Self {
            key: hex::encode(key),
            expires_at: None,
            forgotten: true,
        }
    }
}

struct Journal {
    path: PathBuf,
    file: Arc<std::fs::File>,
    lines: usize,
    compact_at: usize,
}

impl Journal {
    /// Replaces the journal at `path` with one line per live key and opens it
    /// for appending.
    async fn rewrite(
        path: PathBuf,
        live: &[([u8; 32], u64)],
    ) -> Result<Self, SingleUseError> {
        let mut encoded = Vec::new();
        for (key, expires_at) in live {
            serde_json::to_writer(&mut encoded, &JournalLine::recorded(key, *expires_at)).map_err(storage_error)?;
            encoded.push(b'\n');
        }
        match crate::storage::filesystem::atomic_write_file_with_mode(
            &path,
            &encoded,
            Some(crate::audit::journal::OWNER_ONLY_FILE),
        )
        .await
        {
            Ok(()) => {}
            Err(crate::storage::filesystem::AtomicWriteError::ReplacedButUnsynced(error)) => {
                tracing::warn!("Replaced {} but could not sync its directory: {error:#}", path.display());
            }
            Err(crate::storage::filesystem::AtomicWriteError::NotReplaced(error)) => {
                return Err(storage_error(format!("{error:#}")));
            }
        }
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(storage_error)?;
        Ok(Self {
            path,
            file: Arc::new(file),
            lines: live.len(),
            compact_at: live.len() * 2 + COMPACT_SLACK,
        })
    }
}

/// The live keys of the journal at `path`: recorded, not forgotten since, and
/// not expired at `now`. Lines that do not parse, such as one torn by a crash,
/// are skipped.
fn read_journal(
    path: &Path,
    now: u64,
) -> std::io::Result<Vec<([u8; 32], u64)>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut live: HashMap<[u8; 32], u64> = HashMap::new();
    for line in std::io::BufReader::new(file).lines() {
        let Ok(line) = serde_json::from_str::<JournalLine>(&line?) else {
            continue;
        };
        let Some(key) = hex::decode(&line.key)
            .ok()
            .and_then(|key| <[u8; 32]>::try_from(key).ok())
        else {
            continue;
        };
        match (line.forgotten, line.expires_at) {
            (true, _) => {
                live.remove(&key);
            }
            (false, Some(expires_at)) => {
                live.insert(key, expires_at);
            }
            (false, None) => {}
        }
    }
    Ok(live
        .into_iter()
        .filter(|(_, expires_at)| *expires_at > now)
        .collect())
}

fn dynamodb_key(
    namespace: Namespace,
    key: &[u8; 32],
) -> (String, String) {
    crate::storage::dynamodb_generic_repository::object_key(namespace.record_type(), &hex::encode(key))
}

async fn dynamodb_record(
    client: &aws_sdk_dynamodb::Client,
    table: &str,
    namespace: Namespace,
    key: &[u8; 32],
    expires_at: u64,
    now: u64,
) -> Result<bool, SingleUseError> {
    use crate::storage::dynamodb_generic_repository::{PK, SK};
    use aws_sdk_dynamodb::types::AttributeValue;

    let (partition, sort) = dynamodb_key(namespace, key);
    let result = tokio::time::timeout(
        DYNAMODB_TIMEOUT,
        client
            .put_item()
            .table_name(table)
            .item(PK, AttributeValue::S(partition))
            .item(SK, AttributeValue::S(sort))
            .item(EXPIRES_AT, AttributeValue::N(expires_at.to_string()))
            .condition_expression("attribute_not_exists(#pk) OR #expiry <= :now")
            .expression_attribute_names("#pk", PK)
            .expression_attribute_names("#expiry", EXPIRES_AT)
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send(),
    )
    .await
    .map_err(|_| SingleUseError::Storage("DynamoDB timed out".into()))?;
    match result {
        Ok(_) => Ok(true),
        Err(error)
            if error
                .as_service_error()
                .is_some_and(|error| error.is_conditional_check_failed_exception()) =>
        {
            Ok(false)
        }
        Err(error) => Err(storage_error(aws_sdk_dynamodb::error::DisplayErrorContext(error))),
    }
}

async fn dynamodb_expiry(
    client: &aws_sdk_dynamodb::Client,
    table: &str,
    namespace: Namespace,
    key: &[u8; 32],
) -> Result<Option<u64>, SingleUseError> {
    use crate::storage::dynamodb_generic_repository::{PK, SK};
    use aws_sdk_dynamodb::types::AttributeValue;

    let (partition, sort) = dynamodb_key(namespace, key);
    let output = tokio::time::timeout(
        DYNAMODB_TIMEOUT,
        client
            .get_item()
            .table_name(table)
            .key(PK, AttributeValue::S(partition))
            .key(SK, AttributeValue::S(sort))
            .consistent_read(true)
            .send(),
    )
    .await
    .map_err(|_| SingleUseError::Storage("DynamoDB timed out".into()))?
    .map_err(|error| storage_error(aws_sdk_dynamodb::error::DisplayErrorContext(error)))?;
    let Some(item) = output.item else {
        return Ok(None);
    };
    item.get(EXPIRES_AT)
        .and_then(|value| value.as_n().ok())
        .and_then(|value| value.parse().ok())
        .map(Some)
        .ok_or_else(|| SingleUseError::Storage("DynamoDB record has no expiry".into()))
}

async fn dynamodb_forget(
    client: &aws_sdk_dynamodb::Client,
    table: &str,
    namespace: Namespace,
    key: &[u8; 32],
) -> Result<(), SingleUseError> {
    use crate::storage::dynamodb_generic_repository::{PK, SK};
    use aws_sdk_dynamodb::types::AttributeValue;

    let (partition, sort) = dynamodb_key(namespace, key);
    tokio::time::timeout(
        DYNAMODB_TIMEOUT,
        client
            .delete_item()
            .table_name(table)
            .key(PK, AttributeValue::S(partition))
            .key(SK, AttributeValue::S(sort))
            .send(),
    )
    .await
    .map_err(|_| SingleUseError::Storage("DynamoDB timed out".into()))?
    .map(|_| ())
    .map_err(|error| storage_error(aws_sdk_dynamodb::error::DisplayErrorContext(error)))
}

static STORE: OnceLock<Arc<SingleUseStore>> = OnceLock::new();

/// Makes `store` the process's single-use store. It can be set once.
#[cfg(not(test))]
pub fn install(store: SingleUseStore) -> Result<(), SingleUseError> {
    STORE
        .set(Arc::new(store))
        .map_err(|_| SingleUseError::Config("the single-use store is already open".into()))
}

/// Tests start many gateways in one process, each in its own temporary
/// directory, so they all keep the in-memory store [`global`] provides.
#[cfg(test)]
pub fn install(_store: SingleUseStore) -> Result<(), SingleUseError> {
    global().map(|_| ())
}

/// The process's single-use store; unavailable until [`install`] ran.
#[cfg(not(test))]
pub fn global() -> Result<Arc<SingleUseStore>, SingleUseError> {
    STORE
        .get()
        .cloned()
        .ok_or(SingleUseError::Unavailable)
}

#[cfg(test)]
pub fn global() -> Result<Arc<SingleUseStore>, SingleUseError> {
    Ok(Arc::clone(STORE.get_or_init(|| Arc::new(SingleUseStore::in_memory()))))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    async fn open(dir: &Path) -> SingleUseStore {
        SingleUseStore::open(&SingleUseStoreConfig::Disk {}, dir, None, NOW)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_recorded_key_is_refused_after_reopening_until_it_expires() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path()).await;
        assert!(
            store
                .record_unique(Namespace::IdJag, &key(1), NOW + 60, NOW)
                .await
                .unwrap()
        );
        assert!(
            !store
                .record_unique(Namespace::IdJag, &key(1), NOW + 60, NOW)
                .await
                .unwrap()
        );
        drop(store);

        let reopened = open(dir.path()).await;
        assert!(
            reopened
                .is_recorded(Namespace::IdJag, &key(1), NOW)
                .await
                .unwrap()
        );
        assert!(
            !reopened
                .record_unique(Namespace::IdJag, &key(1), NOW + 60, NOW + 59)
                .await
                .unwrap(),
            "a live key is still recorded after a restart"
        );
        assert!(
            reopened
                .record_unique(Namespace::IdJag, &key(1), NOW + 120, NOW + 60)
                .await
                .unwrap(),
            "an expired key is a first use again"
        );
    }

    #[tokio::test]
    async fn a_forgotten_key_stays_forgotten_after_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(open(dir.path()).await);
        assert!(
            store
                .record_unique(Namespace::FabricEnvelope, &key(2), NOW + 60, NOW)
                .await
                .unwrap()
        );
        store.forget_in_background(Namespace::FabricEnvelope, &key(2));
        assert!(
            !store
                .is_recorded(Namespace::FabricEnvelope, &key(2), NOW)
                .await
                .unwrap()
        );
        drop(store);

        let reopened = open(dir.path()).await;
        assert!(
            reopened
                .record_unique(Namespace::FabricEnvelope, &key(2), NOW + 60, NOW)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_background_forget_lands_before_the_next_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(open(dir.path()).await);
        assert!(
            store
                .record_unique(Namespace::FabricEnvelope, &key(3), NOW + 60, NOW)
                .await
                .unwrap()
        );
        store.forget_in_background(Namespace::FabricEnvelope, &key(3));
        assert!(!store.holds(Namespace::FabricEnvelope, &key(3), NOW));
        assert!(
            store
                .record_unique(Namespace::FabricEnvelope, &key(3), NOW + 60, NOW)
                .await
                .unwrap()
        );
        drop(store);

        let reopened = open(dir.path()).await;
        assert!(
            !reopened
                .record_unique(Namespace::FabricEnvelope, &key(3), NOW + 60, NOW)
                .await
                .unwrap(),
            "the record made after the forget is the one kept"
        );
    }

    #[tokio::test]
    async fn opening_compacts_away_expired_and_forgotten_keys() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(open(dir.path()).await);
        for (byte, expires_at) in [(1, NOW + 10), (2, NOW + 1000), (3, NOW + 1000)] {
            assert!(
                store
                    .record_unique(Namespace::VoidedEvidence, &key(byte), expires_at, NOW)
                    .await
                    .unwrap()
            );
        }
        store.forget_in_background(Namespace::VoidedEvidence, &key(3));
        assert!(
            !store
                .is_recorded(Namespace::VoidedEvidence, &key(3), NOW)
                .await
                .unwrap()
        );
        drop(store);
        let path = dir
            .path()
            .join("voided-evidence.jsonl");
        assert_eq!(
            std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .count(),
            4
        );

        let reopened = SingleUseStore::open(&SingleUseStoreConfig::Disk {}, dir.path(), None, NOW + 100)
            .await
            .unwrap();
        let journal = std::fs::read_to_string(&path).unwrap();
        assert_eq!(journal.lines().count(), 1, "{journal}");
        assert!(journal.contains(&hex::encode(key(2))));
        assert!(reopened.holds(Namespace::VoidedEvidence, &key(2), NOW + 100));
        assert!(!reopened.holds(Namespace::VoidedEvidence, &key(1), NOW + 100));

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn namespaces_are_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path()).await;
        assert!(
            store
                .record_unique(Namespace::IdJag, &key(4), NOW + 60, NOW)
                .await
                .unwrap()
        );
        assert!(
            store
                .record_unique(Namespace::McpIdJag, &key(4), NOW + 60, NOW)
                .await
                .unwrap()
        );
        drop(store);
        let reopened = open(dir.path()).await;
        assert!(reopened.holds(Namespace::IdJag, &key(4), NOW));
        assert!(reopened.holds(Namespace::McpIdJag, &key(4), NOW));
        assert!(!reopened.holds(Namespace::FabricEnvelope, &key(4), NOW));
    }

    #[tokio::test]
    async fn a_failed_write_records_nothing() {
        let store = SingleUseStore::failing();
        assert!(
            store
                .record_unique(Namespace::IdJag, &key(5), NOW + 60, NOW)
                .await
                .is_err()
        );
        assert!(!store.holds(Namespace::IdJag, &key(5), NOW));
    }

    #[test]
    fn config_defaults_to_disk_and_validates_the_table() {
        let config: SingleUseStoreConfig = serde_json::from_value(serde_json::json!({"backend": "disk"})).unwrap();
        assert!(config.is_default());
        let config: SingleUseStoreConfig =
            serde_json::from_value(serde_json::json!({"backend": "dynamodb", "table": "single-use"})).unwrap();
        assert_eq!(config, SingleUseStoreConfig::Dynamodb { table: "single-use".into() });
        assert!(config.validate().is_ok());
        assert!(
            SingleUseStoreConfig::Dynamodb { table: "x".into() }
                .validate()
                .is_err()
        );
        assert!(
            serde_json::from_value::<SingleUseStoreConfig>(serde_json::json!({"backend": "disk", "x": 1})).is_err()
        );
    }

    #[test]
    fn continuations_in_dynamodb_need_a_shared_store() {
        use crate::mcp::continuations::config::ContinuationStorageConfig;

        let dynamodb = ContinuationStorageConfig::Dynamodb { table: "continuations".into() };
        let embedded = ContinuationStorageConfig::Embedded { capacity: 10 };
        assert!(matches!(
            SingleUseStoreConfig::Disk {}.check_shared_with(Some(&dynamodb)),
            Err(SingleUseError::Config(_))
        ));
        assert!(
            SingleUseStoreConfig::Disk {}
                .check_shared_with(Some(&embedded))
                .is_ok()
        );
        assert!(
            SingleUseStoreConfig::Disk {}
                .check_shared_with(None)
                .is_ok()
        );
        assert!(
            SingleUseStoreConfig::Dynamodb { table: "single-use".into() }
                .check_shared_with(Some(&dynamodb))
                .is_ok()
        );
    }
}
