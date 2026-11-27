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
//! and forget line is synced before the call returns. When a store takes the
//! journals over, they are read back, expired and forgotten keys dropped, and
//! each journal is atomically rewritten with only its live keys; a journal
//! that outgrows its live keys by [`COMPACT_SLACK`] lines is rewritten the
//! same way while the gateway runs.
//!
//! The journals belong to one process at a time: the store holding them keeps
//! an exclusive lock on [`LOCK_FILE`] in the journal directory, the way the
//! audit journal does. A store that cannot take the lock, because another
//! instance sharing the volume holds it, has no journals and fails every call
//! until it takes them over. The installed store takes them over while the
//! node is Active, trying again every [`TAKE_OVER_RETRY`] while another
//! instance holds them, and gives them up when the node steps down to Standby.

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
const LOCK_FILE: &str = "single-use.lock";
#[cfg_attr(test, allow(dead_code))]
const TAKE_OVER_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

/// What a key is single-use for. Keys of different namespaces never collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Namespace {
    IdJag,
    McpIdJag,
    FabricEnvelope,
    VoidedEvidence,
    /// Kept in this node's memory only: never journaled or sent to the
    /// backend, and lost on a restart. A disk store also drops them on a
    /// take-over or a step-down, while the replay record's own count of them
    /// still refuses them as used.
    VpProof,
}

impl Namespace {
    const ALL: [Self; 4] = [Self::IdJag, Self::McpIdJag, Self::FabricEnvelope, Self::VoidedEvidence];

    pub fn name(self) -> &'static str {
        match self {
            Self::IdJag => "id-jag",
            Self::McpIdJag => "mcp-id-jag",
            Self::FabricEnvelope => "fabric-envelope",
            Self::VoidedEvidence => "voided-evidence",
            Self::VpProof => "vp-proof",
        }
    }

    fn record_type(self) -> &'static str {
        match self {
            Self::IdJag => "SingleUseIdJag",
            Self::McpIdJag => "SingleUseMcpIdJag",
            Self::FabricEnvelope => "SingleUseFabricEnvelope",
            Self::VoidedEvidence => "SingleUseVoidedEvidence",
            Self::VpProof => "SingleUseVpProof",
        }
    }

    fn is_memory_only(self) -> bool {
        matches!(self, Self::VpProof)
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

/// Where the disk backend keeps its journals: `single_use` in the `_storage`
/// folder that holds the agent surfaces, the folder backups and restores
/// cover, or beside the agent surfaces folder when no `_storage` folder
/// contains it.
pub fn journal_dir(storage_paths: &crate::config::types::StoragePaths) -> PathBuf {
    let surfaces = Path::new(&storage_paths.agent_surfaces);
    let root = crate::export::resolve_storage_root(&storage_paths.agent_surfaces, "");
    let root = if root.file_name() == Some(std::ffi::OsStr::new("_storage")) {
        root
    } else {
        surfaces
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };
    root.join("single_use")
}

type Slot = (Namespace, [u8; 32]);

pub struct SingleUseStore {
    memory: DashMap<Slot, u64>,
    forgetting: DashMap<Slot, Arc<tokio::sync::Mutex<()>>>,
    next_prune_at: AtomicU64,
    backend: Backend,
}

enum Backend {
    Disk(Disk),
    Dynamodb {
        client: aws_sdk_dynamodb::Client,
        table: String,
    },
    #[cfg(test)]
    Memory {
        fail: bool,
    },
}

/// The disk backend: its journal directory and, while this store holds them,
/// the journals.
struct Disk {
    dir: PathBuf,
    held: tokio::sync::RwLock<Option<Journals>>,
}

/// The journals of every namespace and the lock that makes them this
/// process's own; dropping it releases the lock.
struct Journals {
    _lock: std::fs::File,
    by_namespace: HashMap<Namespace, tokio::sync::Mutex<Journal>>,
}

impl Journals {
    fn get(
        &self,
        namespace: Namespace,
    ) -> Result<&tokio::sync::Mutex<Journal>, SingleUseError> {
        self.by_namespace
            .get(&namespace)
            .ok_or(SingleUseError::Unavailable)
    }
}

/// What claiming a key in memory came to.
enum Claim {
    /// The key is recorded and has not expired.
    Taken,
    /// The key is now held in memory until its expiry.
    Claimed,
    /// A forget of the key is still running; claim again once it is done.
    Forgetting,
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

    /// Opens the store `config` selects; disk journals live in `dir`. A disk
    /// store whose journals another process holds opens without them (see
    /// [`SingleUseStore::take_over`]).
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
        let store = Self::with_backend(Backend::Disk(Disk {
            dir: dir.to_path_buf(),
            held: tokio::sync::RwLock::new(None),
        }));
        if !store.take_over(now).await? {
            tracing::warn!(
                path = %dir.display(),
                "Another instance holds the single-use journals; single-use checks fail until this node takes them over"
            );
        }
        Ok(store)
    }

    /// Takes the disk journals over: locks them, reads back their live keys
    /// and compacts them. `Ok(false)` while another process holds the lock.
    /// Other backends have nothing to take over.
    pub async fn take_over(
        &self,
        now: u64,
    ) -> Result<bool, SingleUseError> {
        let Backend::Disk(disk) = &self.backend else {
            return Ok(true);
        };
        let mut held = disk.held.write().await;
        if held.is_some() {
            return Ok(true);
        }
        let Some(lock) = lock_journals(&disk.dir)? else {
            return Ok(false);
        };
        let mut by_namespace = HashMap::new();
        let mut live_keys = Vec::new();
        for namespace in Namespace::ALL {
            let path = disk
                .dir
                .join(format!("{}.jsonl", namespace.name()));
            let live = read_journal(&path, now).map_err(storage_error)?;
            by_namespace.insert(namespace, tokio::sync::Mutex::new(Journal::rewrite(path, &live).await?));
            live_keys.extend(
                live.into_iter()
                    .map(|(key, expires_at)| ((namespace, key), expires_at)),
            );
        }
        self.memory.clear();
        for (slot, expires_at) in live_keys {
            self.memory
                .insert(slot, expires_at);
        }
        *held = Some(Journals { _lock: lock, by_namespace });
        Ok(true)
    }

    /// Gives the disk journals up, releasing their lock for another instance;
    /// every call fails until [`SingleUseStore::take_over`] runs again. Waits
    /// for the calls already using them.
    pub async fn step_down(&self) {
        let Backend::Disk(disk) = &self.backend else {
            return;
        };
        let mut held = disk.held.write().await;
        if held.take().is_some() {
            self.memory.clear();
        }
    }

    /// Whether the store can answer: a disk store only while it holds the
    /// journals.
    pub async fn holds_journals(&self) -> bool {
        match &self.backend {
            Backend::Disk(disk) => disk
                .held
                .read()
                .await
                .is_some(),
            _ => true,
        }
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
        if namespace.is_memory_only() {
            return self
                .record_in_memory(slot, expires_at, now)
                .await;
        }
        loop {
            self.wait_for_forget(&slot)
                .await;
            self.prune(now);
            let recorded = match &self.backend {
                Backend::Disk(disk) => {
                    self.record_on_disk(disk, slot, expires_at, now)
                        .await
                }
                Backend::Dynamodb { client, table } => match self.claim(slot, expires_at, now) {
                    Claim::Taken => Some(Ok(false)),
                    Claim::Forgetting => None,
                    Claim::Claimed => {
                        let persisted = dynamodb_record(client, table, namespace, key, expires_at, now).await;
                        if persisted.is_err() {
                            self.release_claim(&slot, expires_at);
                        }
                        Some(persisted)
                    }
                },
                #[cfg(test)]
                Backend::Memory { fail } => match self.claim(slot, expires_at, now) {
                    Claim::Taken => Some(Ok(false)),
                    Claim::Forgetting => None,
                    Claim::Claimed if *fail => {
                        self.release_claim(&slot, expires_at);
                        Some(Err(SingleUseError::Storage("test store refuses writes".into())))
                    }
                    Claim::Claimed => Some(Ok(true)),
                },
            };
            if let Some(recorded) = recorded {
                return recorded;
            }
        }
    }

    /// Holds `slot` in memory until `expires_at`, writing nothing. A disk store
    /// that does not hold the journals refuses it, as it refuses every record.
    async fn record_in_memory(
        &self,
        slot: Slot,
        expires_at: u64,
        now: u64,
    ) -> Result<bool, SingleUseError> {
        self.prune(now);
        let held = match &self.backend {
            Backend::Disk(disk) => Some(disk.held.read().await),
            Backend::Dynamodb { .. } => {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(
                        namespace = slot.0.name(),
                        "VP replay records are per node: they are kept in this node's memory, not in DynamoDB, so other nodes do not see them"
                    );
                });
                None
            }
            #[cfg(test)]
            Backend::Memory { fail: true } => {
                return Err(SingleUseError::Storage("test store refuses writes".into()));
            }
            #[cfg(test)]
            Backend::Memory { fail: false } => None,
        };
        if held
            .as_ref()
            .is_some_and(|held| held.is_none())
        {
            return Err(SingleUseError::Unavailable);
        }
        match self.claim(slot, expires_at, now) {
            Claim::Taken => Ok(false),
            Claim::Claimed => Ok(true),
            Claim::Forgetting => Err(SingleUseError::Unavailable),
        }
    }

    /// Records `slot` in its journal. The claim and its line are made under
    /// the journal's lock, after any compaction, so a compaction never writes
    /// a key whose own line then fails. A line written but not synced stays
    /// recorded, as a restart would read it. `None` when a forget of the key
    /// is still running.
    async fn record_on_disk(
        &self,
        disk: &Disk,
        slot: Slot,
        expires_at: u64,
        now: u64,
    ) -> Option<Result<bool, SingleUseError>> {
        let (namespace, key) = slot;
        let held = disk.held.read().await;
        let journal = match held
            .as_ref()
            .ok_or(SingleUseError::Unavailable)
            .and_then(|journals| journals.get(namespace))
        {
            Ok(journal) => journal,
            Err(error) => return Some(Err(error)),
        };
        let mut journal = journal.lock().await;
        journal
            .compact_if_due(&self.memory, namespace, now)
            .await;
        match self.claim(slot, expires_at, now) {
            Claim::Taken => return Some(Ok(false)),
            Claim::Forgetting => return None,
            Claim::Claimed => {}
        }
        if let Err(error) = journal.write(&JournalLine::recorded(&key, expires_at)) {
            self.release_claim(&slot, expires_at);
            return Some(Err(error));
        }
        let file = Arc::clone(&journal.file);
        drop(journal);
        drop(held);
        Some(
            sync(file)
                .await
                .map(|()| true),
        )
    }

    /// Holds `slot` in memory until `expires_at` unless it is recorded and
    /// live. A forget that started before the claim was seen makes the claim
    /// step back; one that starts after it removes the claimed key, as a
    /// forget that follows the record would.
    fn claim(
        &self,
        slot: Slot,
        expires_at: u64,
        now: u64,
    ) -> Claim {
        match self.memory.entry(slot) {
            Entry::Occupied(recorded) if *recorded.get() > now => return Claim::Taken,
            Entry::Occupied(mut expired) => {
                expired.insert(expires_at);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(expires_at);
            }
        }
        if self
            .forgetting
            .contains_key(&slot)
        {
            self.release_claim(&slot, expires_at);
            return Claim::Forgetting;
        }
        Claim::Claimed
    }

    fn release_claim(
        &self,
        slot: &Slot,
        expires_at: u64,
    ) {
        self.memory
            .remove_if(slot, |_, recorded| *recorded == expires_at);
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
        match &self.backend {
            Backend::Disk(disk) => {
                let held = disk.held.read().await;
                if held.is_none() {
                    return Err(SingleUseError::Unavailable);
                }
                Ok(self.holds(namespace, key, now))
            }
            Backend::Dynamodb { client, table } => {
                if self.holds(namespace, key, now) {
                    return Ok(true);
                }
                if namespace.is_memory_only() {
                    return Ok(false);
                }
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
            #[cfg(test)]
            Backend::Memory { .. } => Ok(self.holds(namespace, key, now)),
        }
    }

    /// Whether this node holds `key` as recorded and unexpired, without asking
    /// the backend. With the disk backend this is the whole answer while the
    /// store holds the journals, and `false` while it does not. With DynamoDB
    /// it answers from this node's cache only, so a `false` is no proof of
    /// first use: [`SingleUseStore::record_unique`] is the authoritative check.
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
        self.forget_in_background_at(namespace, key, unix_now());
    }

    fn forget_in_background_at(
        self: &Arc<Self>,
        namespace: Namespace,
        key: &[u8; 32],
        now: u64,
    ) {
        let slot = (namespace, *key);
        if namespace.is_memory_only() {
            self.memory.remove(&slot);
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.memory.remove(&slot);
            tracing::warn!(
                namespace = namespace.name(),
                "A single-use record was forgotten outside a runtime; it stays recorded in the store"
            );
            return;
        };
        let pending = Arc::new(tokio::sync::Mutex::new(()));
        let held = Arc::clone(&pending)
            .try_lock_owned()
            .expect("a mutex no other task has seen is unlocked");
        self.forgetting
            .insert(slot, Arc::clone(&pending));
        self.memory.remove(&slot);
        let store = Arc::clone(self);
        runtime.spawn(async move {
            if let Err(error) = store
                .forget_in_backend(namespace, &slot.1, now)
                .await
            {
                tracing::error!(namespace = namespace.name(), %error, "Failed to forget a single-use record");
            }
            store
                .forgetting
                .remove_if(&slot, |_, waiting| Arc::ptr_eq(waiting, &pending));
            drop(store);
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
        now: u64,
    ) -> Result<(), SingleUseError> {
        match &self.backend {
            Backend::Disk(disk) => {
                let held = disk.held.read().await;
                let mut journal = held
                    .as_ref()
                    .ok_or(SingleUseError::Unavailable)?
                    .get(namespace)?
                    .lock()
                    .await;
                journal
                    .compact_if_due(&self.memory, namespace, now)
                    .await;
                journal.write(&JournalLine::forgotten(key))?;
                let file = Arc::clone(&journal.file);
                drop(journal);
                drop(held);
                sync(file).await
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
}

/// Takes the exclusive lock on the journals in `dir`, held until the returned
/// file is closed. `None` while another process holds it.
fn lock_journals(dir: &Path) -> Result<Option<std::fs::File>, SingleUseError> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(crate::audit::journal::OWNER_ONLY_FILE)
        .open(dir.join(LOCK_FILE))
        .map_err(storage_error)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(storage_error(error)),
    }
}

async fn sync(file: Arc<std::fs::File>) -> Result<(), SingleUseError> {
    tokio::task::spawn_blocking(move || file.sync_data())
        .await
        .map_err(storage_error)?
        .map_err(storage_error)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
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

    /// Rewrites the journal with only the keys of `namespace` that `memory`
    /// holds unexpired at `now`, once it has outgrown them. A failed rewrite
    /// leaves the journal as it was.
    async fn compact_if_due(
        &mut self,
        memory: &DashMap<Slot, u64>,
        namespace: Namespace,
        now: u64,
    ) {
        if self.lines < self.compact_at {
            return;
        }
        let live: Vec<([u8; 32], u64)> = memory
            .iter()
            .filter(|entry| entry.key().0 == namespace && *entry.value() > now)
            .map(|entry| (entry.key().1, *entry.value()))
            .collect();
        match Self::rewrite(self.path.clone(), &live).await {
            Ok(rewritten) => *self = rewritten,
            Err(error) => tracing::warn!(
                namespace = namespace.name(),
                %error,
                "Failed to compact a single-use journal"
            ),
        }
    }

    /// Appends `line` without syncing it.
    fn write(
        &mut self,
        line: &JournalLine,
    ) -> Result<(), SingleUseError> {
        let mut encoded = serde_json::to_vec(line).map_err(storage_error)?;
        encoded.push(b'\n');
        (&*self.file)
            .write_all(&encoded)
            .map_err(storage_error)?;
        self.lines += 1;
        Ok(())
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
    dynamodb_record_unique(client, table, namespace.record_type(), key, expires_at, now).await
}

/// Records `key` under `record_type` in `table` until `expires_at` with one
/// conditional put: `true` when no unexpired record of it exists, `false` when
/// one does.
pub(crate) async fn dynamodb_record_unique(
    client: &aws_sdk_dynamodb::Client,
    table: &str,
    record_type: &str,
    key: &[u8; 32],
    expires_at: u64,
    now: u64,
) -> Result<bool, SingleUseError> {
    use crate::storage::dynamodb_generic_repository::{PK, SK, object_key};
    use aws_sdk_dynamodb::types::AttributeValue;

    let (partition, sort) = object_key(record_type, &hex::encode(key));
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

/// Makes `store` the process's single-use store. It can be set once. A disk
/// store then follows the node's mode (see the module documentation).
#[cfg(not(test))]
pub fn install(store: SingleUseStore) -> Result<(), SingleUseError> {
    let store = Arc::new(store);
    STORE
        .set(Arc::clone(&store))
        .map_err(|_| SingleUseError::Config("the single-use store is already open".into()))?;
    if matches!(store.backend, Backend::Disk(_)) {
        tokio::spawn(follow_server_mode(store));
    }
    Ok(())
}

/// Holds the disk journals while the node is Active and gives them up while
/// it is Standby, so the instances sharing a volume take turns.
#[cfg(not(test))]
async fn follow_server_mode(store: Arc<SingleUseStore>) {
    use crate::server::mode::ServerMode;
    use tokio::sync::broadcast::error::RecvError;

    let mut changes = crate::server::mode::subscribe_mode_changes();
    let mut mode = crate::server::mode::current_mode();
    let mut retrying = false;
    loop {
        match mode {
            ServerMode::Standby => {
                retrying = false;
                store.step_down().await;
            }
            ServerMode::Active => match store
                .take_over(unix_now())
                .await
            {
                Ok(true) if retrying => {
                    retrying = false;
                    tracing::info!("Took the single-use journals over");
                }
                Ok(true) => {}
                Ok(false) => {
                    if !retrying {
                        tracing::warn!(
                            "Another instance still holds the single-use journals; single-use checks fail until this node takes them over"
                        );
                    }
                    retrying = true;
                }
                Err(error) => {
                    retrying = true;
                    tracing::error!(%error, "Failed to take the single-use journals over; trying again");
                }
            },
        }
        let waiting = mode == ServerMode::Active && !store.holds_journals().await;
        let change = if waiting {
            match tokio::time::timeout(TAKE_OVER_RETRY, changes.recv()).await {
                Ok(change) => change,
                Err(_) => continue,
            }
        } else {
            changes.recv().await
        };
        mode = match change {
            Ok(change) => change.mode,
            Err(RecvError::Lagged(_)) => crate::server::mode::current_mode(),
            Err(RecvError::Closed) => return,
        };
    }
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
thread_local! {
    static THREAD_STORE: std::cell::RefCell<Option<Option<Arc<SingleUseStore>>>> =
        const { std::cell::RefCell::new(None) };
}

/// The thread's store set by [`use_on_this_thread`], or else the in-memory
/// store every test shares.
#[cfg(test)]
pub fn global() -> Result<Arc<SingleUseStore>, SingleUseError> {
    if let Some(store) = THREAD_STORE.with(|store| store.borrow().clone()) {
        return store.ok_or(SingleUseError::Unavailable);
    }
    Ok(Arc::clone(STORE.get_or_init(|| Arc::new(SingleUseStore::in_memory()))))
}

/// Makes [`global`] answer with `store` on this thread, or fail as a store
/// that is not open when `store` is `None`, until the guard drops. A
/// current-thread runtime, the `#[tokio::test]` default, runs its spawned
/// tasks on the same thread, so they see it too.
#[cfg(test)]
pub fn use_on_this_thread(store: Option<SingleUseStore>) -> ThreadStoreGuard {
    let previous = THREAD_STORE.with(|current| current.replace(Some(store.map(Arc::new))));
    ThreadStoreGuard { previous }
}

#[cfg(test)]
pub struct ThreadStoreGuard {
    previous: Option<Option<Arc<SingleUseStore>>>,
}

#[cfg(test)]
impl Drop for ThreadStoreGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        THREAD_STORE.with(|current| current.replace(previous));
    }
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

    #[tokio::test]
    async fn a_second_store_on_the_same_journals_waits_for_the_first_to_step_down() {
        let dir = tempfile::tempdir().unwrap();
        let active = open(dir.path()).await;
        assert!(active.holds_journals().await);
        assert!(
            active
                .record_unique(Namespace::IdJag, &key(6), NOW + 60, NOW)
                .await
                .unwrap()
        );

        let standby = open(dir.path()).await;
        assert!(!standby.holds_journals().await);
        assert!(
            !standby
                .take_over(NOW)
                .await
                .unwrap(),
            "the lock is still held"
        );
        assert!(matches!(
            standby
                .record_unique(Namespace::IdJag, &key(7), NOW + 60, NOW)
                .await,
            Err(SingleUseError::Unavailable)
        ));
        assert!(matches!(
            standby
                .is_recorded(Namespace::IdJag, &key(6), NOW)
                .await,
            Err(SingleUseError::Unavailable)
        ));
        assert!(
            active
                .record_unique(Namespace::IdJag, &key(8), NOW + 60, NOW)
                .await
                .unwrap(),
            "the holder's journal was not replaced under it"
        );

        active.step_down().await;
        assert!(!active.holds_journals().await);
        assert!(matches!(
            active
                .record_unique(Namespace::IdJag, &key(9), NOW + 60, NOW)
                .await,
            Err(SingleUseError::Unavailable)
        ));
        assert!(
            standby
                .take_over(NOW)
                .await
                .unwrap()
        );
        for byte in [6, 8] {
            assert!(
                standby
                    .is_recorded(Namespace::IdJag, &key(byte), NOW)
                    .await
                    .unwrap(),
                "key {byte} recorded by the previous holder"
            );
        }
        assert!(
            !standby
                .is_recorded(Namespace::IdJag, &key(7), NOW)
                .await
                .unwrap()
        );
        assert!(
            !standby
                .record_unique(Namespace::IdJag, &key(8), NOW + 60, NOW)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_line_that_cannot_be_written_records_nothing_even_across_a_compaction() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(dir.path()).await;
        let Backend::Disk(disk) = &store.backend else { unreachable!() };
        let path = dir
            .path()
            .join("id-jag.jsonl");
        {
            let held = disk.held.read().await;
            let mut journal = held
                .as_ref()
                .unwrap()
                .get(Namespace::IdJag)
                .unwrap()
                .lock()
                .await;
            journal.file = Arc::new(std::fs::File::open(&path).unwrap());
        }
        assert!(
            store
                .record_unique(Namespace::IdJag, &key(10), NOW + 60, NOW)
                .await
                .is_err()
        );
        assert!(!store.holds(Namespace::IdJag, &key(10), NOW));

        {
            let held = disk.held.read().await;
            held.as_ref()
                .unwrap()
                .get(Namespace::IdJag)
                .unwrap()
                .lock()
                .await
                .compact_at = 0;
        }
        assert!(
            store
                .record_unique(Namespace::IdJag, &key(11), NOW + 60, NOW)
                .await
                .unwrap(),
            "the compaction reopened a writable journal"
        );
        drop(store);

        let reopened = open(dir.path()).await;
        assert!(!reopened.holds(Namespace::IdJag, &key(10), NOW));
        assert!(reopened.holds(Namespace::IdJag, &key(11), NOW));
    }

    #[tokio::test]
    async fn a_compaction_a_forget_starts_drops_keys_expired_by_then() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(open(dir.path()).await);
        for (byte, expires_at) in [(12, NOW + 10), (13, NOW + 1000), (14, NOW + 1000)] {
            assert!(
                store
                    .record_unique(Namespace::VoidedEvidence, &key(byte), expires_at, NOW)
                    .await
                    .unwrap()
            );
        }
        {
            let Backend::Disk(disk) = &store.backend else { unreachable!() };
            let held = disk.held.read().await;
            held.as_ref()
                .unwrap()
                .get(Namespace::VoidedEvidence)
                .unwrap()
                .lock()
                .await
                .compact_at = 0;
        }
        store.forget_in_background_at(Namespace::VoidedEvidence, &key(14), NOW + 100);
        assert!(
            !store
                .is_recorded(Namespace::VoidedEvidence, &key(14), NOW + 100)
                .await
                .unwrap()
        );
        let journal = std::fs::read_to_string(
            dir.path()
                .join("voided-evidence.jsonl"),
        )
        .unwrap();
        assert_eq!(journal.lines().count(), 2, "{journal}");
        assert!(journal.contains(&hex::encode(key(13))));
        assert!(!journal.contains(&hex::encode(key(12))), "expired by the forget's time");
    }

    #[tokio::test]
    async fn the_thread_store_replaces_the_shared_one_until_dropped() {
        {
            let _unavailable = use_on_this_thread(None);
            assert!(matches!(global(), Err(SingleUseError::Unavailable)));
            {
                let _failing = use_on_this_thread(Some(SingleUseStore::failing()));
                let store = global().unwrap();
                assert!(
                    store
                        .record_unique(Namespace::IdJag, &key(15), NOW + 60, NOW)
                        .await
                        .is_err()
                );
                let spawned = tokio::spawn(async { global().map(|store| format!("{store:?}")) })
                    .await
                    .unwrap();
                assert_eq!(spawned.unwrap(), "SingleUseStore::Memory");
            }
            assert!(matches!(global(), Err(SingleUseError::Unavailable)), "the outer guard is restored");
        }
        assert!(
            global()
                .unwrap()
                .record_unique(Namespace::IdJag, &unique_key(), NOW + 60, NOW)
                .await
                .unwrap()
        );
    }

    fn unique_key() -> [u8; 32] {
        use sha2::Digest;

        sha2::Sha256::digest(uuid::Uuid::new_v4().as_bytes()).into()
    }

    #[test]
    fn the_journal_directory_is_in_the_storage_root() {
        let paths = |agent_surfaces: &str| crate::config::types::StoragePaths {
            agent_surfaces: agent_surfaces.into(),
            ..Default::default()
        };
        assert_eq!(journal_dir(&paths("_storage/agent_surfaces")), Path::new("_storage/single_use"));
        assert_eq!(journal_dir(&paths("/data/_storage/config/agent_surfaces")), Path::new("/data/_storage/single_use"));
        assert_eq!(journal_dir(&paths("/srv/surfaces")), Path::new("/srv/single_use"));
    }
}
