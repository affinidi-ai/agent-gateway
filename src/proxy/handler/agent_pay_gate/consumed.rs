//! The idempotency keys of payments this process has claimed a request for. A
//! payment buys one forwarded request: agent-pay may answer the same credential
//! and request as paid again within its replay window, and this store is what
//! stops that answer from being forwarded a second time.
//!
//! A claim is held by a [`Claim`] guard. It is released when the guard drops
//! before the request was dispatched, so a request that failed or was
//! cancelled on this side can be retried with the same credential, and kept
//! once [`Claim::commit`] marks the request as dispatched.
//!
//! The set is per node. With a [`ClaimJournal`] opened, a dispatched key is
//! also written to it and read back at startup, so a restart does not forward
//! a request twice within the key's lifetime; another node has no memory of
//! the key, so "exactly one forward" holds per node and per agent-pay replay
//! window.

use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CAPACITY: usize = 100_000;
const LIFETIME: Duration = Duration::from_secs(10 * 60);

/// Why a key cannot be claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Unclaimable {
    /// Another request holds the key and has not dispatched yet.
    InFlight,
    /// A request was already dispatched for the key.
    Forwarded,
}

struct Entry {
    id: u64,
    forwarded: bool,
}

/// A bounded set of keys, each remembered for a fixed lifetime. A full set
/// forgets its oldest key first.
struct ConsumedKeys {
    capacity: usize,
    lifetime: Duration,
    keys: HashMap<Arc<str>, Entry>,
    order: VecDeque<(Instant, Arc<str>)>,
    next_id: u64,
}

impl ConsumedKeys {
    fn new(
        capacity: usize,
        lifetime: Duration,
    ) -> Self {
        Self {
            capacity: capacity.max(1),
            lifetime,
            keys: HashMap::new(),
            order: VecDeque::new(),
            next_id: 0,
        }
    }

    /// Claims `key`: the id of the claim, or why it is taken.
    fn claim(
        &mut self,
        key: &str,
        now: Instant,
    ) -> Result<u64, Unclaimable> {
        while self
            .order
            .front()
            .is_some_and(|(claimed_at, _)| now.saturating_duration_since(*claimed_at) >= self.lifetime)
        {
            self.forget_oldest();
        }
        if let Some(entry) = self.keys.get(key) {
            return Err(if entry.forwarded {
                Unclaimable::Forwarded
            } else {
                Unclaimable::InFlight
            });
        }
        if self.order.len() >= self.capacity {
            self.forget_oldest();
        }
        let key: Arc<str> = Arc::from(key);
        self.next_id += 1;
        let id = self.next_id;
        self.keys
            .insert(key.clone(), Entry { id, forwarded: false });
        self.order
            .push_back((now, key));
        Ok(id)
    }

    /// Marks the claim `id` of `key` as dispatched, so it stays consumed.
    fn commit(
        &mut self,
        key: &str,
        id: u64,
    ) {
        if let Some(entry) = self
            .keys
            .get_mut(key)
            .filter(|entry| entry.id == id)
        {
            entry.forwarded = true;
        }
    }

    /// Gives the claim `id` of `key` up, unless it was dispatched or the key
    /// was forgotten and claimed again since.
    fn release(
        &mut self,
        key: &str,
        id: u64,
    ) {
        if self
            .keys
            .get(key)
            .is_none_or(|entry| entry.id != id || entry.forwarded)
        {
            return;
        }
        self.keys.remove(key);
        if let Some(position) = self
            .order
            .iter()
            .rposition(|(_, held)| **held == *key)
        {
            self.order.remove(position);
        }
    }

    /// Gives the claim `id` of `key` back even when it was committed, for a
    /// request that never reached its Target.
    fn revoke(
        &mut self,
        key: &str,
        id: u64,
    ) {
        if let Some(entry) = self
            .keys
            .get_mut(key)
            .filter(|entry| entry.id == id)
        {
            entry.forwarded = false;
        }
        self.release(key, id);
    }

    /// Remembers `key` as dispatched at `claimed_at`, for a key read back from
    /// the journal. Keys must be restored oldest first.
    fn restore(
        &mut self,
        key: &str,
        claimed_at: Instant,
    ) {
        if self.keys.contains_key(key) {
            return;
        }
        if self.order.len() >= self.capacity {
            self.forget_oldest();
        }
        let key: Arc<str> = Arc::from(key);
        self.next_id += 1;
        self.keys.insert(
            key.clone(),
            Entry {
                id: self.next_id,
                forwarded: true,
            },
        );
        self.order
            .push_back((claimed_at, key));
    }

    fn forget_oldest(&mut self) {
        if let Some((_, key)) = self.order.pop_front() {
            self.keys.remove(&key);
        }
    }
}

static CONSUMED: LazyLock<Mutex<ConsumedKeys>> = LazyLock::new(|| Mutex::new(ConsumedKeys::new(CAPACITY, LIFETIME)));

fn consumed() -> std::sync::MutexGuard<'static, ConsumedKeys> {
    CONSUMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where dispatched keys are kept across restarts.
pub(crate) trait ClaimJournal: Send + Sync {
    fn forwarded(
        &self,
        key: &str,
        at_ms: u64,
    );

    fn revoked(
        &self,
        key: &str,
    );
}

static JOURNAL: OnceLock<Box<dyn ClaimJournal>> = OnceLock::new();

fn journal() -> Option<&'static dyn ClaimJournal> {
    JOURNAL.get().map(Box::as_ref)
}

fn epoch_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct JournalLine {
    key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    at: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    revoked: bool,
}

struct JournalState {
    file: Arc<std::fs::File>,
    lines: usize,
    live: HashMap<String, u64>,
}

/// An append-only file of dispatched and revoked keys, rewritten with only the
/// live keys when it holds twice as many lines as they need. A dispatch line is
/// written and synced to the disk before the request is dispatched, so it
/// survives a power loss; the sync runs outside the journal's lock, so
/// concurrent dispatches share the disk's flushes. A revocation is not synced:
/// losing one only refuses a retry of a request that was never delivered.
pub(crate) struct FileJournal {
    path: PathBuf,
    lifetime: Duration,
    state: Mutex<JournalState>,
    syncs: std::sync::atomic::AtomicU64,
}

impl FileJournal {
    const FILE_NAME: &'static str = "dispatched.jsonl";
    const COMPACT_SLACK: usize = 1024;

    /// Opens the journal in `dir` and returns it with the live keys it holds,
    /// oldest first, as `(key, epoch milliseconds)`.
    fn open(
        dir: &Path,
        lifetime: Duration,
        now: SystemTime,
    ) -> std::io::Result<(Self, Vec<(String, u64)>)> {
        crate::audit::journal::create_owner_only_dir(dir)?;
        let path = dir.join(Self::FILE_NAME);
        let mut live: HashMap<String, u64> = HashMap::new();
        if let Ok(file) = std::fs::File::open(&path) {
            for line in std::io::BufReader::new(file)
                .lines()
                .map_while(Result::ok)
            {
                let Ok(line) = serde_json::from_str::<JournalLine>(&line) else {
                    continue;
                };
                match (line.revoked, line.at) {
                    (true, _) => {
                        live.remove(&line.key);
                    }
                    (false, Some(at)) => {
                        live.insert(line.key, at);
                    }
                    (false, None) => {}
                }
            }
        }
        let cutoff = epoch_ms(now).saturating_sub(lifetime.as_millis() as u64);
        live.retain(|_, at| *at > cutoff);
        let file = Self::rewrite(&path, &live)?;
        let mut keys: Vec<(String, u64)> = live
            .iter()
            .map(|(key, at)| (key.clone(), *at))
            .collect();
        keys.sort_by_key(|(_, at)| *at);
        Ok((
            Self {
                path,
                lifetime,
                state: Mutex::new(JournalState {
                    file: Arc::new(file),
                    lines: live.len(),
                    live,
                }),
                syncs: std::sync::atomic::AtomicU64::new(0),
            },
            keys,
        ))
    }

    fn rewrite(
        path: &Path,
        live: &HashMap<String, u64>,
    ) -> std::io::Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;

        let temporary = path.with_extension("jsonl.tmp");
        let mut buffer = Vec::new();
        for (key, at) in live {
            serde_json::to_writer(
                &mut buffer,
                &JournalLine {
                    key: key.clone(),
                    at: Some(*at),
                    revoked: false,
                },
            )?;
            buffer.push(b'\n');
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(crate::audit::journal::OWNER_ONLY_FILE)
            .open(&temporary)?;
        file.write_all(&buffer)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::OpenOptions::new()
            .append(true)
            .open(path)
    }

    fn append(
        &self,
        line: &JournalLine,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match (line.revoked, line.at) {
            (true, _) => {
                state.live.remove(&line.key);
            }
            (false, Some(at)) => {
                state
                    .live
                    .insert(line.key.clone(), at);
            }
            (false, None) => {}
        }
        if state.lines > state.live.len() * 2 + Self::COMPACT_SLACK {
            let cutoff = epoch_ms(SystemTime::now()).saturating_sub(self.lifetime.as_millis() as u64);
            state
                .live
                .retain(|_, at| *at > cutoff);
            match Self::rewrite(&self.path, &state.live) {
                Ok(file) => {
                    state.lines = state.live.len();
                    state.file = Arc::new(file);
                    return;
                }
                Err(e) => tracing::warn!(error = %e, "Failed to compact the payment claim journal"),
            }
        }
        let mut encoded = serde_json::to_vec(line).unwrap_or_default();
        encoded.push(b'\n');
        let file = Arc::clone(&state.file);
        match (&*file).write_all(&encoded) {
            Ok(()) => state.lines += 1,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to write the payment claim journal; a restart may forward this payment's request again"
                );
                return;
            }
        }
        drop(state);
        if line.revoked {
            return;
        }
        match file.sync_data() {
            Ok(()) => {
                self.syncs
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => tracing::warn!(
                error = %e,
                "Failed to sync the payment claim journal; a power loss may forward this payment's request again"
            ),
        }
    }
}

impl ClaimJournal for FileJournal {
    fn forwarded(
        &self,
        key: &str,
        at_ms: u64,
    ) {
        self.append(&JournalLine {
            key: key.to_string(),
            at: Some(at_ms),
            revoked: false,
        });
    }

    fn revoked(
        &self,
        key: &str,
    ) {
        self.append(&JournalLine {
            key: key.to_string(),
            at: None,
            revoked: true,
        });
    }
}

/// Opens the journal in `dir`, restores the keys dispatched within their
/// lifetime and writes every later dispatch to it.
pub(crate) fn open_journal(dir: &Path) -> std::io::Result<usize> {
    let now = SystemTime::now();
    let (journal, keys) = FileJournal::open(dir, LIFETIME, now)?;
    let restored = keys.len();
    {
        let instant_now = Instant::now();
        let now_ms = epoch_ms(now);
        let mut consumed = consumed();
        for (key, at) in keys {
            let age = Duration::from_millis(now_ms.saturating_sub(at));
            consumed.restore(
                &key,
                instant_now
                    .checked_sub(age)
                    .unwrap_or(instant_now),
            );
        }
    }
    if JOURNAL
        .set(Box::new(journal))
        .is_err()
    {
        tracing::warn!("The payment claim journal was already open");
    }
    Ok(restored)
}

/// A claim on the idempotency key of a payment, released when dropped unless
/// the request it paid for was dispatched.
#[derive(Debug)]
pub(super) struct Claim {
    key: Arc<str>,
    id: u64,
    dispatched: AtomicBool,
}

impl Claim {
    /// Records that the request was dispatched: the claim is kept for good.
    pub(super) fn commit(&self) {
        if !self
            .dispatched
            .swap(true, Ordering::SeqCst)
        {
            consumed().commit(&self.key, self.id);
            if let Some(journal) = journal() {
                journal.forwarded(&self.key, epoch_ms(SystemTime::now()));
            }
        }
    }

    /// Takes the dispatch back: the request failed before it reached its
    /// Target, so the credential can pay for a retry.
    pub(super) fn revoke(&self) {
        self.dispatched
            .store(false, Ordering::SeqCst);
        consumed().revoke(&self.key, self.id);
        if let Some(journal) = journal() {
            journal.revoked(&self.key);
        }
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if !self
            .dispatched
            .load(Ordering::SeqCst)
        {
            consumed().release(&self.key, self.id);
        }
    }
}

/// Claims `key` for the request about to be dispatched, or says why it cannot:
/// a request that was already dispatched for it must not be dispatched again,
/// and one that holds it now may still fail and give it up.
pub(super) fn claim(key: &str) -> Result<Claim, Unclaimable> {
    let id = consumed().claim(key, Instant::now())?;
    Ok(Claim {
        key: Arc::from(key),
        id,
        dispatched: AtomicBool::new(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_claimed_once() {
        let mut keys = ConsumedKeys::new(10, Duration::from_secs(60));
        let now = Instant::now();
        assert!(keys.claim("a", now).is_ok());
        assert_eq!(keys.claim("a", now), Err(Unclaimable::InFlight));
        assert!(keys.claim("b", now).is_ok(), "another key is independent");
        assert_eq!(
            keys.claim("a", now + Duration::from_secs(59)),
            Err(Unclaimable::InFlight),
            "still held inside its lifetime"
        );
    }

    #[test]
    fn a_dispatched_key_stays_consumed_and_a_held_one_is_in_flight() {
        let mut keys = ConsumedKeys::new(10, Duration::from_secs(60));
        let now = Instant::now();
        let id = keys.claim("a", now).unwrap();
        assert_eq!(keys.claim("a", now), Err(Unclaimable::InFlight));
        keys.commit("a", id);
        assert_eq!(keys.claim("a", now), Err(Unclaimable::Forwarded));
        keys.release("a", id);
        assert_eq!(keys.claim("a", now), Err(Unclaimable::Forwarded), "a dispatched claim cannot be released");
    }

    #[test]
    fn a_revoked_dispatch_gives_the_key_back_but_only_to_its_own_claim() {
        let mut keys = ConsumedKeys::new(10, Duration::from_secs(60));
        let now = Instant::now();
        let id = keys.claim("a", now).unwrap();
        keys.commit("a", id);
        assert_eq!(keys.claim("a", now), Err(Unclaimable::Forwarded));
        keys.revoke("a", id);
        assert_eq!((keys.keys.len(), keys.order.len()), (0, 0));
        let again = keys.claim("a", now).unwrap();
        keys.commit("a", again);
        keys.revoke("a", id);
        assert_eq!(keys.claim("a", now), Err(Unclaimable::Forwarded), "an old claim cannot revoke a newer one");
    }

    #[test]
    fn a_released_key_can_be_claimed_again_and_leaves_no_trace() {
        let mut keys = ConsumedKeys::new(10, Duration::from_secs(60));
        let now = Instant::now();
        let id = keys.claim("a", now).unwrap();
        keys.release("a", id);
        assert_eq!((keys.keys.len(), keys.order.len()), (0, 0));
        let again = keys.claim("a", now).unwrap();
        assert_ne!(again, id);
        keys.release("a", id);
        assert_eq!(keys.claim("a", now), Err(Unclaimable::InFlight), "an old claim cannot release a newer one");
        keys.commit("a", id);
        keys.commit("a", again);
        assert_eq!(keys.claim("a", now), Err(Unclaimable::Forwarded));
    }

    #[test]
    fn a_key_can_be_claimed_again_after_its_lifetime() {
        let mut keys = ConsumedKeys::new(10, Duration::from_secs(60));
        let now = Instant::now();
        assert!(keys.claim("a", now).is_ok());
        assert!(
            keys.claim("b", now + Duration::from_secs(30))
                .is_ok()
        );
        let later = now + Duration::from_secs(60);
        assert!(keys.claim("a", later).is_ok(), "the first key has expired");
        assert!(
            keys.claim("b", later)
                .is_err(),
            "the second key has not"
        );
        assert_eq!(keys.keys.len(), keys.order.len());
    }

    #[test]
    fn a_full_set_forgets_its_oldest_key_first() {
        let mut keys = ConsumedKeys::new(3, Duration::from_secs(60));
        let now = Instant::now();
        for key in ["a", "b", "c"] {
            assert!(keys.claim(key, now).is_ok());
        }
        assert!(keys.claim("d", now).is_ok(), "a new key is accepted at capacity");
        assert_eq!(keys.keys.len(), 3, "the set stays bounded");
        assert!(keys.claim("c", now).is_err());
        assert!(keys.claim("d", now).is_err());
        assert!(keys.claim("a", now).is_ok(), "the oldest key was forgotten");
        assert_eq!(keys.keys.len(), 3);
        assert_eq!(keys.order.len(), 3);
    }

    #[test]
    fn concurrent_claims_of_one_key_succeed_exactly_once() {
        let key = format!("concurrent-{}", uuid::Uuid::new_v4());
        let claims: Vec<Result<Claim, Unclaimable>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| claim(&key)))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        assert_eq!(
            claims
                .iter()
                .filter(|claim| claim.is_ok())
                .count(),
            1
        );
        assert!(
            claims
                .iter()
                .filter_map(|claim| claim.as_ref().err())
                .all(|error| *error == Unclaimable::InFlight)
        );
        drop(claims);
        assert!(claim(&key).is_ok(), "dropping the only claim before a dispatch gives the key up");
    }

    #[test]
    fn a_claim_dropped_before_dispatch_is_released_and_a_committed_one_is_kept() {
        let released = format!("released-{}", uuid::Uuid::new_v4());
        drop(claim(&released).unwrap());
        let again = claim(&released).expect("released on drop");
        again.commit();
        again.commit();
        drop(again);
        assert_eq!(claim(&released).err(), Some(Unclaimable::Forwarded));
    }

    #[test]
    fn a_restored_key_is_forwarded_and_ages_out_with_its_lifetime() {
        let mut keys = ConsumedKeys::new(10, Duration::from_secs(60));
        let now = Instant::now();
        keys.restore("a", now);
        assert_eq!(keys.claim("a", now), Err(Unclaimable::Forwarded));
        assert!(
            keys.claim("a", now + Duration::from_secs(60))
                .is_ok(),
            "it ages out like any other"
        );
    }

    #[test]
    fn the_journal_reads_back_live_dispatches_and_drops_revoked_and_expired_ones() {
        let dir = tempfile::tempdir().unwrap();
        let lifetime = Duration::from_secs(600);
        let now = SystemTime::now();
        let now_ms = epoch_ms(now);
        {
            let (journal, keys) = FileJournal::open(dir.path(), lifetime, now).unwrap();
            assert!(keys.is_empty());
            journal.forwarded("old", now_ms - 700_000);
            journal.forwarded("kept", now_ms - 1_000);
            journal.forwarded("revoked", now_ms - 500);
            journal.revoked("revoked");
            journal.forwarded("newest", now_ms);
        }
        let (_, keys) = FileJournal::open(dir.path(), lifetime, now).unwrap();
        assert_eq!(keys, vec![("kept".to_string(), now_ms - 1_000), ("newest".to_string(), now_ms)]);
        let written = std::fs::read_to_string(
            dir.path()
                .join(FileJournal::FILE_NAME),
        )
        .unwrap();
        assert_eq!(written.lines().count(), 2, "opening compacts the file to the live keys");
    }

    #[test]
    fn a_dispatch_line_is_synced_before_it_returns_and_a_revocation_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let (journal, _) = FileJournal::open(dir.path(), Duration::from_secs(600), now).unwrap();
        journal.forwarded("synced", epoch_ms(now));
        assert_eq!(
            journal
                .syncs
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        journal.revoked("synced");
        assert_eq!(
            journal
                .syncs
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        journal.forwarded("kept", epoch_ms(now));
        assert_eq!(
            journal
                .syncs
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
        let (_, keys) = FileJournal::open(dir.path(), Duration::from_secs(600), now).unwrap();
        assert_eq!(
            keys.into_iter()
                .map(|(key, _)| key)
                .collect::<Vec<_>>(),
            vec!["kept".to_string()]
        );
    }

    #[test]
    fn the_journal_compacts_itself_when_it_outgrows_its_live_keys() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let (journal, _) = FileJournal::open(dir.path(), Duration::from_secs(600), now).unwrap();
        for _ in 0..(FileJournal::COMPACT_SLACK + 10) {
            journal.forwarded("same", epoch_ms(now));
            journal.revoked("same");
        }
        let lines = std::fs::read_to_string(
            dir.path()
                .join(FileJournal::FILE_NAME),
        )
        .unwrap()
        .lines()
        .count();
        assert!(lines <= FileJournal::COMPACT_SLACK + 2, "{lines} lines");
    }

    #[test]
    fn a_committed_claim_revoked_for_an_undelivered_request_can_be_claimed_again() {
        let key = format!("revoked-{}", uuid::Uuid::new_v4());
        let first = claim(&key).unwrap();
        first.commit();
        assert_eq!(claim(&key).err(), Some(Unclaimable::Forwarded));
        first.revoke();
        drop(first);
        let retry = claim(&key).expect("the credential was given back");
        retry.commit();
        assert_eq!(claim(&key).err(), Some(Unclaimable::Forwarded));
    }
}
