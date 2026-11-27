//! The security record chain: every trust agent change, refused trust agent change and refused
//! signing change is appended here, hash-chained ([`crate::audit::hash_chain`]), before the
//! management request that caused it is answered, whichever audit sinks select its event.
//!
//! Records are kept one JSON line each in `records.jsonl` and the chain head in `head.json`,
//! both owner-only, in the directory [`init`] names, so a restart continues the chain. Each
//! record is synced before the head is replaced. A record that cannot be written is logged at
//! error level on the `security_audit` target and the request goes on: a refusal stays a
//! refusal, and a change that was already stored is not undone.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::hash_chain::{Chained, GENESIS_HASH, link_hash, verify_chain};
use crate::audit::journal::{OWNER_ONLY_FILE, create_owner_only_dir, write_owner_only_atomically};

/// The log target security records and their failures are written under.
pub const LOG_TARGET: &str = "security_audit";

const RECORDS_FILE: &str = "records.jsonl";
const HEAD_FILE: &str = "head.json";

/// A record's place in the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLink {
    pub seq: u64,
    pub prev_hash: String,
    pub record_hash: String,
}

/// One line of `records.jsonl`: the event's category and its details as the audit record
/// carries them, without the chain fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityRecord {
    #[serde(flatten)]
    pub link: ChainLink,
    pub category: String,
    pub record: Value,
}

impl Chained for SecurityRecord {
    fn seq(&self) -> u64 {
        self.link.seq
    }

    fn prev_hash(&self) -> &str {
        &self.link.prev_hash
    }

    fn record_hash(&self) -> &str {
        &self.link.record_hash
    }

    fn compute_hash(&self) -> String {
        record_hash(self.link.seq, &self.link.prev_hash, &self.category, &self.record)
    }
}

/// The hash of `record` of `category` at `seq` after `prev_hash`: over its RFC 8785 canonical
/// JSON, so a verifier can recompute it from the record as any sink delivered it.
pub fn record_hash(
    seq: u64,
    prev_hash: &str,
    category: &str,
    record: &Value,
) -> String {
    let canonical = serde_json_canonicalizer::to_string(record).unwrap_or_default();
    link_hash(seq, prev_hash, &[category, &canonical])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Head {
    seq: u64,
    record_hash: String,
}

impl Head {
    fn genesis() -> Self {
        Self {
            seq: 0,
            record_hash: GENESIS_HASH.to_string(),
        }
    }
}

/// An append-only chain, on disk under `dir` or, without one, in memory.
pub struct SecurityChain {
    dir: Option<PathBuf>,
    head: Mutex<Head>,
}

impl SecurityChain {
    pub fn open(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: Some(dir.into()),
            head: Mutex::new(Head::genesis()),
        }
    }

    pub fn in_memory() -> Self {
        Self {
            dir: None,
            head: Mutex::new(Head::genesis()),
        }
    }

    /// Appends `record` of `category` and returns its link. The head is read from disk on every
    /// append, so a gateway that restarted, or took over the storage of another, continues the
    /// chain; a head behind what this process already wrote is not trusted.
    pub fn append(
        &self,
        category: &str,
        record: &Value,
    ) -> io::Result<ChainLink> {
        let mut head = self
            .head
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(dir) = &self.dir
            && let Some(stored) = read_head(dir)?
            && stored.seq >= head.seq
        {
            *head = stored;
        }
        let seq = head.seq + 1;
        let link = ChainLink {
            seq,
            prev_hash: head.record_hash.clone(),
            record_hash: record_hash(seq, &head.record_hash, category, record),
        };
        if let Some(dir) = &self.dir {
            create_owner_only_dir(dir)?;
            append_line(
                &dir.join(RECORDS_FILE),
                &SecurityRecord {
                    link: link.clone(),
                    category: category.to_string(),
                    record: record.clone(),
                },
            )?;
        }
        *head = Head {
            seq,
            record_hash: link.record_hash.clone(),
        };
        if let Some(dir) = &self.dir
            && let Err(error) = serde_json::to_vec(&*head)
                .map_err(io::Error::other)
                .and_then(|bytes| write_owner_only_atomically(&dir.join(HEAD_FILE), &bytes))
        {
            tracing::error!(
                target: LOG_TARGET,
                seq,
                error = %error,
                "Failed to store the security record chain head; a restart before the next record forks the chain"
            );
        }
        Ok(link)
    }
}

fn read_head(dir: &Path) -> io::Result<Option<Head>> {
    match fs::read(dir.join(HEAD_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn append_line(
    path: &Path,
    record: &SecurityRecord,
) -> io::Result<()> {
    let mut line = serde_json::to_vec(record).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(OWNER_ONLY_FILE)
        .open(path)?;
    file.write_all(&line)?;
    file.sync_data()
}

/// The records under `dir`, in the order they were written.
pub fn read_records(dir: &Path) -> io::Result<Vec<SecurityRecord>> {
    let file = match fs::File::open(dir.join(RECORDS_FILE)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    BufReader::new(file)
        .lines()
        .filter(|line| {
            line.as_ref()
                .map_or(true, |line| !line.trim().is_empty())
        })
        .map(|line| serde_json::from_str(&line?).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)))
        .collect()
}

static CHAIN: OnceLock<SecurityChain> = OnceLock::new();

/// Keeps the chain under `dir` and verifies what it already holds. Called once at startup,
/// before any management request. A chain that does not verify is reported at error level
/// and appended to as it is: the break stays as evidence.
pub fn init(dir: PathBuf) {
    match check(&dir) {
        Ok(0) => {}
        Ok(records) => tracing::info!(target: LOG_TARGET, records, "The security record chain verifies"),
        Err(error) => tracing::error!(target: LOG_TARGET, error = %error, "The security record chain does not verify"),
    }
    if CHAIN
        .set(SecurityChain::open(dir))
        .is_err()
    {
        tracing::warn!(target: LOG_TARGET, "The security record chain was already set up");
    }
}

/// How many records the chain under `dir` holds, or why it does not verify.
pub fn check(dir: &Path) -> io::Result<usize> {
    let records = read_records(dir)?;
    verify_chain(&records).map_err(|index| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("record {} (seq {}) does not follow the record before it", index + 1, records[index].link.seq),
        )
    })?;
    Ok(records.len())
}

/// Appends `record` of `category` to the gateway's chain. A failure is logged at error level
/// and gives `None`: the record is still sent to the audit sinks, without a link.
pub fn append(
    category: &str,
    record: &Value,
) -> Option<ChainLink> {
    match CHAIN
        .get_or_init(SecurityChain::in_memory)
        .append(category, record)
    {
        Ok(link) => Some(link),
        Err(error) => {
            tracing::error!(
                target: LOG_TARGET,
                event = category,
                error = %error,
                "Failed to append a security record to its chain; the record is not tamper-evident"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    fn record(n: u64) -> Value {
        json!({ "actor": { "kind": "user", "id": "u-1" }, "connection_id": format!("c-{n}"), "status": 403 })
    }

    #[test]
    fn appended_records_are_linked_from_genesis_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let chain = SecurityChain::open(dir.path());
        let first = chain
            .append("trust_agent_change_refused", &record(1))
            .unwrap();
        let second = chain
            .append("trust_agent_connection_revoked", &record(2))
            .unwrap();
        assert_eq!(first.seq, 1);
        assert_eq!(first.prev_hash, GENESIS_HASH);
        assert_eq!(second.seq, 2);
        assert_eq!(second.prev_hash, first.record_hash);

        let records = read_records(dir.path()).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].category, "trust_agent_connection_revoked");
        assert_eq!(records[1].record, record(2));
        assert_eq!(verify_chain(&records), Ok(()));
    }

    #[test]
    fn a_chain_reopened_on_the_same_directory_continues_where_it_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let last = SecurityChain::open(dir.path())
            .append("trust_agent_connection_created", &record(1))
            .unwrap();
        let next = SecurityChain::open(dir.path())
            .append("trust_agent_connection_deleted", &record(2))
            .unwrap();
        assert_eq!(next.seq, 2);
        assert_eq!(next.prev_hash, last.record_hash);
        assert_eq!(verify_chain(&read_records(dir.path()).unwrap()), Ok(()));
    }

    #[test]
    fn a_head_rolled_back_on_disk_does_not_rewind_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let chain = SecurityChain::open(dir.path());
        chain
            .append("a", &record(1))
            .unwrap();
        let saved = fs::read(dir.path().join(HEAD_FILE)).unwrap();
        chain
            .append("b", &record(2))
            .unwrap();
        fs::write(dir.path().join(HEAD_FILE), saved).unwrap();
        assert_eq!(
            chain
                .append("c", &record(3))
                .unwrap()
                .seq,
            3
        );
        assert_eq!(verify_chain(&read_records(dir.path()).unwrap()), Ok(()));
    }

    #[test]
    fn an_edited_removed_or_reordered_record_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let chain = SecurityChain::open(dir.path());
        for n in 1..=4 {
            chain
                .append("trust_agent_change_refused", &record(n))
                .unwrap();
        }
        let records = read_records(dir.path()).unwrap();

        let mut edited = records.clone();
        edited[2].record["status"] = json!(200);
        assert_eq!(verify_chain(&edited), Err(2));

        let mut relabelled = records.clone();
        relabelled[1].category = "trust_agent_connection_created".to_string();
        assert_eq!(verify_chain(&relabelled), Err(1));

        let mut removed = records.clone();
        removed.remove(1);
        assert_eq!(verify_chain(&removed), Err(1));

        let mut reordered = records.clone();
        reordered.swap(2, 3);
        assert_eq!(verify_chain(&reordered), Err(2));

        assert_eq!(check(dir.path()).unwrap(), 4);
        let lines: Vec<String> = edited
            .iter()
            .map(|record| serde_json::to_string(record).unwrap())
            .collect();
        fs::write(dir.path().join(RECORDS_FILE), lines.join("\n")).unwrap();
        let error = check(dir.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("seq 3"),
            "{error}"
        );
    }

    #[test]
    fn the_hash_does_not_depend_on_key_order() {
        let ordered = json!({ "a": 1, "b": { "c": 2, "d": 3 } });
        let shuffled: Value = serde_json::from_str(r#"{ "b": { "d": 3, "c": 2 }, "a": 1 }"#).unwrap();
        assert_eq!(record_hash(1, GENESIS_HASH, "x", &ordered), record_hash(1, GENESIS_HASH, "x", &shuffled));
    }

    #[test]
    fn the_files_are_readable_by_the_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        SecurityChain::open(dir.path().join("security"))
            .append("a", &record(1))
            .unwrap();
        for file in [RECORDS_FILE, HEAD_FILE] {
            let mode = fs::metadata(
                dir.path()
                    .join("security")
                    .join(file),
            )
            .unwrap()
            .permissions()
            .mode();
            assert_eq!(mode & 0o777, 0o600, "{file}");
        }
    }

    #[test]
    fn a_chain_that_cannot_be_written_fails_without_advancing() {
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("not-a-dir");
        fs::write(&blocked, b"").unwrap();
        let chain = SecurityChain::open(&blocked);
        assert!(
            chain
                .append("a", &record(1))
                .is_err()
        );
        let memory = SecurityChain::in_memory();
        assert_eq!(
            memory
                .append("a", &record(1))
                .unwrap()
                .seq,
            1
        );
    }
}
