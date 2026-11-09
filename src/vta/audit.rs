//! Optional, **data-minimized**, **bounded**, **non-blocking** audit sink to the
//! VTA for high-value signing flows (VTA-08).
//!
//! The VTA is an authoritative provenance sink, but auditing must never weaken
//! the data plane. Three properties are load-bearing and tested:
//!
//! - **Data minimization** — a record carries only an event label, the signing
//!   key id, and SHA-256 **hashes** of the subject and the signed artifact.
//!   No claims, no token, no PII ever leave the gateway through this path.
//! - **Bounded** — records go through a fixed-capacity queue. When it is full,
//!   new records are **dropped** (and counted), so a slow or stuck sink cannot
//!   grow gateway memory without limit.
//! - **Non-blocking / fail-open** — [`VtaAuditSink::record`] never blocks, never
//!   errors, and never fails the request it describes. A dropped or failed audit
//!   is a lost log line, not a denied operation.
//! - **Tamper-evident** — each accepted record is **hash-chained** to its
//!   predecessor (VTA-17 / SEC0-6115 condition 5). Removing, reordering or
//!   editing a record breaks the chain, so an operator can tell a quiet log from
//!   a doctored one. The chain proves *integrity of the sequence*, not
//!   authorship; signing the head is a later step.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

/// Field separator for the chain pre-image. `0x1e` (record separator) cannot
/// occur in a hex hash, an event label or a key id, so the concatenation parses
/// unambiguously and two different records cannot collide by shifting a field
/// boundary.
const CHAIN_SEP: char = '\u{1e}';

/// `prev_hash` of the first record in a chain.
pub const GENESIS_HASH: &str = "genesis";

/// A single audit record. **Hashes and identifiers only** — see the module doc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// A short, non-sensitive event label (e.g. `"token_signed"`).
    pub event: &'static str,
    /// The VTA key record id that signed the artifact (already an opaque id,
    /// not a secret).
    pub key_id: String,
    /// SHA-256 hex of the token subject (`sub`), or `""` when absent.
    pub subject_hash: String,
    /// SHA-256 hex of the signed artifact (the compact JWS).
    pub artifact_hash: String,
    /// Which carrier the Trust Task travelled over (`https` | `didcomm`).
    /// Recorded because a slow or failing signing path is diagnosed very
    /// differently depending on whether a mediator was involved (VTA-27).
    pub carrier: &'static str,
    /// Position in the chain, from 1. Assigned by the sink.
    pub seq: u64,
    /// [`Self::record_hash`] of the previous record, or [`GENESIS_HASH`].
    /// Assigned by the sink.
    pub prev_hash: String,
    /// SHA-256 over this record's content **and** `prev_hash`. Assigned by the
    /// sink; recomputed by [`verify_chain`].
    pub record_hash: String,
}

impl AuditRecord {
    /// Build a record from the raw subject and artifact, hashing both so no raw
    /// value is ever retained. `subject` may be empty.
    ///
    /// The chain fields are left unset — [`VtaAuditSink::record`] assigns them,
    /// because only the sink knows the sequence.
    pub fn for_signed_token(
        event: &'static str,
        key_id: &str,
        subject: &str,
        artifact: &str,
    ) -> Self {
        Self {
            event,
            key_id: key_id.to_string(),
            subject_hash: hash_hex(subject),
            artifact_hash: hash_hex(artifact),
            carrier: "https",
            seq: 0,
            prev_hash: String::new(),
            record_hash: String::new(),
        }
    }

    /// Label the carrier the Trust Task travelled over.
    #[must_use]
    pub fn via(
        mut self,
        carrier: &'static str,
    ) -> Self {
        self.carrier = carrier;
        self
    }

    /// The chain hash this record *should* carry, given its content and
    /// `prev_hash`. Deterministic, so a verifier recomputes it independently.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        hash_hex(&format!(
            "{seq}{SEP}{prev}{SEP}{event}{SEP}{key}{SEP}{subject}{SEP}{artifact}{SEP}{carrier}",
            seq = self.seq,
            prev = self.prev_hash,
            event = self.event,
            key = self.key_id,
            subject = self.subject_hash,
            artifact = self.artifact_hash,
            // Part of the hash, not just a label: an attacker who could
            // rewrite the carrier could hide that signing moved to a path the
            // operator never approved.
            carrier = self.carrier,
            SEP = CHAIN_SEP,
        ))
    }
}

/// Verify a chain of records in order.
///
/// Returns `Err(index)` of the **first** record that does not follow its
/// predecessor — because it was edited (its `record_hash` no longer matches its
/// content), removed/reordered (its `prev_hash` or `seq` does not follow), or
/// never belonged.
///
/// Test-only for now: the chain is written by the running gateway and verified
/// by whoever reads the log. Exposing it as an operator-facing tool is a
/// follow-up.
#[cfg(test)]
pub fn verify_chain(records: &[AuditRecord]) -> Result<(), usize> {
    let mut expected_prev = GENESIS_HASH.to_string();
    for (index, record) in records.iter().enumerate() {
        // Sequence numbers start at 1, so the expected value is the 0-based
        // index plus one; deriving it here rather than carrying a counter keeps
        // "position in the slice" and "claimed position in the chain" the same
        // statement.
        let expected_seq = index as u64 + 1;
        if record.seq != expected_seq || record.prev_hash != expected_prev {
            return Err(index);
        }
        if record.record_hash != record.compute_hash() {
            return Err(index);
        }
        expected_prev = record.record_hash.clone();
    }
    Ok(())
}

/// SHA-256 hex of `input` (empty string hashes to `""`, so an absent field is
/// distinguishable from a present one).
#[must_use]
pub fn hash_hex(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Where accepted audit records are delivered. A port so the VTA transport (a
/// bounded best-effort Trust Task) can replace the default without touching the
/// queue. The emitter runs off the hot path, in the drain task.
#[async_trait]
pub trait AuditEmitter: Send + Sync {
    async fn emit(
        &self,
        record: &AuditRecord,
    );
}

/// Default emitter: a structured `tracing` line on the `vta_audit` target. It
/// writes only the already-minimized record fields.
pub struct LogAuditEmitter;

#[async_trait]
impl AuditEmitter for LogAuditEmitter {
    async fn emit(
        &self,
        record: &AuditRecord,
    ) {
        tracing::info!(
            target: "vta_audit",
            event = record.event,
            key_id = %record.key_id,
            subject_hash = %record.subject_hash,
            artifact_hash = %record.artifact_hash,
            seq = record.seq,
            prev_hash = %record.prev_hash,
            record_hash = %record.record_hash,
            "VTA audit record",
        );
    }
}

/// A bounded, non-blocking audit queue drained by a background task.
pub struct VtaAuditSink {
    tx: mpsc::Sender<AuditRecord>,
    dropped: Arc<AtomicU64>,
    /// Chain head: `(seq of the last accepted record, its record_hash)`.
    ///
    /// A `std::sync::Mutex` because [`VtaAuditSink::record`] is synchronous and
    /// the critical section is a counter bump plus one SHA-256 — it never
    /// awaits, so it cannot be held across a yield point.
    chain: Mutex<(u64, String)>,
}

impl VtaAuditSink {
    /// Spawn a sink with a fixed-capacity queue drained by `emitter`. The drain
    /// task lives as long as the sink (the channel) does.
    pub fn spawn(
        capacity: usize,
        emitter: Arc<dyn AuditEmitter>,
    ) -> Self {
        let capacity = capacity.max(1);
        let (tx, mut rx) = mpsc::channel::<AuditRecord>(capacity);
        tokio::spawn(async move {
            while let Some(record) = rx.recv().await {
                emitter.emit(&record).await;
            }
        });
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            chain: Mutex::new((0, GENESIS_HASH.to_string())),
        }
    }

    /// Enqueue a record. **Never blocks and never errors**: if the queue is full
    /// (a slow sink) the record is dropped and counted; if the drain task is
    /// gone it is silently discarded. The caller's request is never affected.
    ///
    /// The record is **chained before the capacity check**, so a drop still
    /// consumes a sequence number: a gap in `seq` is then visible evidence that
    /// records were lost, rather than the loss being silent.
    pub fn record(
        &self,
        mut record: AuditRecord,
    ) {
        match self.chain.lock() {
            Ok(mut head) => {
                let (ref mut last_seq, ref mut last_hash) = *head;
                *last_seq += 1;
                record.seq = *last_seq;
                record.prev_hash = last_hash.clone();
                record.record_hash = record.compute_hash();
                *last_hash = record.record_hash.clone();
            }
            // A poisoned chain lock must not fail the caller's request (audit is
            // fail-open by contract). Emit unchained and say so, so the gap is
            // not mistaken for a verified link.
            Err(_) => {
                tracing::error!(
                    target: "vta_audit",
                    "VTA audit chain state is poisoned — emitting an unchained record",
                );
            }
        }
        if let Err(e) = self.tx.try_send(record) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    let n = self
                        .dropped
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    tracing::warn!(
                        target: "vta_audit",
                        dropped_total = n,
                        "VTA audit queue full — dropping record (audit never blocks the request)",
                    );
                }
                mpsc::error::TrySendError::Closed(_) => {}
            }
        }
    }

    /// How many records have been dropped because the queue was full.
    #[cfg(test)]
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
            .load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Collect the records an emitter saw, so the chain can be verified.
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<AuditRecord>>>);

    #[async_trait]
    impl AuditEmitter for Capture {
        async fn emit(
            &self,
            record: &AuditRecord,
        ) {
            self.0
                .lock()
                .unwrap()
                .push(record.clone());
        }
    }

    async fn drain_chained(n: usize) -> Vec<AuditRecord> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = VtaAuditSink::spawn(64, Arc::new(Capture(Arc::clone(&seen))));
        for i in 0..n {
            sink.record(AuditRecord::for_signed_token("token_signed", "key-1", &format!("s{i}"), "jws"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        seen.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn accepted_records_form_a_verifiable_chain() {
        let records = drain_chained(5).await;
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].seq, 1);
        assert_eq!(records[0].prev_hash, GENESIS_HASH);
        for pair in records.windows(2) {
            assert_eq!(pair[1].prev_hash, pair[0].record_hash, "each record links to the previous");
            assert_eq!(pair[1].seq, pair[0].seq + 1, "sequence is contiguous");
        }
        verify_chain(&records).expect("an untouched chain verifies");
    }

    #[tokio::test]
    async fn editing_a_record_breaks_the_chain() {
        let mut records = drain_chained(4).await;
        // Tamper with the payload of record #2 without recomputing its hash —
        // exactly what an attacker editing a log in place would do.
        records[1].artifact_hash = hash_hex("a-different-token");
        let broken = verify_chain(&records).expect_err("tampering must be detected");
        assert_eq!(broken, 1, "the edited record is named");
    }

    #[tokio::test]
    async fn removing_a_record_breaks_the_chain() {
        let mut records = drain_chained(4).await;
        records.remove(1);
        let broken = verify_chain(&records).expect_err("a removal must be detected");
        assert_eq!(broken, 1, "detected at the record that no longer follows");
    }

    #[tokio::test]
    async fn reordering_records_breaks_the_chain() {
        let mut records = drain_chained(4).await;
        records.swap(1, 2);
        verify_chain(&records).expect_err("a reorder must be detected");
    }

    #[test]
    fn a_record_carries_only_hashes_not_raw_values() {
        let subject = "urn:agent:alice";
        let artifact = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.sig";
        let record = AuditRecord::for_signed_token("token_signed", "key-1", subject, artifact);

        // The raw subject/artifact never appear; only their SHA-256 hashes do.
        assert_ne!(record.subject_hash, subject);
        assert_ne!(record.artifact_hash, artifact);
        assert_eq!(record.subject_hash, hash_hex(subject));
        assert_eq!(record.artifact_hash, hash_hex(artifact));
        assert_eq!(record.subject_hash.len(), 64, "sha-256 hex");
        assert_eq!(record.key_id, "key-1");
    }

    #[test]
    fn an_absent_subject_hashes_to_empty() {
        let record = AuditRecord::for_signed_token("token_signed", "key-1", "", "jws");
        assert_eq!(record.subject_hash, "");
        assert!(
            !record
                .artifact_hash
                .is_empty()
        );
    }

    /// An emitter that blocks forever, so the queue fills and stays full.
    struct StalledEmitter;

    #[async_trait]
    impl AuditEmitter for StalledEmitter {
        async fn emit(
            &self,
            _record: &AuditRecord,
        ) {
            // Never returns while the test runs.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    #[tokio::test]
    async fn the_queue_is_bounded_and_record_never_blocks() {
        // Capacity 1 + a stalled drain: the first record is taken by the drain
        // task (and stalls there), the next fills the buffer, and everything
        // after is dropped — without `record` ever blocking.
        let sink = VtaAuditSink::spawn(1, Arc::new(StalledEmitter));

        for i in 0..1000 {
            // If `record` blocked, this loop would hang on the stalled emitter.
            sink.record(AuditRecord::for_signed_token("token_signed", "key-1", &format!("s{i}"), "jws"));
        }
        // Give the drain task a moment to pick up the first record.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(sink.dropped() > 0, "a full bounded queue drops records");
    }

    #[tokio::test]
    async fn records_reach_the_emitter_when_the_queue_has_room() {
        let seen = Arc::new(AtomicU64::new(0));

        struct CountingEmitter(Arc<AtomicU64>);
        #[async_trait]
        impl AuditEmitter for CountingEmitter {
            async fn emit(
                &self,
                _record: &AuditRecord,
            ) {
                self.0
                    .fetch_add(1, Ordering::SeqCst);
            }
        }

        let sink = VtaAuditSink::spawn(16, Arc::new(CountingEmitter(Arc::clone(&seen))));
        for i in 0..5 {
            sink.record(AuditRecord::for_signed_token("token_signed", "key-1", &format!("s{i}"), "jws"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(seen.load(Ordering::SeqCst), 5, "records with room are emitted");
        assert_eq!(sink.dropped(), 0, "nothing dropped when there is room");
    }
}
