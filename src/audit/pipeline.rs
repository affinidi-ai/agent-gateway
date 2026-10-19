//! Starts and stops the audit pipeline: journal writer, producer, cursors and
//! the dispatcher that delivers to every sink. One pipeline at a time writes
//! a journal: the journal's lock refuses a second writer (see
//! [`crate::audit::journal`]).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::sync::{oneshot, watch};
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{error, info};

use crate::audit::audit_log_sink::AuditLogSink;
use crate::audit::cursors::CursorStore;
use crate::audit::dispatch::{DispatcherConfig, JournalSource, run_dispatcher};
use crate::audit::integration_sink::ProductionSinks;
use crate::audit::journal::{JournalWriter, WriterConfig, WriterStopped, spawn_writer};
use crate::audit::producer::{Producer, producer};
use crate::audit::registry::{Sinks, sinks};
use crate::audit::sources::rebuild_sinks_within;
use crate::integrations::audit_integration_triggers::publish_audit_delivery;

const SEGMENT_MAX_BYTES: u64 = 16 * 1024 * 1024;
const REMEMBERED_IDS: usize = 1024;
/// How long a graceful stop lets the writer journal what it was handed.
const WRITER_GRACE: Duration = Duration::from_secs(5);
/// How long a stop waits for a cancelled writer before reporting it stuck.
const WRITER_BACKSTOP: Duration = Duration::from_secs(10);

/// A running pipeline. Every job runs under its cancellation token: the
/// journal writer, the dispatcher and, under the dispatcher, one reader per
/// sink. Dropping a pipeline cancels them all.
pub struct Pipeline {
    producer: &'static Producer,
    cancel: DropGuard,
    cursors: Arc<CursorStore>,
    writer: oneshot::Receiver<WriterStopped<JournalWriter>>,
    /// What the writer handed back once it stopped during a graceful stop.
    writer_stopped: Option<Result<WriterStopped<JournalWriter>, oneshot::error::RecvError>>,
    dispatcher: tokio::task::JoinHandle<()>,
}

impl Pipeline {
    /// Stops gracefully: disconnects the producer and gives the writer up to
    /// [`WRITER_GRACE`] to journal the records it was already handed, then
    /// stops everything with [`Pipeline::abort`].
    pub async fn stop(mut self) {
        self.producer.disconnect();
        if let Ok(stopped) = tokio::time::timeout(WRITER_GRACE, &mut self.writer).await {
            self.writer_stopped = Some(stopped);
        }
        self.abort().await;
    }

    /// Stops every job now: disconnects the producer, cancels the writer, the
    /// dispatcher and its readers, and closes the cursor store, so no cursor
    /// is saved after it. Records the writer had not journalled are
    /// discarded and counted as `aborted`. The journal, and its lock, is
    /// released last, once the dispatcher and the writer have stopped.
    pub async fn abort(self) {
        let Self {
            producer,
            cancel,
            cursors,
            writer,
            writer_stopped,
            dispatcher,
        } = self;
        producer.disconnect();
        drop(cancel);
        cursors.close();
        if let Err(e) = dispatcher.await {
            error!(error = %e, "The audit dispatcher ended abnormally");
        }
        let stopped = match writer_stopped {
            Some(stopped) => stopped,
            None => match tokio::time::timeout(WRITER_BACKSTOP, writer).await {
                Ok(stopped) => stopped,
                Err(_) => {
                    error!(
                        critical = true,
                        "The audit journal writer is stuck in I/O and did not stop; it keeps the journal lock, so no node can take over the audit journal until this node is rebooted"
                    );
                    return;
                }
            },
        };
        match stopped {
            Ok(WriterStopped { journal, lost, aborted }) => {
                info!(lost, aborted, "Audit journal writer stopped");
                drop(journal);
            }
            Err(_) => error!("The audit journal writer ended abnormally"),
        }
    }
}

/// Starts the pipeline for `producer` and `sinks`, keeping the journal under
/// `audit_dir/journal` and the VP Audit Log at `audit_log`. Everything that
/// can fail is opened before anything starts. Every job runs under `cancel`.
/// Fails with [`io::ErrorKind::WouldBlock`] while another writer has the
/// journal open.
pub fn start_with(
    producer: &'static Producer,
    sinks: &'static Sinks,
    audit_dir: &Path,
    audit_log: &Path,
    cancel: CancellationToken,
) -> io::Result<Pipeline> {
    let journal_dir = audit_dir.join("journal");
    let writer = JournalWriter::open(&journal_dir, SEGMENT_MAX_BYTES)?;
    let cursors = Arc::new(CursorStore::open(&journal_dir)?);
    let factory = ProductionSinks {
        audit_log: AuditLogSink::open(audit_log, REMEMBERED_IDS)?,
        publish: Arc::new(publish_audit_delivery),
    };
    let (durable_tx, durable) = watch::channel(
        writer
            .next_seq()
            .saturating_sub(1),
    );
    let (journal, pending) = mpsc::channel();
    let writer = spawn_writer(writer, pending, durable_tx, WriterConfig::default(), cancel.clone())?;
    producer.connect(journal);

    let source = JournalSource {
        cursors: cursors.clone(),
        dir: journal_dir,
        durable,
    };
    let dispatcher =
        tokio::spawn(run_dispatcher(factory, sinks, source, DispatcherConfig::default(), cancel.child_token()));
    Ok(Pipeline {
        producer,
        cancel: cancel.drop_guard(),
        cursors,
        writer,
        writer_stopped: None,
        dispatcher,
    })
}

/// Builds the current sinks into the registry; false when they could not be
/// built. Anything it leaves running, such as a rebuild retry, ends once the
/// given token is cancelled.
pub type BuildSinks = Arc<dyn Fn(&CancellationToken) -> BoxFuture<'static, bool> + Send + Sync>;

/// Runs at most one pipeline for a journal, started and stopped as the node
/// becomes Active or Standby. The sinks are built before every start, so the
/// dispatcher never starts from sinks that were never built or are stale.
///
/// Each period between stops has its own cancellation token, its epoch: a
/// wait to start, the sink rebuild retries and the pipeline's own token are
/// all under it, and [`PipelineControl::stop`] cancels it once the pipeline
/// has stopped gracefully.
pub struct PipelineControl {
    producer: &'static Producer,
    sinks: &'static Sinks,
    audit_dir: PathBuf,
    audit_log: PathBuf,
    build_sinks: BuildSinks,
    epoch: parking_lot::Mutex<CancellationToken>,
    running: tokio::sync::Mutex<Option<Pipeline>>,
}

impl PipelineControl {
    pub fn new(
        producer: &'static Producer,
        sinks: &'static Sinks,
        audit_dir: PathBuf,
        audit_log: PathBuf,
        build_sinks: BuildSinks,
    ) -> Self {
        Self {
            producer,
            sinks,
            audit_dir,
            audit_log,
            build_sinks,
            epoch: parking_lot::Mutex::new(CancellationToken::new()),
            running: tokio::sync::Mutex::new(None),
        }
    }

    /// The control for the process-wide producer and sinks, which it builds
    /// from the settings and integrations. The journal lives in
    /// `audit_dir/journal`.
    pub fn process_wide(
        audit_dir: PathBuf,
        audit_log: PathBuf,
    ) -> Self {
        Self::new(
            producer(),
            sinks(),
            audit_dir,
            audit_log,
            Arc::new(|epoch| Box::pin(rebuild_sinks_within(epoch.clone()))),
        )
    }

    /// The token of the current period, cancelled by the next
    /// [`PipelineControl::stop`].
    pub fn epoch(&self) -> CancellationToken {
        self.epoch.lock().clone()
    }

    /// Starts the pipeline unless it is running. Fails with
    /// [`io::ErrorKind::WouldBlock`] while the sinks cannot be built or
    /// another writer has the journal open.
    pub async fn try_start(&self) -> io::Result<()> {
        let mut running = self.running.lock().await;
        let epoch = self.epoch();
        self.start_into(&mut running, &epoch)
            .await
    }

    /// Starts the pipeline, trying again every `retry` while the sinks cannot
    /// be built or another writer has the journal open. Gives up with
    /// `Ok(false)` once `epoch` is cancelled. `epoch` is checked under the
    /// lock [`PipelineControl::stop`] takes, so a start for a period that a
    /// stop ended never happens.
    pub async fn start_when_free(
        &self,
        retry: Duration,
        epoch: &CancellationToken,
    ) -> io::Result<bool> {
        loop {
            {
                let mut running = self.running.lock().await;
                if epoch.is_cancelled() {
                    return Ok(false);
                }
                match self
                    .start_into(&mut running, epoch)
                    .await
                {
                    Ok(()) => return Ok(true),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
            if epoch
                .run_until_cancelled(tokio::time::sleep(retry))
                .await
                .is_none()
            {
                return Ok(false);
            }
        }
    }

    /// Builds the sinks, then starts the pipeline into `running`, under
    /// `epoch`, unless one is already there.
    async fn start_into(
        &self,
        running: &mut Option<Pipeline>,
        epoch: &CancellationToken,
    ) -> io::Result<()> {
        if running.is_some() {
            return Ok(());
        }
        if !(self.build_sinks)(epoch).await {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "the audit sinks could not be built"));
        }
        *running = Some(start_with(self.producer, self.sinks, &self.audit_dir, &self.audit_log, epoch.child_token())?);
        Ok(())
    }

    /// Stops the pipeline gracefully if it is running, releasing the journal,
    /// then ends the period: a wait to start and the sink rebuild retries end
    /// with it.
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        if let Some(pipeline) = running.take() {
            pipeline.stop().await;
        }
        std::mem::take(&mut *self.epoch.lock()).cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::registry::{EventMask, Sink, SinkId};
    use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent, audit_event};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn stored(path: &Path) -> Vec<DelegationAuditEvent> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    async fn wait_until(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(Instant::now() < deadline, "condition not met in time");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn a_produced_record_reaches_the_vp_audit_log() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let sinks: &'static Sinks = Box::leak(Box::default());
        sinks.replace(vec![Sink::new(SinkId::AuditLog, EventMask::from_categories(["consent_granted"]))], Vec::new());
        let producer: &'static Producer = Box::leak(Box::new(Producer::new(sinks)));

        let pipeline = start_with(producer, sinks, dir.path(), &log, CancellationToken::new()).unwrap();
        let record = audit_event(DelegationAuditAction::ConsentGranted, None, None, Some("github"), None);
        let event_id = record.event_id.clone();
        producer.submit(record);
        producer.submit(audit_event(DelegationAuditAction::TokenInjected, None, None, None, None));

        wait_until(|| stored(&log).len() == 1).await;
        assert_eq!(stored(&log)[0].event_id, event_id);
        assert!(
            dir.path()
                .join("journal")
                .is_dir()
        );
        pipeline.stop().await;
    }

    #[tokio::test]
    async fn a_record_for_another_sink_is_journalled_but_not_written_to_the_log() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let sinks: &'static Sinks = Box::leak(Box::default());
        let producer: &'static Producer = Box::leak(Box::new(Producer::new(sinks)));
        sinks.replace(
            vec![
                Sink::new(SinkId::AuditLog, EventMask::default()),
                Sink::new(SinkId::Integration("siem".to_string()), EventMask::from_categories(["consent_granted"])),
            ],
            Vec::new(),
        );
        let pipeline = start_with(producer, sinks, dir.path(), &log, CancellationToken::new()).unwrap();

        producer.submit(audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None));
        let journal = dir.path().join("journal");
        wait_until(|| crate::audit::cursors::journal_bytes(&journal).unwrap() > 0).await;

        assert!(stored(&log).is_empty());
        pipeline.stop().await;
    }

    fn journal_locked(audit_dir: &Path) -> bool {
        JournalWriter::open(&audit_dir.join("journal"), SEGMENT_MAX_BYTES)
            .err()
            .is_some_and(|e| e.kind() == io::ErrorKind::WouldBlock)
    }

    #[tokio::test]
    async fn the_journal_opens_for_another_writer_only_once_stop_returns() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (producer, sinks) = parts();
        let pipeline = start_with(producer, sinks, dir.path(), &log, CancellationToken::new()).unwrap();
        producer.submit(consent());
        wait_until(|| stored(&log).len() == 1).await;

        assert!(journal_locked(dir.path()));
        pipeline.stop().await;

        assert!(!journal_locked(dir.path()));
        assert_eq!(journal_seqs(dir.path()), vec![1]);
    }

    #[tokio::test]
    async fn an_aborted_pipeline_releases_the_journal_and_saves_no_more_cursors() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (producer, sinks) = parts();
        let pipeline = start_with(producer, sinks, dir.path(), &log, CancellationToken::new()).unwrap();
        producer.submit(consent());
        wait_until(|| stored(&log).len() == 1).await;
        let cursors = pipeline.cursors.clone();
        wait_until(|| cursors.get(&SinkId::AuditLog) == Some(1)).await;

        pipeline.abort().await;
        cursors
            .set(&SinkId::AuditLog, 9)
            .unwrap();
        producer.submit(consent());

        assert!(!journal_locked(dir.path()));
        assert_eq!(
            CursorStore::open(&dir.path().join("journal"))
                .unwrap()
                .get(&SinkId::AuditLog),
            Some(1)
        );
        assert_eq!(journal_seqs(dir.path()), vec![1]);
    }

    #[tokio::test]
    async fn a_dropped_pipeline_stops_its_jobs_and_releases_the_journal() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (producer, sinks) = parts();
        let pipeline = start_with(producer, sinks, dir.path(), &log, CancellationToken::new()).unwrap();
        assert!(journal_locked(dir.path()));

        drop(pipeline);

        wait_until(|| !journal_locked(dir.path())).await;
    }

    fn parts() -> (&'static Producer, &'static Sinks) {
        let sinks: &'static Sinks = Box::leak(Box::default());
        sinks.replace(vec![Sink::new(SinkId::AuditLog, EventMask::from_categories(["consent_granted"]))], Vec::new());
        let producer: &'static Producer = Box::leak(Box::new(Producer::new(sinks)));
        (producer, sinks)
    }

    fn built() -> BuildSinks {
        Arc::new(|_| Box::pin(async { true }))
    }

    fn consent() -> DelegationAuditEvent {
        audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None)
    }

    fn journal_seqs(audit_dir: &Path) -> Vec<u64> {
        crate::audit::journal::segment_paths(&audit_dir.join("journal"))
            .unwrap()
            .into_iter()
            .flat_map(|path| {
                std::fs::read_to_string(path)
                    .unwrap()
                    .lines()
                    .filter_map(|line| crate::audit::journal::JournalEntry::parse(line.as_bytes()))
                    .map(|entry| entry.seq)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[tokio::test]
    async fn a_stopped_pipeline_keeps_what_it_was_handed_and_a_restart_continues_after_it() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (producer, sinks) = parts();

        let pipeline = start_with(producer, sinks, dir.path(), &log, CancellationToken::new()).unwrap();
        producer.submit(consent());
        pipeline.stop().await;
        assert_eq!(journal_seqs(dir.path()), vec![1]);

        producer.submit(consent());
        let pipeline = start_with(producer, sinks, dir.path(), &log, CancellationToken::new()).unwrap();
        producer.submit(consent());

        wait_until(|| stored(&log).len() == 2).await;
        assert_eq!(journal_seqs(dir.path()), vec![1, 2]);
        pipeline.stop().await;
    }

    #[tokio::test]
    async fn a_second_pipeline_cannot_start_on_a_journal_in_use() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (first_producer, first_sinks) = parts();
        let (second_producer, second_sinks) = parts();

        let first = start_with(first_producer, first_sinks, dir.path(), &log, CancellationToken::new()).unwrap();
        let busy = start_with(second_producer, second_sinks, dir.path(), &log, CancellationToken::new())
            .err()
            .unwrap();
        assert_eq!(busy.kind(), io::ErrorKind::WouldBlock);

        first.stop().await;
        let second = start_with(second_producer, second_sinks, dir.path(), &log, CancellationToken::new()).unwrap();
        second.stop().await;
    }

    #[tokio::test]
    async fn a_standby_takes_over_the_journal_once_the_active_node_releases_it() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (active_producer, active_sinks) = parts();
        let (standby_producer, standby_sinks) = parts();
        let active =
            PipelineControl::new(active_producer, active_sinks, dir.path().to_path_buf(), log.clone(), built());
        let standby: &'static PipelineControl = Box::leak(Box::new(PipelineControl::new(
            standby_producer,
            standby_sinks,
            dir.path().to_path_buf(),
            log.clone(),
            built(),
        )));

        active
            .try_start()
            .await
            .unwrap();
        active_producer.submit(consent());
        let epoch = standby.epoch();
        let promoted = tokio::spawn(async move {
            standby
                .start_when_free(Duration::from_millis(10), &epoch)
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!promoted.is_finished());

        active.stop().await;
        let started = tokio::time::timeout(Duration::from_secs(5), promoted)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(started);

        standby_producer.submit(consent());
        wait_until(|| journal_seqs(dir.path()) == vec![1, 2]).await;
        standby.stop().await;
    }

    #[tokio::test]
    async fn waiting_for_the_journal_ends_once_the_control_is_stopped() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (active_producer, active_sinks) = parts();
        let (waiting_producer, waiting_sinks) = parts();
        let active =
            PipelineControl::new(active_producer, active_sinks, dir.path().to_path_buf(), log.clone(), built());
        let waiting = PipelineControl::new(waiting_producer, waiting_sinks, dir.path().to_path_buf(), log, built());
        active
            .try_start()
            .await
            .unwrap();

        let epoch = waiting.epoch();
        let (started, ()) = tokio::join!(waiting.start_when_free(Duration::from_secs(60), &epoch), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            waiting.stop().await;
        });

        assert!(!started.unwrap());
        assert!(epoch.is_cancelled());
        assert!(!waiting.epoch().is_cancelled());
        active.stop().await;
    }

    #[tokio::test]
    async fn a_wait_to_start_from_before_a_stop_never_starts_the_pipeline() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (producer, sinks) = parts();
        let (build, attempts) = building(&[true]);
        let control = PipelineControl::new(producer, sinks, dir.path().to_path_buf(), log, build);
        let epoch = control.epoch();

        control.stop().await;
        let started = control
            .start_when_free(Duration::from_millis(5), &epoch)
            .await
            .unwrap();

        assert!(!started);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            !dir.path()
                .join("journal")
                .exists()
        );
    }

    #[tokio::test]
    async fn the_sinks_are_built_under_the_period_a_stop_ends() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (producer, sinks) = parts();
        let seen: Arc<parking_lot::Mutex<Vec<CancellationToken>>> = Arc::default();
        let recorded = seen.clone();
        let build: BuildSinks = Arc::new(move |epoch| {
            recorded
                .lock()
                .push(epoch.clone());
            Box::pin(async { true })
        });
        let control = PipelineControl::new(producer, sinks, dir.path().to_path_buf(), log, build);

        control
            .try_start()
            .await
            .unwrap();
        assert!(!seen.lock()[0].is_cancelled());
        control.stop().await;
        control
            .try_start()
            .await
            .unwrap();

        let seen = seen.lock().clone();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].is_cancelled());
        assert!(!seen[1].is_cancelled());
        control.stop().await;
    }

    #[tokio::test]
    async fn a_control_starts_once_and_starts_again_after_a_stop() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (producer, sinks) = parts();
        let control = PipelineControl::new(producer, sinks, dir.path().to_path_buf(), log, built());

        control
            .try_start()
            .await
            .unwrap();
        control
            .try_start()
            .await
            .unwrap();
        producer.submit(consent());
        control.stop().await;
        control.stop().await;
        control
            .try_start()
            .await
            .unwrap();
        producer.submit(consent());
        control.stop().await;

        assert_eq!(journal_seqs(dir.path()), vec![1, 2]);
    }

    fn building(outcomes: &[bool]) -> (BuildSinks, Arc<std::sync::atomic::AtomicUsize>) {
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (outcomes, counted) = (outcomes.to_vec(), attempts.clone());
        let build: BuildSinks = Arc::new(move |_| {
            let attempt = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let built = outcomes
                .get(attempt)
                .or(outcomes.last())
                .copied()
                .unwrap_or(true);
            Box::pin(async move { built })
        });
        (build, attempts)
    }

    #[tokio::test]
    async fn the_sinks_are_built_before_the_journal_is_opened() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let sinks: &'static Sinks = Box::leak(Box::default());
        let producer: &'static Producer = Box::leak(Box::new(Producer::new(sinks)));
        let journal = dir.path().join("journal");
        let built_first = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = built_first.clone();
        let build: BuildSinks = Arc::new(move |_| {
            seen.store(!journal.exists(), std::sync::atomic::Ordering::SeqCst);
            sinks.replace(
                vec![Sink::new(SinkId::AuditLog, EventMask::from_categories(["consent_granted"]))],
                Vec::new(),
            );
            Box::pin(async { true })
        });
        let control = PipelineControl::new(producer, sinks, dir.path().to_path_buf(), log.clone(), build);

        control
            .try_start()
            .await
            .unwrap();
        producer.submit(consent());

        wait_until(|| stored(&log).len() == 1).await;
        assert!(built_first.load(std::sync::atomic::Ordering::SeqCst));
        control.stop().await;
    }

    #[tokio::test]
    async fn a_control_whose_sinks_cannot_be_built_does_not_start() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (producer, sinks) = parts();
        let (build, attempts) = building(&[false]);
        let control = PipelineControl::new(producer, sinks, dir.path().to_path_buf(), log, build);

        let refused = control
            .try_start()
            .await
            .err()
            .unwrap();

        assert_eq!(refused.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            !dir.path()
                .join("journal")
                .exists()
        );
    }

    #[tokio::test]
    async fn waiting_to_start_retries_until_the_sinks_are_built() {
        let dir = TempDir::new().unwrap();
        let log = dir
            .path()
            .join("delegation-audit.jsonl");
        let (producer, sinks) = parts();
        let (build, attempts) = building(&[false, false, true]);
        let control = PipelineControl::new(producer, sinks, dir.path().to_path_buf(), log.clone(), build);

        let started = control
            .start_when_free(Duration::from_millis(5), &control.epoch())
            .await
            .unwrap();
        producer.submit(consent());

        assert!(started);
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
        wait_until(|| stored(&log).len() == 1).await;
        control.stop().await;
    }
}
