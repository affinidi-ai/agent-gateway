//! System-level CPU and memory metrics collection with local file persistence.
//!
//! Periodically samples process and system resource usage, keeps a bounded
//! in-memory ring buffer, and flushes it to a JSON file at most once per
//! [`PERSIST_INTERVAL`] so historical data survives restarts without
//! rewriting the whole history on every sample. The gateway also writes it on
//! SIGTERM or Ctrl-C through [`SystemMetricsStore::flush`]; a crash or forced
//! kill drops the samples taken since the last write (up to
//! [`PERSIST_INTERVAL`]). On a rolling deploy the new instance starts from the
//! file as it stood when it loaded, so up to [`PERSIST_INTERVAL`] before the old
//! instance stopped can be missing too. This history only feeds the dashboard view.
//!
//! When an OpenTelemetry meter provider is active, every sample is also
//! recorded as OTel gauge metrics and exported via OTLP.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use opentelemetry::{global, metrics::Gauge};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use sysinfo::{Pid, System};
use tokio::sync::{Mutex, RwLock};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

/// Collection interval in seconds.
pub const SYSTEM_METRICS_INTERVAL_SECS: u64 = 5;

/// Maximum number of samples kept in memory / on disk.
const MAX_SAMPLES: usize = 17_280; // 24 h at 5 s intervals

/// Minimum time between writes of the sample history to disk.
const PERSIST_INTERVAL: Duration = Duration::from_secs(900);

/// Age after which [`SystemMetricsStore::load`] removes a temp file left by an interrupted write.
/// Younger ones are kept because another instance sharing the directory may still be writing them.
const STALE_TEMP_FILE_AGE: Duration = Duration::from_secs(60);

/// A single point-in-time snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetricsSample {
    /// UTC timestamp
    pub timestamp: DateTime<Utc>,
    /// Process CPU usage (0-100 per core, so can exceed 100 on multi-core).
    pub process_cpu_percent: f32,
    /// Process resident memory in bytes.
    pub process_memory_bytes: u64,
    /// Overall system CPU usage (0-100).
    pub system_cpu_percent: f32,
    /// Total system memory in bytes.
    pub system_total_memory_bytes: u64,
    /// Used system memory in bytes.
    pub system_used_memory_bytes: u64,
}

/// Static system identity information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub name: Option<String>,
    pub kernel_version: Option<String>,
    pub os_version: Option<String>,
    pub host_name: Option<String>,
    /// Service uptime in seconds.
    pub uptime_seconds: u64,
}

/// Response returned by the `/v1/dashboard/system-metrics` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetricsResponse {
    pub system_info: SystemInfo,
    pub samples: Vec<SystemMetricsSample>,
    /// Current / latest snapshot (convenience).
    pub current: Option<SystemMetricsSample>,
}

/// Persistent store for system metrics.
pub struct SystemMetricsStore {
    samples: Arc<RwLock<Vec<SystemMetricsSample>>>,
    storage_path: PathBuf,
    /// When the process (store) was created – used for service uptime.
    started_at: std::time::Instant,
    persist_interval: Duration,
    last_persisted: Mutex<Option<Instant>>,
}

impl SystemMetricsStore {
    pub fn new<P: AsRef<Path>>(storage_dir: P) -> Self {
        Self::with_persist_interval(storage_dir, PERSIST_INTERVAL)
    }

    fn with_persist_interval<P: AsRef<Path>>(
        storage_dir: P,
        persist_interval: Duration,
    ) -> Self {
        let storage_path = storage_dir
            .as_ref()
            .join("system_metrics.json");
        Self {
            samples: Arc::new(RwLock::new(Vec::new())),
            storage_path,
            started_at: std::time::Instant::now(),
            persist_interval,
            last_persisted: Mutex::new(None),
        }
    }

    /// Load previously persisted samples from disk.
    pub async fn load(&self) -> Result<()> {
        if let Some(parent) = self.storage_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create system_metrics directory: {:?}", parent))?;
        }
        self.remove_stale_temp_files()
            .await;

        if self.storage_path.exists() {
            match tokio::fs::read_to_string(&self.storage_path).await {
                Ok(content) => match serde_json::from_str::<Vec<SystemMetricsSample>>(&content) {
                    Ok(mut loaded) => {
                        if loaded.len() > MAX_SAMPLES {
                            loaded.drain(..loaded.len() - MAX_SAMPLES);
                        }
                        info!("Loaded {} system metrics samples from {:?}", loaded.len(), self.storage_path);
                        let mut samples = self.samples.write().await;
                        *samples = loaded;
                    }
                    Err(e) => {
                        warn!("Failed to parse system metrics file, starting fresh: {}", e);
                    }
                },
                Err(e) => {
                    warn!("Failed to read system metrics file, starting fresh: {}", e);
                }
            }
        } else {
            info!("No previous system metrics file found, starting fresh");
        }
        Ok(())
    }

    /// Removes temp files older than [`STALE_TEMP_FILE_AGE`] that an interrupted write left
    /// beside the history file.
    async fn remove_stale_temp_files(&self) {
        let (Some(dir), Some(name)) = (self.storage_path.parent(), self.storage_path.file_name()) else {
            return;
        };
        let prefix = format!("{}.", name.to_string_lossy());
        let mut entries = match tokio::fs::read_dir(dir).await {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to list {:?} for stale system metrics temp files: {}", dir, e);
                return;
            }
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if !file_name.starts_with(&prefix) || !file_name.ends_with(".tmp") {
                continue;
            }
            let stale = entry
                .metadata()
                .await
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= STALE_TEMP_FILE_AGE);
            if !stale {
                continue;
            }
            match tokio::fs::remove_file(entry.path()).await {
                Ok(()) => info!("Removed stale system metrics temp file {:?}", entry.path()),
                Err(e) => warn!("Failed to remove stale system metrics temp file {:?}: {}", entry.path(), e),
            }
        }
    }

    /// Append a new sample, persisting the history when [`Self::persist_interval`] has elapsed.
    async fn push(
        &self,
        sample: SystemMetricsSample,
    ) {
        let data = {
            let mut samples = self.samples.write().await;
            samples.push(sample);
            let len = samples.len();
            if len > MAX_SAMPLES {
                samples.drain(..len - MAX_SAMPLES);
            }
            if !self.persist_due().await {
                return;
            }
            samples.clone()
        };

        if let Err(e) = write_samples_atomically(&self.storage_path, &data).await {
            error!("Failed to persist system metrics: {:#}", e);
        }
    }

    /// Writes the whole history now, regardless of [`Self::persist_interval`]. Called on shutdown.
    pub async fn flush(&self) {
        let data = self
            .samples
            .read()
            .await
            .clone();
        if data.is_empty() {
            return;
        }
        *self
            .last_persisted
            .lock()
            .await = Some(Instant::now());
        if let Err(e) = write_samples_atomically(&self.storage_path, &data).await {
            error!("Failed to persist system metrics: {:#}", e);
        }
    }

    /// Claims the next persist slot. A failed write still consumes the slot, so a persistent
    /// storage fault is retried once per interval rather than on every sample.
    async fn persist_due(&self) -> bool {
        let mut last = self
            .last_persisted
            .lock()
            .await;
        let due = last.is_none_or(|at| at.elapsed() >= self.persist_interval);
        if due {
            *last = Some(Instant::now());
        }
        due
    }

    /// Return all samples (for the API response).
    #[allow(dead_code)]
    pub async fn get_response(&self) -> SystemMetricsResponse {
        self.get_response_since(None)
            .await
    }

    /// Return samples filtered to a time window.
    ///
    /// `since` – if `Some`, only samples with `timestamp >= since` are included.
    pub async fn get_response_since(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> SystemMetricsResponse {
        let samples = self.samples.read().await;
        let current = samples.last().cloned();
        let filtered = match since {
            Some(cutoff) => samples
                .iter()
                .filter(|s| s.timestamp > cutoff)
                .cloned()
                .collect(),
            None => samples.clone(),
        };
        SystemMetricsResponse {
            system_info: SystemInfo {
                name: System::name(),
                kernel_version: System::kernel_version(),
                os_version: System::os_version(),
                host_name: System::host_name(),
                uptime_seconds: self
                    .started_at
                    .elapsed()
                    .as_secs(),
            },
            samples: filtered,
            current,
        }
    }
}

static GLOBAL_SYSTEM_METRICS_STORE: OnceLock<Arc<SystemMetricsStore>> = OnceLock::new();

/// Register the process-wide system metrics store (orchestrator, once) so shutdown can flush it.
pub fn set_global_system_metrics_store(store: Arc<SystemMetricsStore>) {
    let _ = GLOBAL_SYSTEM_METRICS_STORE.set(store);
}

/// Access the process-wide system metrics store, if registered.
pub fn global_system_metrics_store() -> Option<Arc<SystemMetricsStore>> {
    GLOBAL_SYSTEM_METRICS_STORE
        .get()
        .cloned()
}

/// Writes the history to a uniquely named sibling temp file and renames it over `path`, so a
/// reader never sees a partial file and concurrent writers sharing the directory cannot collide.
async fn write_samples_atomically(
    path: &Path,
    samples: &[SystemMetricsSample],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create system_metrics directory: {:?}", parent))?;
    }
    let json = serde_json::to_vec(samples).context("Failed to serialize system metrics")?;
    let tmp_path = path.with_extension(format!("json.{}.tmp", uuid::Uuid::new_v4().simple()));
    if let Err(e) = tokio::fs::write(&tmp_path, json).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e).with_context(|| format!("Failed to write {:?}", tmp_path));
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e).with_context(|| format!("Failed to replace {:?}", path));
    }
    Ok(())
}

/// OpenTelemetry gauge instruments for system metrics.
///
/// Created once on first collection tick and reused for the lifetime of the
/// process.  The gauges record into whichever `MeterProvider` was set as
/// global at the time they were created (i.e. the OTLP provider when OTel is
/// enabled).
struct OtelSystemGauges {
    process_cpu_percent: Gauge<f64>,
    process_memory_bytes: Gauge<u64>,
    system_cpu_percent: Gauge<f64>,
    system_total_memory_bytes: Gauge<u64>,
    system_used_memory_bytes: Gauge<u64>,
}

impl OtelSystemGauges {
    fn new() -> Self {
        let meter = global::meter("agent_gateway.system");
        Self {
            process_cpu_percent: meter
                .f64_gauge("process.cpu.utilization")
                .with_description("Process CPU usage percentage (per core, can exceed 100)")
                .with_unit("%")
                .build(),
            process_memory_bytes: meter
                .u64_gauge("process.memory.usage")
                .with_description("Process resident memory in bytes")
                .with_unit("By")
                .build(),
            system_cpu_percent: meter
                .f64_gauge("system.cpu.utilization")
                .with_description("Overall system CPU usage percentage")
                .with_unit("%")
                .build(),
            system_total_memory_bytes: meter
                .u64_gauge("system.memory.limit")
                .with_description("Total system memory in bytes")
                .with_unit("By")
                .build(),
            system_used_memory_bytes: meter
                .u64_gauge("system.memory.usage")
                .with_description("Used system memory in bytes")
                .with_unit("By")
                .build(),
        }
    }

    fn record(
        &self,
        sample: &SystemMetricsSample,
    ) {
        self.process_cpu_percent
            .record(sample.process_cpu_percent as f64, &[]);
        self.process_memory_bytes
            .record(sample.process_memory_bytes, &[]);
        self.system_cpu_percent
            .record(sample.system_cpu_percent as f64, &[]);
        self.system_total_memory_bytes
            .record(sample.system_total_memory_bytes, &[]);
        self.system_used_memory_bytes
            .record(sample.system_used_memory_bytes, &[]);
    }
}

/// Background task that collects CPU / memory metrics at a fixed interval.
pub async fn periodic_system_metrics_collection(
    store: Arc<SystemMetricsStore>,
    interval_secs: u64,
) {
    let mut sys = System::new();
    let pid = Pid::from_u32(std::process::id());
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Create OTel gauges once – they record into the global meter provider.
    let otel_gauges = OtelSystemGauges::new();

    info!("Starting system metrics collection (every {}s)", interval_secs);

    loop {
        interval.tick().await;

        // Refresh only what we need.
        sys.refresh_cpu_all();
        sys.refresh_memory();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);

        let (process_cpu, process_mem) = sys
            .process(pid)
            .map(|p| (p.cpu_usage(), p.memory()))
            .unwrap_or((0.0, 0));

        let system_cpu = sys.global_cpu_usage();
        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();

        let sample = SystemMetricsSample {
            timestamp: Utc::now(),
            process_cpu_percent: process_cpu,
            process_memory_bytes: process_mem,
            system_cpu_percent: system_cpu,
            system_total_memory_bytes: total_mem,
            system_used_memory_bytes: used_mem,
        };

        debug!(
            "System metrics: proc_cpu={:.1}%, proc_mem={:.1}MB, sys_cpu={:.1}%, sys_mem={}/{}",
            process_cpu,
            process_mem as f64 / 1_048_576.0,
            system_cpu,
            used_mem / 1_048_576,
            total_mem / 1_048_576,
        );

        // Record into OpenTelemetry gauges (exported via OTLP on next flush).
        otel_gauges.record(&sample);

        store.push(sample).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(cpu: f32) -> SystemMetricsSample {
        SystemMetricsSample {
            timestamp: Utc::now(),
            process_cpu_percent: cpu,
            process_memory_bytes: 1024,
            system_cpu_percent: cpu,
            system_total_memory_bytes: 4096,
            system_used_memory_bytes: 2048,
        }
    }

    async fn persisted_cpu(dir: &Path) -> Vec<f32> {
        let content = tokio::fs::read_to_string(dir.join("system_metrics.json"))
            .await
            .expect("system_metrics.json should exist");
        serde_json::from_str::<Vec<SystemMetricsSample>>(&content)
            .expect("persisted history should be valid JSON")
            .iter()
            .map(|s| s.process_cpu_percent)
            .collect()
    }

    #[tokio::test]
    async fn persists_first_sample_then_throttles_until_interval_elapses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SystemMetricsStore::with_persist_interval(dir.path(), Duration::from_secs(3600));

        store.push(sample(1.0)).await;
        store.push(sample(2.0)).await;
        store.push(sample(3.0)).await;

        assert_eq!(persisted_cpu(dir.path()).await, vec![1.0]);
        let in_memory: Vec<f32> = store
            .get_response_since(None)
            .await
            .samples
            .iter()
            .map(|s| s.process_cpu_percent)
            .collect();
        assert_eq!(in_memory, vec![1.0, 2.0, 3.0]);
    }

    #[tokio::test]
    async fn persists_full_history_once_interval_has_elapsed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SystemMetricsStore::with_persist_interval(dir.path(), Duration::ZERO);

        store.push(sample(1.0)).await;
        store.push(sample(2.0)).await;

        assert_eq!(persisted_cpu(dir.path()).await, vec![1.0, 2.0]);
    }

    #[tokio::test]
    async fn persisted_history_is_restored_by_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = SystemMetricsStore::with_persist_interval(dir.path(), Duration::ZERO);
        writer.push(sample(1.0)).await;
        writer.push(sample(2.0)).await;

        let reader = SystemMetricsStore::new(dir.path());
        reader
            .load()
            .await
            .expect("load");

        let restored: Vec<f32> = reader
            .get_response_since(None)
            .await
            .samples
            .iter()
            .map(|s| s.process_cpu_percent)
            .collect();
        assert_eq!(restored, vec![1.0, 2.0]);
    }

    #[tokio::test]
    async fn persisting_leaves_no_temp_files_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SystemMetricsStore::with_persist_interval(dir.path(), Duration::ZERO);
        store.push(sample(1.0)).await;
        store.push(sample(2.0)).await;

        let mut names = Vec::new();
        let mut entries = tokio::fs::read_dir(dir.path())
            .await
            .expect("read_dir");
        while let Some(entry) = entries
            .next_entry()
            .await
            .expect("next_entry")
        {
            names.push(
                entry
                    .file_name()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        assert_eq!(names, vec!["system_metrics.json".to_string()]);
    }

    #[tokio::test]
    async fn load_removes_stale_temp_files_and_keeps_recent_ones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let stale = dir
            .path()
            .join("system_metrics.json.0001.tmp");
        let recent = dir
            .path()
            .join("system_metrics.json.0002.tmp");
        let unrelated = dir
            .path()
            .join("other.json.0003.tmp");
        for path in [&stale, &recent, &unrelated] {
            tokio::fs::write(path, b"partial")
                .await
                .expect("create temp file");
        }
        let old = std::time::SystemTime::now() - STALE_TEMP_FILE_AGE - Duration::from_secs(1);
        for path in [&stale, &unrelated] {
            std::fs::File::options()
                .write(true)
                .open(path)
                .and_then(|f| f.set_modified(old))
                .expect("age temp file");
        }

        SystemMetricsStore::new(dir.path())
            .load()
            .await
            .expect("load");

        assert!(!stale.exists());
        assert!(recent.exists());
        assert!(unrelated.exists());
    }

    #[tokio::test]
    async fn flush_writes_full_history_before_interval_elapses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SystemMetricsStore::with_persist_interval(dir.path(), Duration::from_secs(3600));
        store.push(sample(1.0)).await;
        store.push(sample(2.0)).await;
        assert_eq!(persisted_cpu(dir.path()).await, vec![1.0]);

        store.flush().await;

        assert_eq!(persisted_cpu(dir.path()).await, vec![1.0, 2.0]);
    }

    #[tokio::test]
    async fn flush_with_no_samples_leaves_existing_history_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let writer = SystemMetricsStore::with_persist_interval(dir.path(), Duration::ZERO);
        writer.push(sample(1.0)).await;

        SystemMetricsStore::new(dir.path())
            .flush()
            .await;

        assert_eq!(persisted_cpu(dir.path()).await, vec![1.0]);
    }

    #[tokio::test]
    async fn failed_rename_removes_temp_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir
            .path()
            .join("system_metrics.json");
        tokio::fs::create_dir(&target)
            .await
            .expect("create a directory at the history path");
        tokio::fs::write(target.join("keep"), b"")
            .await
            .expect("make the directory non-empty");

        let result = write_samples_atomically(&target, &[sample(1.0)]).await;

        assert!(result.is_err());
        let mut names = Vec::new();
        let mut entries = tokio::fs::read_dir(dir.path())
            .await
            .expect("read_dir");
        while let Some(entry) = entries
            .next_entry()
            .await
            .expect("next_entry")
        {
            names.push(
                entry
                    .file_name()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        assert_eq!(names, vec!["system_metrics.json".to_string()]);
    }

    #[tokio::test]
    async fn failed_write_keeps_samples_in_memory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let not_a_directory = dir.path().join("blocker");
        tokio::fs::write(&not_a_directory, b"")
            .await
            .expect("create blocker file");
        let store = SystemMetricsStore::with_persist_interval(&not_a_directory, Duration::ZERO);

        store.push(sample(1.0)).await;

        assert!(
            !not_a_directory
                .join("system_metrics.json")
                .exists()
        );
        assert_eq!(
            store
                .get_response_since(None)
                .await
                .samples
                .len(),
            1
        );
    }
}
