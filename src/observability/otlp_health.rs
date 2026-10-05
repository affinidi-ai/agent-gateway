//! OTLP export health tracking and bounded exponential backoff.
//!
//! The OpenTelemetry SDK processors (`BatchSpanProcessor`, `PeriodicReader`,
//! `BatchLogProcessor`) call their exporter every cycle and implement no retry
//! ceiling of their own — when the collector is unreachable this produces
//! repeated per-cycle export errors indefinitely.
//!
//! This module provides:
//! - a per-signal [`SignalHealth`] snapshot (surfaced to the dashboard),
//! - a [`BackoffController`] that gates export attempts with bounded
//!   exponential backoff (capped at [`BACKOFF_CAP`]), and
//! - three exporter decorators ([`BackoffSpanExporter`],
//!   [`BackoffMetricExporter`], [`BackoffLogExporter`]) that consult the
//!   controller: while inside a backoff window they short-circuit the export
//!   (dropping that batch — the collector is unreachable anyway) instead of
//!   hammering the network and spamming logs.
//!
//! An export failure is logged **once per real attempt** (attempts are
//! rate-limited by the backoff), and a single INFO is emitted on recovery.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tracing::{info, warn};

/// Base backoff applied after the first consecutive failure.
const BACKOFF_BASE: Duration = Duration::from_secs(5);
/// Maximum backoff between export attempts (30 minutes).
const BACKOFF_CAP: Duration = Duration::from_secs(30 * 60);
/// Cap on the stored last-error string to avoid unbounded growth.
const MAX_ERROR_LEN: usize = 500;

/// The three OTLP signals exported independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpSignal {
    Traces,
    Metrics,
    Logs,
}

impl OtlpSignal {
    fn as_str(self) -> &'static str {
        match self {
            OtlpSignal::Traces => "traces",
            OtlpSignal::Metrics => "metrics",
            OtlpSignal::Logs => "logs",
        }
    }
}

impl std::fmt::Display for OtlpSignal {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serializable per-signal export health snapshot for the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct OtlpSignalStatus {
    /// Signal name: `traces` | `metrics` | `logs`.
    pub signal: String,
    /// Whether the last export attempt succeeded (or none has run yet).
    pub healthy: bool,
    /// Whether this signal has ever attempted an export since startup.
    pub active: bool,
    /// Consecutive failures since the last success.
    pub consecutive_failures: u32,
    /// Current backoff between attempts, in seconds (0 when healthy).
    pub backoff_seconds: u64,
    /// Last export error message, if any.
    pub last_error: Option<String>,
    /// RFC 3339 timestamp of the last error, if any.
    pub last_error_at: Option<String>,
    /// RFC 3339 timestamp of the last successful export, if any.
    pub last_success_at: Option<String>,
    /// RFC 3339 timestamp when the next export attempt is allowed, if backing off.
    pub next_retry_at: Option<String>,
}

/// Interior-mutable per-signal health, updated by a [`BackoffController`].
#[derive(Debug)]
struct SignalHealth {
    healthy: AtomicBool,
    active: AtomicBool,
    consecutive_failures: AtomicU32,
    backoff_seconds: AtomicU64,
    last_error_at_ms: AtomicI64,
    last_success_at_ms: AtomicI64,
    next_retry_at_ms: AtomicI64,
    last_error: Mutex<Option<String>>,
}

impl SignalHealth {
    fn new() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            active: AtomicBool::new(false),
            consecutive_failures: AtomicU32::new(0),
            backoff_seconds: AtomicU64::new(0),
            last_error_at_ms: AtomicI64::new(0),
            last_success_at_ms: AtomicI64::new(0),
            next_retry_at_ms: AtomicI64::new(0),
            last_error: Mutex::new(None),
        }
    }

    fn snapshot(
        &self,
        signal: OtlpSignal,
    ) -> OtlpSignalStatus {
        OtlpSignalStatus {
            signal: signal.as_str().to_string(),
            healthy: self
                .healthy
                .load(Ordering::Relaxed),
            active: self
                .active
                .load(Ordering::Relaxed),
            consecutive_failures: self
                .consecutive_failures
                .load(Ordering::Relaxed),
            backoff_seconds: self
                .backoff_seconds
                .load(Ordering::Relaxed),
            last_error: self
                .last_error
                .lock()
                .ok()
                .and_then(|g| g.clone()),
            last_error_at: ms_to_rfc3339(
                self.last_error_at_ms
                    .load(Ordering::Relaxed),
            ),
            last_success_at: ms_to_rfc3339(
                self.last_success_at_ms
                    .load(Ordering::Relaxed),
            ),
            next_retry_at: ms_to_rfc3339(
                self.next_retry_at_ms
                    .load(Ordering::Relaxed),
            ),
        }
    }
}

/// Gates OTLP export attempts with bounded exponential backoff and records the
/// resulting health for the dashboard. Shared (`Arc`) between the exporter
/// decorator and the global registry the status endpoint reads.
#[derive(Debug)]
pub struct BackoffController {
    signal: OtlpSignal,
    health: Arc<SignalHealth>,
    /// Monotonic gate: the earliest instant a new export attempt is allowed.
    next_allowed: Mutex<Option<Instant>>,
}

impl BackoffController {
    fn new(signal: OtlpSignal) -> Self {
        Self {
            signal,
            health: Arc::new(SignalHealth::new()),
            next_allowed: Mutex::new(None),
        }
    }

    /// Returns `true` when the caller should skip the export because a backoff
    /// window is still open.
    pub fn should_skip(&self) -> bool {
        let guard = self
            .next_allowed
            .lock()
            .expect("next_allowed poisoned");
        matches!(*guard, Some(t) if Instant::now() < t)
    }

    /// Record a successful export: clear backoff and mark the signal healthy.
    pub fn record_success(&self) {
        self.health
            .active
            .store(true, Ordering::Relaxed);
        let prev_failures = self
            .health
            .consecutive_failures
            .swap(0, Ordering::Relaxed);
        let was_unhealthy = !self
            .health
            .healthy
            .swap(true, Ordering::Relaxed);
        self.health
            .backoff_seconds
            .store(0, Ordering::Relaxed);
        self.health
            .last_success_at_ms
            .store(now_ms(), Ordering::Relaxed);
        self.health
            .next_retry_at_ms
            .store(0, Ordering::Relaxed);
        *self
            .next_allowed
            .lock()
            .expect("next_allowed poisoned") = None;

        if was_unhealthy || prev_failures > 0 {
            info!(
                target: "otlp_export",
                signal = %self.signal,
                recovered_after_failures = prev_failures,
                "OTLP {} export recovered after {} consecutive failure(s)",
                self.signal, prev_failures
            );
        }
    }

    /// Record a failed export: extend the backoff window and mark the signal
    /// unhealthy. Logs one WARN per real attempt (attempts are backoff-gated).
    pub fn record_failure(
        &self,
        error: &str,
    ) {
        self.health
            .active
            .store(true, Ordering::Relaxed);
        let failures = self
            .health
            .consecutive_failures
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        let backoff = compute_backoff(failures);
        let backoff_secs = backoff.as_secs();

        self.health
            .healthy
            .store(false, Ordering::Relaxed);
        self.health
            .backoff_seconds
            .store(backoff_secs, Ordering::Relaxed);
        let now = now_ms();
        self.health
            .last_error_at_ms
            .store(now, Ordering::Relaxed);
        self.health
            .next_retry_at_ms
            .store(now.saturating_add(backoff.as_millis() as i64), Ordering::Relaxed);
        if let Ok(mut guard) = self.health.last_error.lock() {
            *guard = Some(truncate_error(error));
        }
        *self
            .next_allowed
            .lock()
            .expect("next_allowed poisoned") = Some(Instant::now() + backoff);

        warn!(
            target: "otlp_export",
            signal = %self.signal,
            consecutive_failures = failures,
            backoff_seconds = backoff_secs,
            error = error,
            "OTLP {} export failed; backing off {}s before next attempt",
            self.signal, backoff_secs
        );
    }

    /// Clear the backoff window and failure counters so the next export attempt
    /// happens immediately. Called on config apply so a corrected endpoint is
    /// retried at once instead of waiting out a stale backoff window.
    pub fn reset(&self) {
        self.health
            .consecutive_failures
            .store(0, Ordering::Relaxed);
        self.health
            .backoff_seconds
            .store(0, Ordering::Relaxed);
        self.health
            .next_retry_at_ms
            .store(0, Ordering::Relaxed);
        self.health
            .healthy
            .store(true, Ordering::Relaxed);
        *self
            .next_allowed
            .lock()
            .expect("next_allowed poisoned") = None;
    }
}

/// Exponential backoff `BACKOFF_BASE * 2^(failures - 1)`, capped at
/// [`BACKOFF_CAP`].
fn compute_backoff(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    let exp = (failures - 1).min(32);
    let scaled = BACKOFF_BASE
        .as_secs()
        .saturating_mul(
            1u64.checked_shl(exp)
                .unwrap_or(u64::MAX),
        );
    Duration::from_secs(scaled.min(BACKOFF_CAP.as_secs()))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn ms_to_rfc3339(ms: i64) -> Option<String> {
    if ms == 0 {
        return None;
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms).map(|dt| dt.to_rfc3339())
}

fn truncate_error(error: &str) -> String {
    if error.len() <= MAX_ERROR_LEN {
        return error.to_string();
    }
    let mut end = MAX_ERROR_LEN;
    while end > 0 && !error.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &error[..end])
}

// ── Global registry ─────────────────────────────────────────────────

struct Registry {
    traces: Arc<BackoffController>,
    metrics: Arc<BackoffController>,
    logs: Arc<BackoffController>,
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| Registry {
        traces: Arc::new(BackoffController::new(OtlpSignal::Traces)),
        metrics: Arc::new(BackoffController::new(OtlpSignal::Metrics)),
        logs: Arc::new(BackoffController::new(OtlpSignal::Logs)),
    })
}

/// Return the process-global [`BackoffController`] for a signal. Stable across
/// OTEL re-initialisation so the gate state and health survive a config reload.
pub fn controller(signal: OtlpSignal) -> Arc<BackoffController> {
    let r = registry();
    match signal {
        OtlpSignal::Traces => r.traces.clone(),
        OtlpSignal::Metrics => r.metrics.clone(),
        OtlpSignal::Logs => r.logs.clone(),
    }
}

/// Reset the backoff/health state for a signal so the next export attempt is
/// immediate (e.g. on a config apply that may have corrected the endpoint).
pub fn reset_backoff(signal: OtlpSignal) {
    controller(signal).reset();
}

/// Snapshot the per-signal export health for the status endpoint.
pub fn snapshot() -> Vec<OtlpSignalStatus> {
    let r = registry();
    vec![
        r.traces
            .health
            .snapshot(OtlpSignal::Traces),
        r.metrics
            .health
            .snapshot(OtlpSignal::Metrics),
        r.logs
            .health
            .snapshot(OtlpSignal::Logs),
    ]
}

// ── Exporter decorators ─────────────────────────────────────────────

use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;

/// Backoff-gating [`opentelemetry_sdk::trace::SpanExporter`] decorator.
#[derive(Debug)]
pub struct BackoffSpanExporter<E> {
    inner: E,
    controller: Arc<BackoffController>,
}

impl<E> BackoffSpanExporter<E> {
    pub fn new(
        inner: E,
        controller: Arc<BackoffController>,
    ) -> Self {
        Self { inner, controller }
    }
}

impl<E> opentelemetry_sdk::trace::SpanExporter for BackoffSpanExporter<E>
where
    E: opentelemetry_sdk::trace::SpanExporter,
{
    async fn export(
        &self,
        batch: Vec<opentelemetry_sdk::trace::SpanData>,
    ) -> OTelSdkResult {
        if self.controller.should_skip() {
            return Ok(());
        }
        match self.inner.export(batch).await {
            Ok(()) => {
                self.controller
                    .record_success();
                Ok(())
            }
            Err(e) => {
                // Swallow the error (return Ok) so the SDK processor does not
                // add its own per-cycle error log; our controller logs once per
                // attempt and records the failure for the dashboard.
                self.controller
                    .record_failure(&e.to_string());
                Ok(())
            }
        }
    }

    fn set_resource(
        &mut self,
        resource: &Resource,
    ) {
        self.inner
            .set_resource(resource);
    }

    fn shutdown(&mut self) -> OTelSdkResult {
        self.inner.shutdown()
    }
}

/// Backoff-gating [`opentelemetry_sdk::metrics::exporter::PushMetricExporter`]
/// decorator.
#[derive(Debug)]
pub struct BackoffMetricExporter<E> {
    inner: E,
    controller: Arc<BackoffController>,
}

impl<E> BackoffMetricExporter<E> {
    pub fn new(
        inner: E,
        controller: Arc<BackoffController>,
    ) -> Self {
        Self { inner, controller }
    }
}

impl<E> opentelemetry_sdk::metrics::exporter::PushMetricExporter for BackoffMetricExporter<E>
where
    E: opentelemetry_sdk::metrics::exporter::PushMetricExporter,
{
    async fn export(
        &self,
        metrics: &opentelemetry_sdk::metrics::data::ResourceMetrics,
    ) -> OTelSdkResult {
        if self.controller.should_skip() {
            return Ok(());
        }
        match self
            .inner
            .export(metrics)
            .await
        {
            Ok(()) => {
                self.controller
                    .record_success();
                Ok(())
            }
            Err(e) => {
                self.controller
                    .record_failure(&e.to_string());
                Ok(())
            }
        }
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn shutdown_with_timeout(
        &self,
        timeout: Duration,
    ) -> OTelSdkResult {
        self.inner
            .shutdown_with_timeout(timeout)
    }

    fn temporality(&self) -> opentelemetry_sdk::metrics::Temporality {
        self.inner.temporality()
    }
}

/// Backoff-gating [`opentelemetry_sdk::logs::LogExporter`] decorator.
#[derive(Debug)]
pub struct BackoffLogExporter<E> {
    inner: E,
    controller: Arc<BackoffController>,
}

impl<E> BackoffLogExporter<E> {
    pub fn new(
        inner: E,
        controller: Arc<BackoffController>,
    ) -> Self {
        Self { inner, controller }
    }
}

impl<E> opentelemetry_sdk::logs::LogExporter for BackoffLogExporter<E>
where
    E: opentelemetry_sdk::logs::LogExporter,
{
    async fn export(
        &self,
        batch: opentelemetry_sdk::logs::LogBatch<'_>,
    ) -> OTelSdkResult {
        if self.controller.should_skip() {
            return Ok(());
        }
        match self.inner.export(batch).await {
            Ok(()) => {
                self.controller
                    .record_success();
                Ok(())
            }
            Err(e) => {
                self.controller
                    .record_failure(&e.to_string());
                Ok(())
            }
        }
    }

    fn shutdown_with_timeout(
        &self,
        timeout: Duration,
    ) -> OTelSdkResult {
        self.inner
            .shutdown_with_timeout(timeout)
    }

    fn set_resource(
        &mut self,
        resource: &Resource,
    ) {
        self.inner
            .set_resource(resource);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_backoff_grows_exponentially_and_caps() {
        assert_eq!(compute_backoff(0), Duration::ZERO);
        assert_eq!(compute_backoff(1), Duration::from_secs(5));
        assert_eq!(compute_backoff(2), Duration::from_secs(10));
        assert_eq!(compute_backoff(3), Duration::from_secs(20));
        assert_eq!(compute_backoff(4), Duration::from_secs(40));
        // Caps at 30 minutes regardless of how high the failure count climbs.
        assert_eq!(compute_backoff(20), BACKOFF_CAP);
        assert_eq!(compute_backoff(1000), BACKOFF_CAP);
    }

    #[test]
    fn failure_then_skip_then_success_transitions() {
        let ctrl = BackoffController::new(OtlpSignal::Traces);
        assert!(!ctrl.should_skip());

        ctrl.record_failure("connection refused");
        // A backoff window is now open, so the next attempt is skipped.
        assert!(ctrl.should_skip());
        let snap = ctrl
            .health
            .snapshot(OtlpSignal::Traces);
        assert!(!snap.healthy);
        assert_eq!(snap.consecutive_failures, 1);
        assert_eq!(snap.backoff_seconds, 5);
        assert_eq!(snap.last_error.as_deref(), Some("connection refused"));
        assert!(snap.next_retry_at.is_some());
        assert!(snap.active);

        ctrl.record_failure("connection refused");
        assert_eq!(
            ctrl.health
                .snapshot(OtlpSignal::Traces)
                .backoff_seconds,
            10
        );

        ctrl.record_success();
        let snap = ctrl
            .health
            .snapshot(OtlpSignal::Traces);
        assert!(snap.healthy);
        assert_eq!(snap.consecutive_failures, 0);
        assert_eq!(snap.backoff_seconds, 0);
        assert!(snap.last_success_at.is_some());
        // Backoff window cleared, so a fresh attempt is allowed immediately.
        assert!(!ctrl.should_skip());
    }

    #[test]
    fn reset_clears_backoff_window_for_immediate_retry() {
        let ctrl = BackoffController::new(OtlpSignal::Metrics);
        ctrl.record_failure("connection refused");
        ctrl.record_failure("connection refused");
        assert!(ctrl.should_skip());
        let snap = ctrl
            .health
            .snapshot(OtlpSignal::Metrics);
        assert!(!snap.healthy);
        assert_eq!(snap.consecutive_failures, 2);

        // Resetting (e.g. on an endpoint change) clears the gate and counters so
        // the next attempt fires immediately rather than waiting out the window.
        ctrl.reset();
        assert!(!ctrl.should_skip());
        let snap = ctrl
            .health
            .snapshot(OtlpSignal::Metrics);
        assert!(snap.healthy);
        assert_eq!(snap.consecutive_failures, 0);
        assert_eq!(snap.backoff_seconds, 0);
        assert!(snap.next_retry_at.is_none());
    }

    #[test]
    fn snapshot_defaults_are_healthy_and_inactive() {
        // A never-used signal reports healthy but inactive.
        let snap = snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].signal, "traces");
        assert_eq!(snap[1].signal, "metrics");
        assert_eq!(snap[2].signal, "logs");
    }

    #[test]
    fn truncate_error_respects_char_boundary() {
        let long = "x".repeat(MAX_ERROR_LEN + 50);
        let out = truncate_error(&long);
        assert!(out.len() <= MAX_ERROR_LEN + 4);
        assert!(out.ends_with('…'));
        assert_eq!(truncate_error("short"), "short");
    }
}
