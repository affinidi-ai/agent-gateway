//! Append-only ledger of delegated payment gate calls: one record per call to
//! a connected agent-pay gateway, kept for `payment_ledger.retention_days` days
//! (7 unless configured).
//!
//! Rows are held in a bounded in-memory window that serves the API and are
//! written to append-only hourly segment files by a background worker; see
//! [`DelegatedPaymentStore`].

mod admin_api;
mod caller_api;
mod case_status;
pub mod settlement;
mod store;

pub use admin_api::{PaymentsLedgerApiState, create_payments_ledger_router};
pub use caller_api::{caller_case, init_case_status};
pub use case_status::{CaseStatusLookup, FabricCaseStatus};
pub use store::DelegatedPaymentStore;

use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

pub const DEFAULT_LIST_LIMIT: usize = 100;
pub const MAX_LIST_LIMIT: usize = 1000;

const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerOutcome {
    Paid,
    Challenge,
    Held,
    Rejected,
    /// Whether the payment was taken is not known: the caller was told to retry
    /// the same request with the same credential.
    Unconfirmed,
    Unavailable,
    /// Funds are held: captured once the Target delivered, voided otherwise.
    Authorized,
    /// A held payment was released without a charge.
    Voided,
    /// The Target delivered but capturing the held payment failed.
    CaptureFailed,
}

impl LedgerOutcome {
    /// Whether a row with this outcome records money moved or held, and is
    /// written to the disk before the request goes on.
    pub fn is_money(self) -> bool {
        matches!(self, Self::Paid | Self::Authorized | Self::CaptureFailed | Self::Unconfirmed | Self::Voided)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Paid => "paid",
            Self::Challenge => "challenge",
            Self::Held => "held",
            Self::Rejected => "rejected",
            Self::Unconfirmed => "unconfirmed",
            Self::Unavailable => "unavailable",
            Self::Authorized => "authorized",
            Self::Voided => "voided",
            Self::CaptureFailed => "capture_failed",
        }
    }
}

/// What the gateway decided to do with a held payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettleAction {
    Capture,
    Void,
}

impl SettleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Void => "void",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerRail {
    X402,
    Mpp,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PaymentLedgerRow {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub surface_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub payment_gateway_id: String,
    pub payment_surface_id: String,
    pub outcome: LedgerOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail: Option<LedgerRail>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vc_fingerprint: Option<String>,
    /// Why the payment was refused, failed or released, as [`ledger_reason`] keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// The amount agent-pay's receipt names differs from the manifest snapshot;
    /// `amount` and `currency` are then the receipt's.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub price_mismatch: bool,
    /// The manifest snapshot's price, kept when it differs from the charged one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quoted_currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// agent-pay's `payment-authorization` for funds held until delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_deadline: Option<DateTime<Utc>>,
    /// The capture or void decided for a held payment, written before it is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_intent: Option<SettleAction>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub settle_attempts: u32,
    /// How long one settle request waits for agent-pay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settle_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    /// A later row for the same idempotency key settled this payment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    /// The reconciler gave up on this row at its deadline.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reconcile_failed: bool,
    /// A peppered hash of the authenticated caller that made the paid request,
    /// the only caller its held case is shown to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_principal: Option<String>,
}

/// The most characters of a reason a ledger row keeps.
pub const MAX_REASON_CHARS: usize = 200;

/// The shortest run of token characters treated as a credential in a reason.
const MIN_SECRET_CHARS: usize = 32;

/// A refusal or failure reason fit for a ledger row: control characters
/// dropped, every word that looks like a credential (a JWT, or a long run of
/// base64 or hex) replaced with `[redacted]`, clipped to [`MAX_REASON_CHARS`].
pub fn ledger_reason(raw: &str) -> String {
    let looks_secret = |word: &str| {
        let token_chars = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '/' | '=');
        let token = word.trim_matches(|c: char| !token_chars(c));
        let jwt = token.split('.').count() == 3
            && token
                .split('.')
                .all(|part| !part.is_empty() && part.chars().all(token_chars))
            && token.len() >= 20;
        jwt || (token.len() >= MIN_SECRET_CHARS && token.chars().all(token_chars))
    };
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_control() {
                ' '
            } else {
                c
            }
        })
        .collect();
    let redacted = cleaned
        .split_whitespace()
        .map(|word| {
            if looks_secret(word) {
                "[redacted]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut clipped: String = redacted
        .chars()
        .take(MAX_REASON_CHARS)
        .collect();
    if redacted.chars().count() > MAX_REASON_CHARS {
        clipped.pop();
        clipped.push('…');
    }
    clipped
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl PaymentLedgerRow {
    /// A row for a gate call made now.
    pub fn new(
        surface_id: String,
        payment_gateway_id: String,
        payment_surface_id: String,
        outcome: LedgerOutcome,
    ) -> Self {
        Self {
            id: uuid::Uuid::now_v7().to_string(),
            created_at: Utc::now(),
            surface_id,
            variant: None,
            payment_gateway_id,
            payment_surface_id,
            outcome,
            rail: None,
            amount: None,
            currency: None,
            resource: None,
            case_id: None,
            receipt_reference: None,
            vc_fingerprint: None,
            reason: None,
            latency_ms: 0,
            remote_status: None,
            trace_id: None,
            price_mismatch: false,
            quoted_amount: None,
            quoted_currency: None,
            idempotency_key: None,
            authorization_id: None,
            capture_deadline: None,
            settle_intent: None,
            settle_attempts: 0,
            settle_timeout_ms: None,
            updated_at: None,
            superseded_by: None,
            reconcile_failed: false,
            caller_principal: None,
        }
    }
}

/// The persisted record: the API row plus the caller surface's tenant, which
/// scopes reads but is never part of the API row.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredLedgerRow {
    #[serde(flatten)]
    row: PaymentLedgerRow,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerFilter {
    pub surface_id: Option<String>,
    pub outcome: Option<LedgerOutcome>,
    pub limit: usize,
}

impl Default for LedgerFilter {
    fn default() -> Self {
        Self {
            surface_id: None,
            outcome: None,
            limit: DEFAULT_LIST_LIMIT,
        }
    }
}

impl LedgerFilter {
    fn matches(
        &self,
        row: &PaymentLedgerRow,
    ) -> bool {
        self.surface_id
            .as_deref()
            .is_none_or(|surface_id| row.surface_id == surface_id)
            && self
                .outcome
                .is_none_or(|outcome| row.outcome == outcome)
    }
}

/// Writes the rows recorded since the last pass every second and removes
/// whole segments older than `retention_days` at startup and then hourly.
pub fn spawn_background_workers(
    store: Arc<DelegatedPaymentStore>,
    retention_days: u32,
) {
    spawn_workers(store, retention_days, FLUSH_INTERVAL, CLEANUP_INTERVAL);
}

fn spawn_workers(
    store: Arc<DelegatedPaymentStore>,
    retention_days: u32,
    flush_every: std::time::Duration,
    cleanup_every: std::time::Duration,
) {
    tokio::spawn(async move {
        let mut flush = tokio::time::interval(flush_every);
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut cleanup = tokio::time::interval(cleanup_every);
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = flush.tick() => store.flush().await,
                _ = cleanup.tick() => {
                    let removed = store
                        .cleanup_older_than(Duration::days(i64::from(retention_days)))
                        .await;
                    if removed > 0 {
                        info!("[payments-ledger] Removed {} segment(s) older than {} days", removed, retention_days);
                    }
                }
            }
        }
    });
}

static GLOBAL_STORE: OnceLock<Arc<DelegatedPaymentStore>> = OnceLock::new();

/// Process-global handle so the payment gate (HTTP and fabric paths) can record without threading state.
pub fn init_global(store: Arc<DelegatedPaymentStore>) {
    if GLOBAL_STORE
        .set(store)
        .is_err()
    {
        warn!("[payments-ledger] Global ledger store was already initialised");
    }
}

pub fn global() -> Option<Arc<DelegatedPaymentStore>> {
    GLOBAL_STORE.get().cloned()
}

/// Records a row in the global store, when it is initialised. A row that
/// records money ([`LedgerOutcome::is_money`]) is on the disk when this
/// returns; any other is written by the background worker.
pub async fn record(
    row: PaymentLedgerRow,
    tenant_id: Option<String>,
) {
    let Some(store) = global() else {
        return;
    };
    let recorded = if row.outcome.is_money() {
        store
            .record_durable(row, tenant_id)
            .await
    } else {
        store.record(row, tenant_id)
    };
    if let Err(e) = recorded {
        warn!(error = %e, "[payments-ledger] Failed to record delegated payment");
    }
}

/// Writes what the global store still holds in memory, before the process ends.
pub async fn flush_global() {
    if let Some(store) = global() {
        store.flush().await;
    }
}

/// The most a termination signal waits for the ledger to reach the disk.
const TERMINATION_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A signal that ends the process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Termination {
    Interrupt,
    Terminate,
}

impl Termination {
    /// The status a shell reports for a process the signal ended: 128 plus the
    /// signal number.
    fn exit_status(self) -> i32 {
        match self {
            Self::Interrupt => 130,
            Self::Terminate => 143,
        }
    }
}

/// Waits for the first termination signal.
#[cfg(unix)]
fn termination_signal() -> Option<impl std::future::Future<Output = Termination>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt()).ok()?;
    let mut terminate = signal(SignalKind::terminate()).ok()?;
    Some(async move {
        tokio::select! {
            _ = interrupt.recv() => Termination::Interrupt,
            _ = terminate.recv() => Termination::Terminate,
        }
    })
}

#[cfg(not(unix))]
fn termination_signal() -> Option<impl std::future::Future<Output = Termination>> {
    Some(async {
        let _ = tokio::signal::ctrl_c().await;
        Termination::Interrupt
    })
}

/// Waits for `signal`, gives `store` up to `limit` to write what it still holds,
/// then hands the signal's conventional exit status to `exit`.
async fn flush_when_terminated(
    signal: impl std::future::Future<Output = Termination>,
    store: Option<Arc<DelegatedPaymentStore>>,
    limit: std::time::Duration,
    exit: impl FnOnce(i32),
) {
    let termination = signal.await;
    if let Some(store) = store
        && tokio::time::timeout(limit, store.flush())
            .await
            .is_err()
    {
        warn!("[payments-ledger] The ledger did not reach the disk within {limit:?} of {termination:?}");
    }
    exit(termination.exit_status());
}

/// Writes what the global store still holds when the process is interrupted or
/// terminated, then ends it with the status that signal would have given it.
/// Taking over those signals from the operating system's default is why the
/// process must end here itself. Only the real binary listens: a test process
/// would otherwise stop obeying them.
#[cfg_attr(test, allow(dead_code, reason = "only the real binary listens for termination signals"))]
pub fn spawn_termination_flush() {
    static SPAWNED: std::sync::Once = std::sync::Once::new();
    SPAWNED.call_once(|| {
        let Some(signal) = termination_signal() else {
            warn!(
                "[payments-ledger] Could not listen for termination signals; the ledger is flushed on a clean exit only"
            );
            return;
        };
        tokio::spawn(flush_when_terminated(signal, global(), TERMINATION_FLUSH_TIMEOUT, |status| {
            std::process::exit(status)
        }));
    });
}

/// Rebuilds the global store's window from disk when this node becomes Active.
pub async fn reload_global() {
    if let Some(store) = global() {
        store.reload_from_disk().await;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A row recorded `age` ago. Its id is time-ordered, like a recorded row's.
    pub(crate) fn row(
        surface_id: &str,
        outcome: LedgerOutcome,
        age: Duration,
    ) -> PaymentLedgerRow {
        row_at(surface_id, outcome, Utc::now() - age)
    }

    /// A row created `seconds` after the middle of the previous hour, so the rows
    /// of one test share a segment whatever time of day it runs.
    pub(crate) fn row_in_one_segment(
        surface_id: &str,
        outcome: LedgerOutcome,
        seconds: i64,
    ) -> PaymentLedgerRow {
        let now = Utc::now();
        let previous_hour_midpoint =
            now - Duration::seconds(
                now.timestamp()
                    .rem_euclid(3600),
            ) - Duration::minutes(30);
        row_at(surface_id, outcome, previous_hour_midpoint + Duration::seconds(seconds))
    }

    fn row_at(
        surface_id: &str,
        outcome: LedgerOutcome,
        created_at: DateTime<Utc>,
    ) -> PaymentLedgerRow {
        PaymentLedgerRow {
            id: uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
                uuid::NoContext,
                created_at
                    .timestamp()
                    .unsigned_abs(),
                created_at.timestamp_subsec_nanos(),
            ))
            .to_string(),
            created_at,
            surface_id: surface_id.to_string(),
            variant: None,
            payment_gateway_id: "gw-pay".to_string(),
            payment_surface_id: "ps-1".to_string(),
            outcome,
            rail: None,
            amount: None,
            currency: None,
            resource: None,
            case_id: None,
            receipt_reference: None,
            vc_fingerprint: None,
            latency_ms: 12,
            remote_status: None,
            trace_id: None,
            ..PaymentLedgerRow::new(String::new(), String::new(), String::new(), outcome)
        }
    }

    pub(crate) async fn store() -> (DelegatedPaymentStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("payments-ledger-test-{}", uuid::Uuid::new_v4()));
        (
            DelegatedPaymentStore::new(dir.clone())
                .await
                .unwrap(),
            dir,
        )
    }

    pub(crate) fn all(
        _: Option<&str>,
        _: &str,
    ) -> bool {
        true
    }

    pub(crate) fn ids(rows: &[PaymentLedgerRow]) -> Vec<&str> {
        rows.iter()
            .map(|r| r.id.as_str())
            .collect()
    }

    #[tokio::test]
    async fn a_termination_signal_flushes_the_ledger_and_exits_with_its_conventional_status() {
        for (termination, status) in [(Termination::Interrupt, 130), (Termination::Terminate, 143)] {
            let (store, dir) = store().await;
            let recorded = row("s-1", LedgerOutcome::Paid, Duration::zero());
            store
                .record(recorded.clone(), None)
                .unwrap();
            let exited = std::sync::Mutex::new(None);

            flush_when_terminated(
                std::future::ready(termination),
                Some(Arc::new(store)),
                std::time::Duration::from_secs(5),
                |status| *exited.lock().unwrap() = Some(status),
            )
            .await;

            assert_eq!(*exited.lock().unwrap(), Some(status), "{termination:?}");
            let reopened = DelegatedPaymentStore::new(dir.clone())
                .await
                .unwrap();
            assert_eq!(
                reopened
                    .get(&recorded.id)
                    .await,
                Some((recorded, None)),
                "{termination:?}: written to disk"
            );
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[tokio::test]
    async fn a_termination_signal_without_a_ledger_still_exits_and_waits_for_the_signal() {
        let (signal, arrived) = tokio::sync::oneshot::channel();
        let exited = Arc::new(std::sync::Mutex::new(None));
        let task = tokio::spawn({
            let exited = exited.clone();
            flush_when_terminated(
                async move {
                    arrived
                        .await
                        .unwrap_or(Termination::Terminate)
                },
                None,
                std::time::Duration::from_secs(5),
                move |status| *exited.lock().unwrap() = Some(status),
            )
        });
        tokio::task::yield_now().await;
        assert_eq!(*exited.lock().unwrap(), None, "nothing happens before a signal");
        signal
            .send(Termination::Interrupt)
            .unwrap();
        task.await.unwrap();
        assert_eq!(*exited.lock().unwrap(), Some(130));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_signal_listener_registers_for_interrupt_and_terminate() {
        assert!(termination_signal().is_some());
        assert_eq!(Termination::Interrupt.exit_status(), 130);
        assert_eq!(Termination::Terminate.exit_status(), 143);
    }

    #[tokio::test]
    async fn the_background_worker_writes_recorded_rows_and_removes_expired_segments() {
        let (store, dir) = store().await;
        let store = Arc::new(store);
        let expired = row(
            "s-1",
            LedgerOutcome::Paid,
            Duration::days(i64::from(crate::config::types::PaymentLedgerConfig::DEFAULT_RETENTION_DAYS) + 1),
        );
        store
            .record(expired.clone(), None)
            .unwrap();
        store.flush().await;
        let fresh = row("s-1", LedgerOutcome::Paid, Duration::zero());
        store
            .record(fresh.clone(), None)
            .unwrap();
        spawn_workers(
            store.clone(),
            crate::config::types::PaymentLedgerConfig::DEFAULT_RETENTION_DAYS,
            std::time::Duration::from_millis(20),
            std::time::Duration::from_millis(20),
        );

        let segments = || {
            std::fs::read_dir(&dir)
                .unwrap()
                .count()
        };
        for _ in 0..200 {
            if segments() == 1
                && store
                    .get(&expired.id)
                    .await
                    .is_none()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(segments(), 1, "the fresh row was written and the expired segment removed");
        assert_eq!(store.get(&expired.id).await, None);
        assert_eq!(store.get(&fresh.id).await, Some((fresh, None)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_window_never_holds_more_than_its_bound() {
        let (store, dir) = store().await;
        let newest: Vec<_> = (0..50_010)
            .map(|i| row("s-1", LedgerOutcome::Challenge, Duration::milliseconds(60_000 - i)))
            .collect();
        for r in &newest {
            store
                .record(r.clone(), None)
                .unwrap();
        }
        let (listed, total) = store.list(
            &LedgerFilter {
                limit: MAX_LIST_LIMIT,
                ..LedgerFilter::default()
            },
            all,
        );
        assert_eq!(total, 50_000);
        assert_eq!(listed.len(), MAX_LIST_LIMIT);
        assert_eq!(listed[0].id, newest[50_009].id, "newest first");
        assert_eq!(
            store.get(&newest[0].id).await,
            None,
            "the oldest rows left the window and, unwritten, are gone from memory"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_reason_is_clipped_and_never_carries_a_credential() {
        assert_eq!(ledger_reason("insufficient_funds: card declined"), "insufficient_funds: card declined");
        assert_eq!(
            ledger_reason("bad credential eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl\nretry"),
            "bad credential [redacted] retry"
        );
        assert_eq!(ledger_reason("token=0123456789abcdef0123456789abcdef0123 refused"), "[redacted] refused");
        assert_eq!(ledger_reason("key 0123456789abcdef0123456789abcdef0123."), "key [redacted]");
        let long = "x ".repeat(300);
        let clipped = ledger_reason(&long);
        assert_eq!(clipped.chars().count(), MAX_REASON_CHARS);
        assert!(clipped.ends_with('…'));
        assert_eq!(ledger_reason(""), "");
    }

    #[test]
    fn the_stored_record_carries_the_tenant_beside_the_row_fields() {
        let paid = row("s-1", LedgerOutcome::Paid, Duration::zero());
        let stored = serde_json::to_value(StoredLedgerRow {
            row: paid.clone(),
            tenant_id: Some("tenant-a".to_string()),
        })
        .unwrap();
        assert_eq!(stored["tenant_id"], "tenant-a");
        assert_eq!(stored["outcome"], "paid");
        assert_eq!(
            stored["created_at"],
            paid.created_at
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
        );

        let operator = serde_json::to_value(StoredLedgerRow { row: paid, tenant_id: None }).unwrap();
        assert!(
            operator
                .get("tenant_id")
                .is_none()
        );
    }
}
