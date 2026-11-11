//! Rotating the control key the gateway holds for its `[vta]` trust agent while
//! it runs, on a schedule or on request.
//!
//! The running gateway registers its shared trust agent client here once the
//! signing backend is built. Everything that rotates (the schedule, the admin
//! API) goes through [`rotate_now`], so the checks, the recording and the audit
//! events cannot differ between them.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::client::VtaRestClient;
use super::control_key_schedule::{self, Decision, Schedule};
use super::control_rotation::{self, RotateLiveError};
use super::error::VtaError;
use crate::config::vta::VtaConfig;

/// Where the rotation record is kept, beside the control key.
pub const RECORD_FILE: &str = "vta_control_key_rotation.json";

/// When the gateway began holding its control key and when it last moved to a
/// new one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    since: DateTime<Utc>,
    #[serde(default)]
    rotated_at: Option<DateTime<Utc>>,
}

fn record_path(storage: &Path) -> PathBuf {
    storage.join(RECORD_FILE)
}

async fn load_record(storage: &Path) -> Option<Record> {
    let text = crate::encryption::secret_file::read_secret_file(&record_path(storage))
        .await
        .ok()??;
    serde_json::from_str(&text).ok()
}

async fn save_record(
    storage: &Path,
    record: &Record,
) -> Result<(), String> {
    let text =
        serde_json::to_string_pretty(record).map_err(|e| format!("could not encode the rotation record: {e}"))?;
    crate::encryption::secret_file::write_secret_file(&record_path(storage), &text)
        .await
        .map_err(|e| format!("could not persist the rotation record: {e}"))
}

/// What the status API reports about the control key the gateway rotates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlKeyStatus {
    pub control_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<DateTime<Utc>>,
    /// Absent when automatic rotation is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_rotation_at: Option<DateTime<Utc>>,
    /// Days between automatic rotations; `0` is off.
    pub rotation_days: u32,
}

fn status_for(
    record: &Record,
    config: &VtaConfig,
    control_did: String,
) -> ControlKeyStatus {
    ControlKeyStatus {
        control_did,
        rotated_at: record.rotated_at,
        next_rotation_at: control_key_schedule::next_due(
            record.rotated_at,
            record.since,
            config.control_key_rotation_days,
        ),
        rotation_days: config.control_key_rotation_days,
    }
}

static STATUS: RwLock<Option<ControlKeyStatus>> = RwLock::new(None);

/// The control key's status, when this gateway holds one it can rotate.
pub fn status() -> Option<ControlKeyStatus> {
    STATUS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn set_status(status: Option<ControlKeyStatus>) {
    *STATUS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = status;
}

/// What the gateway needs to rotate: the running client, the `[vta]` block, and
/// where the key material is kept.
pub struct Live {
    client: Arc<VtaRestClient>,
    config: VtaConfig,
    storage: PathBuf,
}

static LIVE: RwLock<Option<Arc<Live>>> = RwLock::new(None);

fn live() -> Option<Arc<Live>> {
    LIVE.read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Remember the client for later rotations, replacing an earlier one (a process
/// that builds more than one gateway, as the tests do, rotates the latest), and
/// publish the control key's status.
pub async fn register(
    client: Arc<VtaRestClient>,
    config: VtaConfig,
    storage: PathBuf,
) {
    let record = match load_record(&storage).await {
        Some(record) => record,
        None => {
            let record = Record {
                since: Utc::now(),
                rotated_at: None,
            };
            if let Err(e) = save_record(&storage, &record).await {
                tracing::warn!(target: "vta_audit", "{e}");
            }
            record
        }
    };
    set_status(Some(status_for(&record, &config, client.control_did())));
    *LIVE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(Live { client, config, storage }));
}

/// The shortest time between two rotations asked for by a person.
pub const MIN_MANUAL_INTERVAL: chrono::Duration = chrono::Duration::minutes(10);

/// Seconds left before another rotation may be asked for, if it is too soon.
pub fn seconds_until_allowed(
    last_rotated_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Option<u64> {
    let allowed_at = last_rotated_at? + MIN_MANUAL_INTERVAL;
    (now < allowed_at).then(|| {
        (allowed_at - now)
            .num_seconds()
            .max(1) as u64
    })
}

/// What started a rotation, for the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Schedule,
    Api,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Schedule => "schedule",
            Self::Api => "api",
        }
    }
}

/// Why a rotation was not done.
#[derive(Debug)]
pub enum RotateNowError {
    /// This gateway holds no control key it can rotate.
    NotConfigured,
    /// A standby gateway never rotates: the active one owns the key.
    Standby,
    /// Another rotation is running.
    InProgress,
    /// A rotation was asked for too soon after the last one; the seconds to wait.
    TooSoon(u64),
    Failed(VtaError),
}

/// A finished rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub previous_control_did: String,
    pub control_did: String,
    pub rotated_at: DateTime<Utc>,
    pub next_rotation_at: Option<DateTime<Utc>>,
}

/// Whether a rotation may start now.
pub fn precondition(
    standby: bool,
    configured: bool,
) -> Result<(), RotateNowError> {
    if !configured {
        return Err(RotateNowError::NotConfigured);
    }
    if standby {
        return Err(RotateNowError::Standby);
    }
    Ok(())
}

/// Record a finished rotation: the rotation record, the onboarding record and
/// the published status.
///
/// Only the gateway's access entry moved; the signing key and everything else
/// the trust agent holds are untouched.
async fn record_rotation(
    storage: &Path,
    config: &VtaConfig,
    rotated: &control_rotation::Rotated,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let mut record = load_record(storage)
        .await
        .unwrap_or(Record { since: now, rotated_at: None });
    record.rotated_at = Some(now);
    set_status(Some(status_for(&record, config, rotated.new_did.clone())));

    // Written before the client signs in as the new DID, so the onboarding check
    // finds the record already current instead of flagging an off-schedule change.
    let onboarding_path = storage.join(super::onboarding::ONBOARDING_RECORD_FILE);
    if let Ok(Some(mut onboarding)) = super::onboarding::OnboardingRecord::load(&onboarding_path).await {
        onboarding.control_did = rotated.new_did.clone();
        onboarding.granted_at = now;
        if let Err(e) = onboarding
            .save(&onboarding_path)
            .await
        {
            tracing::warn!(target: "vta_audit", "could not update the onboarding record: {}", e.log_detail());
        }
    }
    save_record(storage, &record).await
}

async fn perform(
    live: &Live,
    trigger: Trigger,
    user: Option<&str>,
) -> Result<Report, RotateNowError> {
    let vta_did = live
        .config
        .vta_did
        .as_deref()
        .ok_or(RotateNowError::NotConfigured)?;
    let key_path = super::rotatable_control_key_path(&live.config).ok_or(RotateNowError::NotConfigured)?;
    let rotated = control_rotation::rotate_live(&live.client, &live.config, vta_did, &key_path)
        .await
        .map_err(|e| match e {
            RotateLiveError::InProgress => RotateNowError::InProgress,
            RotateLiveError::Failed(e) => RotateNowError::Failed(e),
        })?;
    let now = Utc::now();
    if let Err(e) = record_rotation(&live.storage, &live.config, &rotated, now).await {
        tracing::error!(
            target: "vta_audit",
            event = "vta_control_key_record_failed",
            error = %e,
            "the control key was rotated but the record of it could not be written; the next start repairs it",
        );
    }
    tracing::info!(
        target: "vta_audit",
        event = "vta_control_key_rotated",
        previous_control_did = %rotated.previous_did,
        control_did = %rotated.new_did,
        trigger = trigger.as_str(),
        user_id = user.unwrap_or(""),
        "the gateway's control key on its trust agent was rotated",
    );
    let next = status().and_then(|s| s.next_rotation_at);
    Ok(Report {
        previous_control_did: rotated.previous_did,
        control_did: rotated.new_did,
        rotated_at: now,
        next_rotation_at: next,
    })
}

/// Rotate the control key now.
pub async fn rotate_now(
    trigger: Trigger,
    user: Option<&str>,
) -> Result<Report, RotateNowError> {
    let live = live();
    precondition(crate::server::mode::is_standby(), live.is_some())?;
    let live = live.ok_or(RotateNowError::NotConfigured)?;
    if trigger == Trigger::Api
        && let Some(seconds) = seconds_until_allowed(status().and_then(|s| s.rotated_at), Utc::now())
    {
        return Err(RotateNowError::TooSoon(seconds));
    }
    let result = perform(&live, trigger, user).await;
    if let Err(e) = &result {
        tracing::warn!(
            target: "vta_audit",
            event = "vta_control_key_rotation_failed",
            trigger = trigger.as_str(),
            reason = %describe(e),
            "the control key was not rotated; the current key keeps working",
        );
    }
    result
}

fn describe(error: &RotateNowError) -> String {
    match error {
        RotateNowError::NotConfigured => "no control key this gateway can rotate".to_string(),
        RotateNowError::Standby => "this gateway is on standby".to_string(),
        RotateNowError::InProgress => "another rotation is running".to_string(),
        RotateNowError::TooSoon(seconds) => format!("the last rotation was too recent; retry in {seconds}s"),
        RotateNowError::Failed(e) => e.to_string(),
    }
}

/// One look at the schedule: rotate if it says so, and remember how it went.
pub async fn tick<F, Fut>(
    schedule: &mut Schedule,
    now: DateTime<Utc>,
    due: Option<DateTime<Utc>>,
    jitter: std::time::Duration,
    standby: bool,
    connected: bool,
    rotate: F,
) -> Decision
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Report, RotateNowError>>,
{
    let decision = schedule.decide(now, due, jitter, standby, connected);
    if decision != Decision::Rotate {
        return decision;
    }
    match rotate().await {
        Ok(_) => schedule.succeeded(),
        Err(e) => {
            let failures = schedule.failed(now);
            let reason = describe(&e);
            if failures >= control_key_schedule::ESCALATE_AFTER_FAILURES {
                tracing::error!(
                    target: "vta_audit",
                    event = "vta_control_key_rotation_failing",
                    failures,
                    reason = %reason,
                    "the scheduled control-key rotation keeps failing; the current key still works",
                );
            }
        }
    }
    decision
}

/// Start the background schedule. Rotation runs only on the active gateway and
/// only when `control_key_rotation_days` is set, checked an hour apart.
pub fn spawn_schedule() {
    static STARTED: Once = Once::new();
    if live().is_none() {
        return;
    }
    STARTED.call_once(|| {
        tokio::spawn(schedule_loop());
    });
}

async fn schedule_loop() {
    let mut schedule = Schedule::default();
    let mut modes = crate::server::mode::subscribe_mode_changes();
    let mut wait = std::time::Duration::from_secs(60);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = modes.recv() => {}
        }
        wait = std::time::Duration::from_secs(3600);
        let current = status();
        let connected = current.is_some();
        let due = current
            .as_ref()
            .and_then(|s| s.next_rotation_at);
        let jitter = current
            .as_ref()
            .map(|s| control_key_schedule::jitter(&s.control_did))
            .unwrap_or_default();
        tick(&mut schedule, Utc::now(), due, jitter, crate::server::mode::is_standby(), connected, || {
            rotate_now(Trigger::Schedule, None)
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn at(day: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap() + chrono::Duration::days(day)
    }

    fn report() -> Report {
        Report {
            previous_control_did: "did:key:z6MkOld".to_string(),
            control_did: "did:key:z6MkNew".to_string(),
            rotated_at: at(90),
            next_rotation_at: Some(at(180)),
        }
    }

    #[test]
    fn a_manual_rotation_is_refused_for_ten_minutes_after_the_last() {
        let last = Some(at(5));
        assert_eq!(seconds_until_allowed(last, at(5) + chrono::Duration::minutes(4)), Some(360));
        assert_eq!(seconds_until_allowed(last, at(5) + chrono::Duration::minutes(10)), None);
        assert_eq!(seconds_until_allowed(None, at(5)), None, "never rotated is never too soon");
    }

    fn config_with_days(days: u32) -> VtaConfig {
        VtaConfig {
            control_key_rotation_days: days,
            ..VtaConfig::default()
        }
    }

    #[test]
    fn the_status_counts_the_next_rotation_from_the_last_one_or_else_from_when_the_key_was_first_held() {
        let never = Record { since: at(0), rotated_at: None };
        let status = status_for(&never, &config_with_days(30), "did:key:z6MkA".to_string());
        assert_eq!(status.control_did, "did:key:z6MkA");
        assert_eq!(status.rotated_at, None);
        assert_eq!(status.next_rotation_at, Some(at(30)));
        assert_eq!(status.rotation_days, 30);

        let rotated = Record {
            since: at(0),
            rotated_at: Some(at(10)),
        };
        assert_eq!(
            status_for(&rotated, &config_with_days(30), "did:key:z6MkB".to_string()).next_rotation_at,
            Some(at(40))
        );
    }

    #[test]
    fn with_automatic_rotation_off_the_status_names_no_next_rotation() {
        let record = Record {
            since: at(0),
            rotated_at: Some(at(10)),
        };
        let status = status_for(&record, &config_with_days(0), "did:key:z6MkA".to_string());
        assert_eq!(status.next_rotation_at, None);
        assert_eq!(status.rotation_days, 0);
        assert_eq!(status.rotated_at, Some(at(10)));
    }

    #[tokio::test]
    async fn a_recorded_rotation_is_kept_beside_the_key_and_keeps_when_the_key_was_first_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        save_record(dir.path(), &Record { since: at(1), rotated_at: None })
            .await
            .expect("save");
        let rotated = control_rotation::Rotated {
            previous_did: "did:key:z6MkOld".to_string(),
            new_did: "did:key:z6MkNew".to_string(),
        };

        record_rotation(dir.path(), &config_with_days(30), &rotated, at(20))
            .await
            .expect("record");

        let record = load_record(dir.path())
            .await
            .expect("a record");
        assert_eq!(
            record,
            Record {
                since: at(1),
                rotated_at: Some(at(20))
            }
        );
    }

    #[tokio::test]
    async fn a_missing_record_reads_as_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(load_record(dir.path()).await, None);
    }

    #[test]
    fn a_gateway_with_no_rotatable_control_key_cannot_rotate() {
        assert!(matches!(precondition(false, false), Err(RotateNowError::NotConfigured)));
    }

    #[test]
    fn a_standby_gateway_cannot_rotate() {
        assert!(matches!(precondition(true, true), Err(RotateNowError::Standby)));
    }

    #[test]
    fn an_active_gateway_with_a_rotatable_control_key_may_rotate() {
        assert!(precondition(false, true).is_ok());
    }

    #[tokio::test]
    async fn a_due_tick_rotates_and_a_success_clears_the_schedule() {
        let mut schedule = Schedule::default();
        let calls = AtomicUsize::new(0);

        let decision = tick(&mut schedule, at(100), Some(at(90)), std::time::Duration::ZERO, false, true, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(report())
        })
        .await;

        assert_eq!(decision, Decision::Rotate);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_tick_that_is_not_due_standby_or_unconnected_rotates_nothing() {
        let calls = AtomicUsize::new(0);
        let rotate = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(report())
        };
        let mut schedule = Schedule::default();
        let zero = std::time::Duration::ZERO;

        assert_eq!(tick(&mut schedule, at(10), Some(at(90)), zero, false, true, rotate).await, Decision::NotYet);
        assert_eq!(tick(&mut schedule, at(100), Some(at(90)), zero, true, true, rotate).await, Decision::Standby);
        assert_eq!(
            tick(&mut schedule, at(100), Some(at(90)), zero, false, false, rotate).await,
            Decision::NotConnected
        );
        assert_eq!(tick(&mut schedule, at(100), None, zero, false, true, rotate).await, Decision::Off);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_failed_rotation_is_not_tried_again_until_the_backoff_has_passed() {
        let mut schedule = Schedule::default();
        let calls = AtomicUsize::new(0);
        let zero = std::time::Duration::ZERO;
        let failing = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(RotateNowError::Failed(VtaError::Transport("down".to_string())))
        };

        tick(&mut schedule, at(100), Some(at(90)), zero, false, true, failing).await;
        let soon = at(100) + chrono::Duration::minutes(30);
        let again = tick(&mut schedule, soon, Some(at(90)), zero, false, true, failing).await;
        let later = at(100) + chrono::Duration::hours(1);
        tick(&mut schedule, later, Some(at(90)), zero, false, true, failing).await;

        assert_eq!(again, Decision::NotYet, "the failure holds the next attempt back");
        assert_eq!(calls.load(Ordering::SeqCst), 2, "one try, none within the hour, one after it");
    }
}
