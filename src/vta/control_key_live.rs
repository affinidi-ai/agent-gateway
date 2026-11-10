//! Rotating the bundled trust agent's control key while the gateway runs, on a
//! schedule or on request.
//!
//! The running gateway registers its shared trust agent client here once the
//! signing backend is built. Everything that rotates (the schedule, the admin
//! API) goes through [`rotate_now`], so the checks, the recording and the audit
//! events cannot differ between them.

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Once, RwLock};

use chrono::{DateTime, Utc};

use super::bundled::BootstrapState;
use super::client::VtaRestClient;
use super::control_key_schedule::{self, Decision, Schedule};
use super::control_rotation::{self, RotateLiveError};
use super::error::VtaError;
use crate::config::vta::VtaConfig;

/// What the gateway needs to rotate: the running client, the `[vta]` block as
/// it stands after the bootstrap, and where the key material is kept.
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

/// Remember the bundled client for later rotations, replacing an earlier one
/// (a process that builds more than one gateway, as the tests do, rotates the
/// latest).
pub fn register(
    client: Arc<VtaRestClient>,
    config: VtaConfig,
    storage: PathBuf,
) {
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
    /// This gateway runs no bundled trust agent.
    NotBundled,
    /// The bundled agent is not connected; carries what it is doing instead.
    NotConnected(&'static str),
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
    state: Option<BootstrapState>,
) -> Result<(), RotateNowError> {
    let state = state.ok_or(RotateNowError::NotBundled)?;
    if standby {
        return Err(RotateNowError::Standby);
    }
    if state != BootstrapState::Connected {
        return Err(RotateNowError::NotConnected(state.label()));
    }
    Ok(())
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
        .ok_or(RotateNowError::NotBundled)?;
    let key_path = super::appliance_control_key_path(&live.storage);
    let rotated = control_rotation::rotate_live(&live.client, &live.config, vta_did, &key_path)
        .await
        .map_err(|e| match e {
            RotateLiveError::InProgress => RotateNowError::InProgress,
            RotateLiveError::Failed(e) => RotateNowError::Failed(e),
        })?;
    let now = Utc::now();
    if let Err(e) =
        super::bundled::record_rotation(&live.storage, std::path::Path::new(&live.config.bootstrap_dir), &rotated, now)
            .await
    {
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
        "the gateway's control key on the bundled trust agent was rotated",
    );
    let next = super::bundled::status().and_then(|s| s.control_key_next_rotation_at);
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
    precondition(crate::server::mode::is_standby(), super::bundled::status().map(|s| s.state))?;
    let live = live().ok_or(RotateNowError::NotBundled)?;
    if trigger == Trigger::Api
        && let Some(seconds) =
            seconds_until_allowed(super::bundled::status().and_then(|s| s.control_key_rotated_at), Utc::now())
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
        RotateNowError::NotBundled => "no bundled trust agent".to_string(),
        RotateNowError::NotConnected(state) => format!("the bundled trust agent is {state}"),
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
/// only while the bundled agent is connected, an hour apart at most.
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
        let status = super::bundled::status();
        let connected = status
            .as_ref()
            .is_some_and(|s| s.state == BootstrapState::Connected);
        let due = status
            .as_ref()
            .and_then(|s| s.control_key_next_rotation_at);
        let jitter = status
            .as_ref()
            .and_then(|s| s.control_did.as_deref())
            .map(control_key_schedule::jitter)
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

    #[test]
    fn a_gateway_with_no_bundled_agent_cannot_rotate() {
        assert!(matches!(precondition(false, None), Err(RotateNowError::NotBundled)));
    }

    #[test]
    fn a_standby_gateway_cannot_rotate() {
        assert!(matches!(precondition(true, Some(BootstrapState::Connected)), Err(RotateNowError::Standby)));
    }

    #[test]
    fn an_agent_that_is_not_connected_names_what_it_is_doing() {
        let err = precondition(false, Some(BootstrapState::WaitingForVta)).expect_err("not connected");
        assert!(matches!(err, RotateNowError::NotConnected(state) if state == BootstrapState::WaitingForVta.label()));
    }

    #[test]
    fn a_connected_active_gateway_may_rotate() {
        assert!(precondition(false, Some(BootstrapState::Connected)).is_ok());
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
