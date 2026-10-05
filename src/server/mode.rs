use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServerMode {
    #[default]
    Active,
    Standby,
}

/// A mode transition, carrying the activation generation assigned to it. The
/// generation lets a consumer (e.g. the orchestrator's mode task) pass the exact
/// window it observed to [`mark_activation_ready`], so a readiness mark that lost
/// its race against a newer transition is ignored rather than promoting a stale
/// activation to health-ready.
#[derive(Debug, Clone, Copy)]
pub struct ModeChange {
    pub mode: ServerMode,
    pub generation: u64,
}

// Serve-state machine gating the externally mounted `/api/v1/health` readiness endpoint. A single atomic packs the
// activation *generation* in the high 62 bits and the serve *state* in the low 2
// bits, so a reader never observes a torn combination of "active", "ready", and a
// generation: becoming active enters `ACTIVATING` (active, but the config/policy
// re-derive has not finished, so health stays 503), and `mark_activation_ready`
// promotes it to `ACTIVE` only once that re-derive completes. Every transition
// bumps the generation, so a `mark_activation_ready` carrying a stale generation
// (its activation window was superseded by a step-down + re-promote) is a no-op
// and health never flips ready for the wrong window. SeqCst gives a single total
// order across every transition and the health read.
const STATE_MASK: u64 = 0b11;
const STATE_STANDBY: u64 = 0;
const STATE_ACTIVATING: u64 = 1;
const STATE_ACTIVE: u64 = 2;
static SERVE_STATE: AtomicU64 = AtomicU64::new(STATE_ACTIVE);
static MODE_CHANGE_TX: OnceLock<broadcast::Sender<ModeChange>> = OnceLock::new();

#[inline]
fn pack(
    generation: u64,
    state: u64,
) -> u64 {
    (generation << 2) | state
}

#[inline]
fn unpack_state(packed: u64) -> u64 {
    packed & STATE_MASK
}

#[inline]
fn unpack_generation(packed: u64) -> u64 {
    packed >> 2
}
#[cfg(unix)]
static PENDING_SIGNAL_HANDLES: std::sync::Mutex<Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>> =
    std::sync::Mutex::new(None);

fn mode_change_tx() -> &'static broadcast::Sender<ModeChange> {
    MODE_CHANGE_TX.get_or_init(|| broadcast::channel::<ModeChange>(16).0)
}

/// Subscribe to server mode transitions. Receivers see every Active/Standby change
/// together with the activation generation assigned to it.
pub fn subscribe_mode_changes() -> broadcast::Receiver<ModeChange> {
    mode_change_tx().subscribe()
}

pub fn set_server_mode(mode: ServerMode) {
    // Becoming active starts an activation window: the node is not health-ready until
    // `mark_activation_ready` runs after the startup/promotion config+policy re-derive.
    let state = match mode {
        ServerMode::Active => STATE_ACTIVATING,
        ServerMode::Standby => STATE_STANDBY,
    };
    // Bump the generation on *every* transition so a later readiness mark can be matched
    // to the exact activation window it was issued for (see `mark_activation_ready`).
    let previous = SERVE_STATE
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |packed| {
            Some(pack(unpack_generation(packed).wrapping_add(1), state))
        })
        .expect("fetch_update closure always returns Some");
    let generation = unpack_generation(previous).wrapping_add(1);
    let _ = mode_change_tx().send(ModeChange { mode, generation });
}

/// Promote an in-progress activation to fully ready once the config/policy re-derive
/// has completed, so `/api/v1/health` may report 200. Only advances `ACTIVATING → ACTIVE`
/// for the activation identified by `observed_generation`: a concurrent step-down to
/// standby, or a step-down + re-promote that superseded this window, leaves the CAS to
/// fail and this mark a no-op — health never flips ready for a stale activation.
pub fn mark_activation_ready(observed_generation: u64) {
    let _ = SERVE_STATE.compare_exchange(
        pack(observed_generation, STATE_ACTIVATING),
        pack(observed_generation, STATE_ACTIVE),
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
}

pub fn is_standby() -> bool {
    unpack_state(SERVE_STATE.load(Ordering::SeqCst)) == STATE_STANDBY
}

/// True while the node is active but its activation re-derive has not yet completed.
pub fn is_activating() -> bool {
    unpack_state(SERVE_STATE.load(Ordering::SeqCst)) == STATE_ACTIVATING
}

/// The generation of the current activation window. A caller that begins a re-derive
/// captures this, then passes it to [`mark_activation_ready`] so a mark that lost its
/// race against a newer transition is ignored.
pub fn current_activation_generation() -> u64 {
    unpack_generation(SERVE_STATE.load(Ordering::SeqCst))
}

/// True only when the node is active AND has finished its activation re-derive.
/// `/api/v1/health` returns 200 exactly when this is true.
pub fn is_ready_to_serve() -> bool {
    unpack_state(SERVE_STATE.load(Ordering::SeqCst)) == STATE_ACTIVE
}

#[allow(dead_code)]
pub fn current_mode() -> ServerMode {
    if is_standby() {
        ServerMode::Standby
    } else {
        ServerMode::Active
    }
}

/// Register SIGUSR1/SIGUSR2 with Tokio and return the handles, or warn and return None.
#[cfg(unix)]
fn register_raw_signals() -> Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)> {
    use tokio::signal::unix::{SignalKind, signal};
    let sigusr1 = match signal(SignalKind::user_defined1()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("failed to register SIGUSR1 handler: {e}");
            return None;
        }
    };
    let sigusr2 = match signal(SignalKind::user_defined2()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("failed to register SIGUSR2 handler: {e}");
            return None;
        }
    };
    Some((sigusr1, sigusr2))
}

/// Installs SIGUSR1/SIGUSR2 dispositions early; a signal arriving before [`spawn_signal_handlers`]
/// runs is queued rather than killing the process (default terminate → exit code 138).
#[cfg(unix)]
pub fn install_signal_handlers() {
    if let Some(handles) = register_raw_signals() {
        *PENDING_SIGNAL_HANDLES
            .lock()
            .expect("signal handles mutex poisoned") = Some(handles);
    }
}

#[cfg(not(unix))]
pub fn install_signal_handlers() {}

/// Spawns the listener loop that maps SIGUSR1 → active and SIGUSR2 → standby.
/// Consumes handles pre-registered by [`install_signal_handlers`], or registers fresh ones.
#[cfg(unix)]
pub fn spawn_signal_handlers() {
    let handles = PENDING_SIGNAL_HANDLES
        .lock()
        .expect("signal handles mutex poisoned")
        .take()
        .or_else(register_raw_signals);
    let Some((mut sigusr1, mut sigusr2)) = handles else {
        return;
    };
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sigusr1.recv() => {
                    set_server_mode(ServerMode::Active);
                    tracing::info!("SIGUSR1: server_mode switched to active");
                }
                _ = sigusr2.recv() => {
                    set_server_mode(ServerMode::Standby);
                    tracing::info!("SIGUSR2: server_mode switched to standby, /api/v1/health will report 503");
                }
            }
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_signal_handlers() {}

/// Serializes tests that mutate the process-global [`SERVE_STATE`] flag so they cannot
/// race each other across the crate's test binary. Any test in another module that
/// sets the server mode must hold this guard for the duration of its assertions.
#[cfg(test)]
pub(crate) static TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn run_with_test_isolation(test: impl FnOnce()) {
        let _guard = TEST_GUARD.blocking_lock();
        let previous = SERVE_STATE.load(Ordering::SeqCst);
        test();
        SERVE_STATE.store(previous, Ordering::SeqCst);
    }

    #[derive(Deserialize)]
    struct Cfg {
        server_mode: ServerMode,
    }

    #[test]
    fn default_mode_is_active() {
        assert_eq!(ServerMode::default(), ServerMode::Active);
    }

    #[test]
    fn serde_round_trips_active() {
        let cfg: Cfg = toml::from_str("server_mode = \"active\"").unwrap();
        assert_eq!(cfg.server_mode, ServerMode::Active);
    }

    #[test]
    fn serde_round_trips_standby() {
        let cfg: Cfg = toml::from_str("server_mode = \"standby\"").unwrap();
        assert_eq!(cfg.server_mode, ServerMode::Standby);
    }

    #[test]
    fn serde_rejects_unknown_value() {
        let result = toml::from_str::<Cfg>("server_mode = \"drain\"");
        assert!(result.is_err());
    }

    #[test]
    fn set_standby_makes_is_standby_true() {
        run_with_test_isolation(|| {
            set_server_mode(ServerMode::Active);
            assert!(!is_standby());
            assert_eq!(current_mode(), ServerMode::Active);

            set_server_mode(ServerMode::Standby);
            assert!(is_standby());
            assert_eq!(current_mode(), ServerMode::Standby);
        });
    }

    #[test]
    fn set_active_clears_standby() {
        run_with_test_isolation(|| {
            set_server_mode(ServerMode::Standby);
            assert!(is_standby());

            set_server_mode(ServerMode::Active);
            assert!(!is_standby());
        });
    }

    #[test]
    fn activation_is_not_ready_until_marked() {
        run_with_test_isolation(|| {
            // Becoming active is not immediately health-ready: the re-derive must run first.
            set_server_mode(ServerMode::Active);
            assert!(!is_standby());
            assert!(!is_ready_to_serve());

            mark_activation_ready(current_activation_generation());
            assert!(is_ready_to_serve());
        });
    }

    #[test]
    fn stale_activation_mark_from_prior_generation_is_ignored() {
        run_with_test_isolation(|| {
            // Capture the generation of the first activation window.
            set_server_mode(ServerMode::Active);
            let stale_gen = current_activation_generation();

            // A step-down + re-promote supersedes that window with a newer generation.
            set_server_mode(ServerMode::Standby);
            set_server_mode(ServerMode::Active);
            assert!(is_activating());

            // A late mark carrying the *old* generation must not flip health ready.
            mark_activation_ready(stale_gen);
            assert!(!is_ready_to_serve(), "a stale-generation mark must be a no-op");

            // The current activation's own mark does promote it.
            mark_activation_ready(current_activation_generation());
            assert!(is_ready_to_serve());
        });
    }

    #[test]
    fn standby_is_never_ready_and_mark_does_not_promote_it() {
        run_with_test_isolation(|| {
            set_server_mode(ServerMode::Standby);
            assert!(is_standby());
            assert!(!is_ready_to_serve());

            // A late `mark_activation_ready` must not flip a stepped-down node to ready.
            mark_activation_ready(current_activation_generation());
            assert!(is_standby());
            assert!(!is_ready_to_serve());
        });
    }

    /// Concurrency guard for F4: rapidly flapping Active/Standby must assign a strictly
    /// advancing generation to every broadcast, and only the generation carried by the
    /// current window's own broadcast may promote it to health-ready. Kept synchronous
    /// (draining the broadcast with `try_recv`) so it holds the process-global serve
    /// state for only a microsecond, matching the other mode tests' footprint.
    #[test]
    fn broadcast_generation_advances_and_gates_readiness_across_flapping() {
        run_with_test_isolation(|| {
            set_server_mode(ServerMode::Standby);
            let mut rx = subscribe_mode_changes();
            let mut last_gen = current_activation_generation();

            for _ in 0..3 {
                set_server_mode(ServerMode::Active);
                let active = rx
                    .try_recv()
                    .expect("active change must be broadcast");
                assert_eq!(active.mode, ServerMode::Active);
                assert!(active.generation > last_gen, "generation must advance on each transition");
                assert_eq!(active.generation, current_activation_generation());
                assert!(is_activating());

                // A stale mark from the just-superseded window is a no-op.
                mark_activation_ready(last_gen);
                assert!(!is_ready_to_serve(), "stale-generation mark must not promote");

                // The current window's own generation promotes it.
                mark_activation_ready(active.generation);
                assert!(is_ready_to_serve());
                last_gen = active.generation;

                set_server_mode(ServerMode::Standby);
                let standby = rx
                    .try_recv()
                    .expect("standby change must be broadcast");
                assert_eq!(standby.mode, ServerMode::Standby);
                assert!(standby.generation > last_gen, "step-down must also advance the generation");
                assert!(is_standby());
                assert!(!is_ready_to_serve());
                last_gen = standby.generation;
            }
        });
    }

    /// End-to-end: deliver real SIGUSR1/SIGUSR2 to this process and assert the spawned
    /// handler flips the mode and broadcasts the transition — the exact signal → mode →
    /// broadcast path the orchestrator's mode_task consumes to start/stop listeners.
    #[cfg(unix)]
    #[tokio::test]
    async fn os_signals_drive_mode_transitions_and_broadcast() {
        use tokio::time::{Duration, timeout};

        let _guard = TEST_GUARD.lock().await;
        let previous = SERVE_STATE.load(Ordering::SeqCst);

        // Known starting point, then subscribe before spawning handlers so we observe
        // only the signal-driven transitions (not this priming send).
        set_server_mode(ServerMode::Active);
        let mut rx = subscribe_mode_changes();
        spawn_signal_handlers();

        async fn wait_for(
            rx: &mut broadcast::Receiver<ModeChange>,
            want: ServerMode,
        ) {
            timeout(Duration::from_secs(2), async {
                loop {
                    match rx.recv().await {
                        Ok(change) if change.mode == want => break,
                        Ok(_) => continue,
                        Err(e) => panic!("mode broadcast ended before {want:?}: {e:?}"),
                    }
                }
            })
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {want:?} after signal"));
        }

        // SIGUSR2 → Standby
        assert_eq!(unsafe { libc::raise(libc::SIGUSR2) }, 0, "raise(SIGUSR2) failed");
        wait_for(&mut rx, ServerMode::Standby).await;
        assert!(is_standby(), "SIGUSR2 must put the node in standby");

        // SIGUSR1 → Active
        assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0, "raise(SIGUSR1) failed");
        wait_for(&mut rx, ServerMode::Active).await;
        assert!(!is_standby(), "SIGUSR1 must bring the node back to active");

        SERVE_STATE.store(previous, Ordering::SeqCst);
    }
}
