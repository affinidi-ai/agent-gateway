//! Test-only stand-in for the mediator-facing steps of a Connection Point: a
//! mediator DID with an installed outcome gets that OOB invitation result, and
//! its listener connects without a live mediator socket. An installed mediator
//! can first refuse the DID a set number of times, which the first-call retry
//! has to ride out.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

use super::first_call_retry::FirstCallRetry;

pub(crate) type OobOutcome = Result<(String, String, Value), String>;

#[derive(Clone)]
struct Installed {
    outcome: OobOutcome,
    refusals_left: Arc<AtomicU32>,
    calls: Arc<AtomicU32>,
    retry: FirstCallRetry,
}

fn outcomes() -> &'static dashmap::DashMap<String, Installed> {
    static OUTCOMES: std::sync::OnceLock<dashmap::DashMap<String, Installed>> = std::sync::OnceLock::new();
    OUTCOMES.get_or_init(dashmap::DashMap::new)
}

pub(crate) fn install(
    mediator_did: &str,
    outcome: OobOutcome,
) {
    install_refusing(mediator_did, outcome, 0, FirstCallRetry::default());
}

pub(crate) fn install_refusing(
    mediator_did: &str,
    outcome: OobOutcome,
    refusals: u32,
    retry: FirstCallRetry,
) {
    outcomes().insert(
        mediator_did.to_string(),
        Installed {
            outcome,
            refusals_left: Arc::new(AtomicU32::new(refusals)),
            calls: Arc::new(AtomicU32::new(0)),
            retry,
        },
    );
}

pub(crate) fn first_calls(mediator_did: &str) -> u32 {
    outcomes()
        .get(mediator_did)
        .map_or(0, |installed| {
            installed
                .calls
                .load(Ordering::SeqCst)
        })
}

pub(super) async fn oob_invitation(
    mediator_did: &str,
    retried: bool,
) -> Option<OobOutcome> {
    let installed = outcomes()
        .get(mediator_did)
        .map(|installed| installed.clone())?;
    let retry = if retried {
        installed.retry
    } else {
        FirstCallRetry::never()
    };
    let admitted = retry
        .run(
            || {
                installed
                    .calls
                    .fetch_add(1, Ordering::SeqCst);
                let refused = installed
                    .refusals_left
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
                    .is_ok();
                async move {
                    if refused {
                        Err("refused")
                    } else {
                        Ok(())
                    }
                }
            },
            |_| true,
            || "timed out",
        )
        .await;
    Some(match admitted {
        Ok(()) => installed.outcome,
        Err(reason) => Err(format!("Failed to add profile to ATM: {reason}")),
    })
}

pub(super) fn connects_offline(mediator_did: &str) -> bool {
    outcomes().contains_key(mediator_did)
}
