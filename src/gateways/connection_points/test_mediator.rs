//! Test-only stand-in for the mediator-facing steps of a Connection Point: a
//! mediator DID with an installed outcome gets that OOB invitation result, and
//! its listener connects without a live mediator socket.

use serde_json::Value;

pub(crate) type OobOutcome = Result<(String, String, Value), String>;

fn outcomes() -> &'static dashmap::DashMap<String, OobOutcome> {
    static OUTCOMES: std::sync::OnceLock<dashmap::DashMap<String, OobOutcome>> = std::sync::OnceLock::new();
    OUTCOMES.get_or_init(dashmap::DashMap::new)
}

pub(crate) fn install(
    mediator_did: &str,
    outcome: OobOutcome,
) {
    outcomes().insert(mediator_did.to_string(), outcome);
}

pub(super) fn oob_invitation(mediator_did: &str) -> Option<OobOutcome> {
    outcomes()
        .get(mediator_did)
        .map(|outcome| outcome.clone())
}

pub(super) fn connects_offline(mediator_did: &str) -> bool {
    outcomes().contains_key(mediator_did)
}
