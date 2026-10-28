//! Test-only stand-in for building a trust registry client: a registry ID or
//! registry DID with installed outcomes gets them in order, the last one
//! repeating, and connects an offline client instead of a mediator session.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::Notify;

use crate::comm::didcomm::client::DIDCommClient;

#[derive(Clone)]
pub(crate) enum Outcome {
    Connect,
    Fail(String),
    /// Wait until the gate is notified, then connect.
    Hold(Arc<Notify>),
}

struct Installed {
    outcomes: std::sync::Mutex<VecDeque<Outcome>>,
    calls: AtomicU32,
}

fn installed() -> &'static dashmap::DashMap<String, Arc<Installed>> {
    static INSTALLED: std::sync::OnceLock<dashmap::DashMap<String, Arc<Installed>>> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(dashmap::DashMap::new)
}

pub(crate) fn install(
    key: &str,
    outcomes: Vec<Outcome>,
) {
    installed().insert(
        key.to_string(),
        Arc::new(Installed {
            outcomes: std::sync::Mutex::new(outcomes.into()),
            calls: AtomicU32::new(0),
        }),
    );
}

pub(crate) fn calls(key: &str) -> u32 {
    installed()
        .get(key)
        .map_or(0, |installed| {
            installed
                .calls
                .load(Ordering::SeqCst)
        })
}

pub(crate) async fn offline_client() -> DIDCommClient {
    DIDCommClient::new("did:example:gateway".to_string(), Vec::new(), None, None)
        .await
        .expect("a client without a mediator builds offline")
}

pub(super) async fn run(key: &str) -> Option<Result<DIDCommClient, String>> {
    let installed = installed()
        .get(key)
        .map(|installed| Arc::clone(&installed))?;
    installed
        .calls
        .fetch_add(1, Ordering::SeqCst);
    let outcome = {
        let mut outcomes = installed
            .outcomes
            .lock()
            .expect("outcomes lock");
        if outcomes.len() > 1 {
            outcomes.pop_front()
        } else {
            outcomes.front().cloned()
        }
    }?;
    match outcome {
        Outcome::Connect => Some(Ok(offline_client().await)),
        Outcome::Fail(reason) => Some(Err(reason)),
        Outcome::Hold(gate) => {
            gate.notified().await;
            Some(Ok(offline_client().await))
        }
    }
}
