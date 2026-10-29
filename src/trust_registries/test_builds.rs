//! Test-only stand-in for building a trust registry client: a registry ID or
//! registry DID with installed outcomes gets them in order, the last one
//! repeating, and connects an offline client instead of a mediator session.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::Notify;

use super::communication::BuildClients;
use crate::comm::didcomm::client::DIDCommClient;

#[derive(Clone)]
pub(crate) enum Outcome {
    Connect,
    Fail(String),
    /// Wait until the gate is notified, then connect.
    Hold(Arc<Notify>),
    /// Create the client, notify the gate, then never finish.
    Stall(Arc<Notify>),
}

struct Installed {
    outcomes: std::sync::Mutex<VecDeque<Outcome>>,
    calls: AtomicU32,
    shutdowns: AtomicU32,
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
            shutdowns: AtomicU32::new(0),
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

/// How many times a build for `key` shut down clients it had not installed.
pub(crate) fn shutdowns(key: &str) -> u32 {
    installed()
        .get(key)
        .map_or(0, |installed| {
            installed
                .shutdowns
                .load(Ordering::SeqCst)
        })
}

pub(super) fn record_shutdown(key: &str) {
    if let Some(installed) = installed().get(key) {
        installed
            .shutdowns
            .fetch_add(1, Ordering::SeqCst);
    }
}

pub(crate) async fn offline_client() -> DIDCommClient {
    DIDCommClient::new("did:example:gateway".to_string(), Vec::new(), None, None)
        .await
        .expect("a client without a mediator builds offline")
}

pub(super) async fn run(
    key: &str,
    clients: &BuildClients,
) -> Option<Result<DIDCommClient, String>> {
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
    let connect = || async {
        let client = offline_client().await;
        clients.hold(&client);
        client
    };
    match outcome {
        Outcome::Connect => Some(Ok(connect().await)),
        Outcome::Fail(reason) => Some(Err(reason)),
        Outcome::Hold(gate) => {
            gate.notified().await;
            Some(Ok(connect().await))
        }
        Outcome::Stall(held) => {
            let _client = connect().await;
            held.notify_one();
            std::future::pending().await
        }
    }
}
