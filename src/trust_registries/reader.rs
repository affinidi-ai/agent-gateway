//! Per-registry DIDComm stream reader.
//!
//! Each active trust-registry connection has exactly one reader task draining
//! the mediator websocket via `live_stream_next`. It is the **sole** consumer of
//! that stream: it demultiplexes query responses back to the `send_and_await`
//! waiter registered under the response's thread id (`thid`), and drives the
//! connection setup/approval status transitions that were previously handled by
//! the standalone worker loop.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_didcomm::Message as DIDCommMessage;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::communication::{TrustRegistryConnection, connection};
use super::store::TrustRegistryStore;
use super::types::TrustRegistryConnectionStatus;
use crate::comm::didcomm::trust_registry::PollResult;
use crate::server::websocket::WsState;

/// Problem report message type (DIDComm standard).
const MSG_TYPE_PROBLEM_REPORT: &str = "https://didcomm.org/report-problem/2.0/problem-report";

/// How long a single `live_stream_next` call blocks before returning `None`,
/// letting the loop re-check that its connection still exists.
const READ_WAIT: Duration = Duration::from_secs(300);

type Connections = Arc<RwLock<HashMap<String, TrustRegistryConnection>>>;

/// Drive the reader loop for a single registry connection until the connection
/// is removed from the map (graceful stop) or the task is aborted.
pub(crate) async fn run(
    connections: Connections,
    trust_registry_id: String,
    store: Option<Arc<dyn TrustRegistryStore>>,
    ws_state: Option<WsState>,
) {
    info!("TR reader: starting for '{}'", trust_registry_id);

    loop {
        let connection = {
            let guard = connections.read().await;
            match guard.get(&trust_registry_id) {
                Some(c) => c.clone(),
                None => {
                    debug!("TR reader: connection '{}' gone, stopping", trust_registry_id);
                    break;
                }
            }
        };

        match connection
            .client
            .live_stream_next(READ_WAIT, true)
            .await
        {
            Ok(Some((message, _metadata))) => {
                // Sender identity is verified natively by the SDK's authcrypt-only
                // UnpackPolicy (anoncrypt/plaintext envelopes are purged at pickup),
                // so any message delivered here has a cryptographically verified
                // `from`.
                handle_message(message, &connection, &store, &ws_state).await;
            }
            Ok(None) => {
                // Timeout or a transient disconnect. The SDK reconnects the
                // socket in the background; re-check the connection and retry.
                continue;
            }
            Err(e) => {
                warn!("TR reader: stream error for '{}': {:?}", trust_registry_id, e);
                connection
                    .fail_all_waiters()
                    .await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    // Reader exiting — release any queries still awaiting on this connection so
    // they fail fast rather than block until their own timeout.
    if let Some(connection) = connections
        .read()
        .await
        .get(&trust_registry_id)
    {
        connection
            .fail_all_waiters()
            .await;
    }
    info!("TR reader: stopped for '{}'", trust_registry_id);
}

/// Route one inbound message: demux query responses by `thid`, otherwise drive
/// connection-setup status transitions.
async fn handle_message(
    message: DIDCommMessage,
    connection: &TrustRegistryConnection,
    store: &Option<Arc<dyn TrustRegistryStore>>,
    ws_state: &Option<WsState>,
) {
    let thid = message
        .thid
        .clone()
        .or_else(|| message.pthid.clone())
        .unwrap_or_else(|| message.id.clone());

    match message.typ.as_str() {
        connection::SETUP_RECEIVED => {
            info!("TR reader: setup/received for '{}'", connection.trust_registry_id);
            update_status(connection, TrustRegistryConnectionStatus::AwaitingApproval, store, ws_state).await;
        }
        connection::SETUP_APPROVED => {
            info!("TR reader: setup/approved for '{}'", connection.trust_registry_id);
            update_status(connection, TrustRegistryConnectionStatus::Connected, store, ws_state).await;
        }
        MSG_TYPE_PROBLEM_REPORT => {
            let result = PollResult {
                msg_type: message.typ.clone(),
                body: message.body.clone(),
            };
            if connection
                .deliver_response(&thid, result)
                .await
            {
                debug!("TR reader: delivered problem-report to waiter (thid {})", thid);
            } else {
                // No query waiter → a connection-level problem (e.g. the
                // registry rejected the setup / approval).
                let code = message
                    .body
                    .get("code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let comment = message
                    .body
                    .get("comment")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                error!("TR reader: problem-report for '{}': {}: {}", connection.trust_registry_id, code, comment);
                update_status(connection, TrustRegistryConnectionStatus::Failed, store, ws_state).await;
            }
        }
        other => {
            let result = PollResult {
                msg_type: message.typ.clone(),
                body: message.body.clone(),
            };
            if !connection
                .deliver_response(&thid, result)
                .await
            {
                debug!(
                    "TR reader: no waiter for message type '{}' (thid {}) on '{}', ignoring",
                    other, thid, connection.trust_registry_id
                );
            }
        }
    }
}

/// Persist a connection-status change and refresh the dashboard, mirroring the
/// former worker behavior. A no-op when no store is configured.
async fn update_status(
    connection: &TrustRegistryConnection,
    new_status: TrustRegistryConnectionStatus,
    store: &Option<Arc<dyn TrustRegistryStore>>,
    ws_state: &Option<WsState>,
) {
    let Some(store) = store else {
        return;
    };
    let tr_id = &connection.trust_registry_id;

    let mut tr = match store.get(tr_id).await {
        Ok(Some(tr)) => tr,
        Ok(None) => {
            warn!("TR reader: trust registry '{}' not found in store", tr_id);
            return;
        }
        Err(e) => {
            error!("TR reader: failed to get trust registry '{}': {}", tr_id, e);
            return;
        }
    };

    let status_label = format!("{:?}", new_status);
    tr.connection_status = new_status;
    tr.updated_at = chrono::Utc::now();

    if let Err(e) = store.update(&tr).await {
        error!("TR reader: failed to update status for '{}': {}", tr_id, e);
        return;
    }

    info!("TR reader: updated '{}' status to {}", tr_id, status_label);

    if let Some(ws_state) = ws_state {
        ws_state.broadcast(crate::server::WsUpdate::RefreshDashboard);
    }
}
