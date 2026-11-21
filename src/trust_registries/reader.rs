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

use super::communication::{TrustRegistryConnection, connection, is_request_thread};
use super::store::TrustRegistryStore;
use super::types::{TrustRegistry, TrustRegistryConnectionStatus};
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
    let sender = message.from.as_deref();

    match message.typ.as_str() {
        connection::SETUP_RECEIVED | connection::SETUP_APPROVED if !sent_by_registry(connection, sender) => {
            ignore_unverified_signal(connection, &message.typ, sender);
        }
        connection::SETUP_RECEIVED => {
            info!("TR reader: setup/received for '{}'", connection.trust_registry_id);
            update_status(connection, TrustRegistryConnectionStatus::AwaitingApproval, store, ws_state).await;
        }
        connection::SETUP_APPROVED => {
            info!("TR reader: setup/approved for '{}'", connection.trust_registry_id);
            update_status(connection, TrustRegistryConnectionStatus::Connected, store, ws_state).await;
        }
        MSG_TYPE_PROBLEM_REPORT if !may_reject(connection, sender) => {
            ignore_unverified_signal(connection, &message.typ, sender);
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
            } else if is_request_thread(&thid) {
                warn!(
                    // Peer-chosen: capped at 64 chars and Debug-escaped.
                    thid = ?capped(&thid),
                    "TR reader: problem-report for '{}' answers a request no longer awaited, ignoring",
                    connection.trust_registry_id
                );
            } else {
                // Not a reply to a request → the registry rejected the gateway.
                let field = |name| {
                    message
                        .body
                        .get(name)
                        .and_then(|v| v.as_str())
                        .map(capped)
                };
                error!(
                    // Peer-chosen: capped at 64 chars and Debug-escaped.
                    code = ?field("code"),
                    comment = ?field("comment"),
                    "TR reader: problem-report for '{}'",
                    connection.trust_registry_id
                );
                update_status(connection, TrustRegistryConnectionStatus::Failed, store, ws_state).await;
            }
        }
        _ if !sent_by_registry(connection, sender) => {
            ignore_unverified_signal(connection, &message.typ, sender);
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

fn capped(peer_chosen: &str) -> String {
    peer_chosen
        .chars()
        .take(64)
        .collect()
}

fn sent_by_registry(
    connection: &TrustRegistryConnection,
    sender: Option<&str>,
) -> bool {
    sender.is_some_and(|did| connection.serves(did))
}

fn may_reject(
    connection: &TrustRegistryConnection,
    sender: Option<&str>,
) -> bool {
    sent_by_registry(connection, sender) || sender.is_some_and(|did| did == connection.mediator_did)
}

fn ignore_unverified_signal(
    connection: &TrustRegistryConnection,
    message_type: &str,
    sender: Option<&str>,
) {
    warn!(
        // Peer-chosen: capped at 64 chars and Debug-escaped.
        sender = ?sender.map(capped),
        "TR reader: ignoring '{}' for '{}' from a sender that is not the registry",
        capped(message_type),
        connection.trust_registry_id
    );
}

/// Whether a registry message may move the connection from `current` to `next`.
/// Setup messages only move it forward; a rejection may fail it from any state.
fn may_move(
    current: &TrustRegistryConnectionStatus,
    next: &TrustRegistryConnectionStatus,
) -> bool {
    use TrustRegistryConnectionStatus::*;
    match next {
        AwaitingApproval => matches!(current, Connecting | AwaitingApproval),
        Connected => matches!(current, Connecting | AwaitingApproval | Connected),
        Failed => true,
        Connecting | Disconnected => false,
    }
}

/// Persist a connection-status change and refresh the dashboard. A no-op when
/// no store is configured or the current status does not allow the change.
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

    let status_label = format!("{:?}", new_status);
    let applied = new_status.clone();
    let change = Box::new(move |tr: &mut TrustRegistry| {
        if may_move(&tr.connection_status, &new_status) {
            tr.connection_status = new_status;
            tr.updated_at = chrono::Utc::now();
        }
    });
    match store
        .modify(tr_id, change)
        .await
    {
        Ok(Some(updated)) if updated.connection_status != applied => {
            warn!(
                "TR reader: kept '{}' at {:?}; a registry message cannot move it to {}",
                tr_id, updated.connection_status, status_label
            );
            return;
        }
        Ok(Some(_)) => {}
        Ok(None) => {
            debug!("TR reader: trust registry '{}' was deleted; its status was not written", tr_id);
            return;
        }
        Err(e) => {
            error!("TR reader: failed to update status for '{}': {}", tr_id, e);
            return;
        }
    }

    info!("TR reader: updated '{}' status to {}", tr_id, status_label);

    if let Some(ws_state) = ws_state {
        ws_state.broadcast(crate::server::WsUpdate::RefreshDashboard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_registries::FileSystemTrustRegistryStore;
    use crate::trust_registries::did_manager::DidMethod;
    use crate::trust_registries::types::TrustRegistry;
    use tokio::sync::Mutex;

    async fn registry_with(
        status: TrustRegistryConnectionStatus
    ) -> (TrustRegistryConnection, Option<Arc<dyn TrustRegistryStore>>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemTrustRegistryStore::new(dir.path().join("records"))
            .await
            .expect("store");
        let mut registry = TrustRegistry::new(
            "registry".to_string(),
            String::new(),
            "https://registry.example/oob".to_string(),
            DidMethod::Peer,
        );
        registry.connection_status = status;
        store
            .create(&registry)
            .await
            .expect("create");
        let connection = TrustRegistryConnection {
            trust_registry_id: registry.id,
            our_did: "did:example:gateway".to_string(),
            registry_did: "did:example:registry".to_string(),
            main_did: None,
            mediator_did: "did:example:mediator".to_string(),
            is_temporary: false,
            client: crate::trust_registries::test_builds::offline_client().await,
            response_waiters: Arc::new(Mutex::new(HashMap::new())),
        };
        (connection, Some(Arc::new(store) as Arc<dyn TrustRegistryStore>), dir)
    }

    const REGISTRY: &str = "did:example:registry";
    const STRANGER: &str = "did:example:stranger";

    fn problem_report(
        thid: &str,
        from: &str,
    ) -> DIDCommMessage {
        DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            MSG_TYPE_PROBLEM_REPORT.to_string(),
            serde_json::json!({ "code": "e.p.rejected", "comment": "rejected" }),
        )
        .thid(thid.to_string())
        .from(from.to_string())
        .finalize()
    }

    fn setup(
        message_type: &str,
        from: &str,
    ) -> DIDCommMessage {
        DIDCommMessage::build(uuid::Uuid::new_v4().to_string(), message_type.to_string(), serde_json::json!({}))
            .from(from.to_string())
            .finalize()
    }

    async fn status_of(
        store: &Option<Arc<dyn TrustRegistryStore>>,
        connection: &TrustRegistryConnection,
    ) -> TrustRegistryConnectionStatus {
        store
            .as_ref()
            .expect("store")
            .get(&connection.trust_registry_id)
            .await
            .expect("get")
            .expect("the registry is stored")
            .connection_status
    }

    #[tokio::test]
    async fn a_problem_report_answering_a_request_no_longer_awaited_keeps_the_status() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;

        let thid = format!("{}timed-out", super::super::communication::REQUEST_THREAD_PREFIX);
        handle_message(problem_report(&thid, REGISTRY), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    #[tokio::test]
    async fn an_unmatched_problem_report_on_any_other_thread_marks_the_registry_failed() {
        for status in [
            TrustRegistryConnectionStatus::Connecting,
            TrustRegistryConnectionStatus::AwaitingApproval,
            TrustRegistryConnectionStatus::Connected,
        ] {
            let (connection, store, _dir) = registry_with(status).await;

            handle_message(problem_report("thid-rejection", REGISTRY), &connection, &store, &None).await;

            assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Failed);
        }
    }

    #[tokio::test]
    async fn a_rejection_relayed_by_the_registry_mediator_marks_the_registry_failed() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connecting).await;
        let mediator = connection
            .mediator_did
            .clone();

        handle_message(problem_report("thid-rejection", &mediator), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Failed);
    }

    #[tokio::test]
    async fn a_rejection_from_another_sender_keeps_the_status() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;

        handle_message(problem_report("thid-rejection", STRANGER), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    async fn awaiting(
        connection: &TrustRegistryConnection,
        thid: &str,
    ) -> tokio::sync::oneshot::Receiver<PollResult> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        connection
            .response_waiters
            .lock()
            .await
            .insert(thid.to_string(), tx);
        rx
    }

    fn reply(
        thid: &str,
        from: &str,
    ) -> DIDCommMessage {
        DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            "https://example.org/registry/query-response".to_string(),
            serde_json::json!({ "recognized": true }),
        )
        .thid(thid.to_string())
        .from(from.to_string())
        .finalize()
    }

    #[tokio::test]
    async fn only_the_registry_answers_a_pending_query() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;
        let mediator = connection
            .mediator_did
            .clone();
        let mut pending = awaiting(&connection, "thid-query").await;

        for forger in [STRANGER, mediator.as_str()] {
            handle_message(reply("thid-query", forger), &connection, &store, &None).await;
            assert!(pending.try_recv().is_err(), "{forger} answers nothing");
        }

        handle_message(reply("thid-query", REGISTRY), &connection, &store, &None).await;
        assert_eq!(
            pending
                .try_recv()
                .unwrap()
                .body,
            serde_json::json!({ "recognized": true })
        );
    }

    #[tokio::test]
    async fn a_problem_report_from_another_sender_answers_no_pending_query() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;
        let mut pending = awaiting(&connection, "thid-query").await;

        handle_message(problem_report("thid-query", STRANGER), &connection, &store, &None).await;
        assert!(pending.try_recv().is_err());

        handle_message(problem_report("thid-query", REGISTRY), &connection, &store, &None).await;
        assert_eq!(
            pending
                .try_recv()
                .unwrap()
                .msg_type,
            MSG_TYPE_PROBLEM_REPORT
        );
        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    #[tokio::test]
    async fn the_registry_moves_the_connection_through_setup() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connecting).await;

        handle_message(setup(connection::SETUP_RECEIVED, REGISTRY), &connection, &store, &None).await;
        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::AwaitingApproval);

        handle_message(setup(connection::SETUP_APPROVED, REGISTRY), &connection, &store, &None).await;
        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    #[tokio::test]
    async fn setup_messages_from_another_sender_keep_the_status() {
        for message_type in [connection::SETUP_RECEIVED, connection::SETUP_APPROVED] {
            let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connecting).await;

            handle_message(setup(message_type, STRANGER), &connection, &store, &None).await;

            assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connecting);
        }
    }

    #[tokio::test]
    async fn a_setup_message_without_a_sender_keeps_the_status() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connecting).await;
        let unsigned = DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            connection::SETUP_APPROVED.to_string(),
            serde_json::json!({}),
        )
        .finalize();

        handle_message(unsigned, &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connecting);
    }

    #[tokio::test]
    async fn a_late_setup_received_does_not_downgrade_a_connected_registry() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;

        handle_message(setup(connection::SETUP_RECEIVED, REGISTRY), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    #[tokio::test]
    async fn setup_messages_do_not_revive_a_failed_registry() {
        for message_type in [connection::SETUP_RECEIVED, connection::SETUP_APPROVED] {
            let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Failed).await;

            handle_message(setup(message_type, REGISTRY), &connection, &store, &None).await;

            assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Failed);
        }
    }

    #[test]
    fn registry_messages_cannot_move_a_connection_back_to_connecting_or_disconnected() {
        for current in [
            TrustRegistryConnectionStatus::Connecting,
            TrustRegistryConnectionStatus::AwaitingApproval,
            TrustRegistryConnectionStatus::Connected,
            TrustRegistryConnectionStatus::Failed,
        ] {
            assert!(!may_move(&current, &TrustRegistryConnectionStatus::Connecting));
            assert!(!may_move(&current, &TrustRegistryConnectionStatus::Disconnected));
            assert!(may_move(&current, &TrustRegistryConnectionStatus::Failed));
        }
    }
}
