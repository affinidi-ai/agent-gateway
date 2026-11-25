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
use affinidi_messaging_sdk::errors::TrustTaskRefusal;
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

    // A mediator from v0.52 refuses with a `trust-task-error` document where an
    // earlier one sent a problem report. Both are routed by the query they
    // answer; the newer form can also name that query in its own correlators.
    // No other message carries such a document, so reading it first takes
    // nothing from the arms below.
    let refusal = TrustTaskRefusal::from_document(&message.body);
    if refusal.is_some() || message.typ == MSG_TYPE_PROBLEM_REPORT {
        if may_reject(connection, sender) {
            handle_refusal(&message, refusal.as_ref(), &thid, connection, store, ws_state).await;
        } else {
            ignore_unverified_signal(connection, &message.typ, sender);
        }
        return;
    }

    match message.typ.as_str() {
        _ if !sent_by_registry(connection, sender) => {
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

/// Route a refusal the way a problem report has always been routed: to the
/// waiter of the query it answers, ignored when that query is no longer
/// awaited, and otherwise taken as the gateway being rejected. A
/// `trust-task-error` can name its query in its own correlators as well as in
/// its envelope. `refusal` is that document when the refusal came in that
/// form.
async fn handle_refusal(
    message: &DIDCommMessage,
    refusal: Option<&TrustTaskRefusal>,
    thid: &str,
    connection: &TrustRegistryConnection,
    store: &Option<Arc<dyn TrustRegistryStore>>,
    ws_state: &Option<WsState>,
) {
    let result = PollResult {
        msg_type: message.typ.clone(),
        body: message.body.clone(),
    };
    for query_thread in std::iter::once(thid).chain(named_threads(refusal)) {
        if connection
            .deliver_response(query_thread, result.clone())
            .await
        {
            debug!("TR reader: delivered refusal to waiter (thid {})", query_thread);
            return;
        }
    }
    // A refusal answering a query of the gateway's own never fails the
    // registry, however late it arrives. A correlator naming anything else
    // says nothing about the gateway's queries, so it changes nothing.
    if is_request_thread(thid) || named_threads(refusal).any(is_request_thread) {
        warn!(
            thid = ?for_log(thid, 64),
            "TR reader: refusal for '{}' answers a query the gateway no longer awaits, ignoring",
            connection.trust_registry_id
        );
        return;
    }
    // Not a reply to a query → the registry rejected the gateway.
    let (code, comment) = refusal_reason(message, refusal);
    error!(
        code = ?for_log(&code, 128),
        comment = ?for_log(&comment, 256),
        "TR reader: refusal for '{}'",
        connection.trust_registry_id
    );
    update_status(connection, TrustRegistryConnectionStatus::Failed, store, ws_state).await;
}

/// The threads a `trust-task-error` names in its own correlators: its
/// `threadId`, and the id `inResponseTo` gives the refused request. These are
/// what `TrustTaskRefusal::answers` matches a request on, and either can name
/// a query of the gateway's own when the envelope's thread does not.
fn named_threads(refusal: Option<&TrustTaskRefusal>) -> impl Iterator<Item = &str> {
    refusal
        .into_iter()
        .flat_map(|refusal| {
            refusal
                .thread_id
                .as_deref()
                .into_iter()
                .chain(
                    refusal
                        .in_response_to
                        .as_ref()
                        .and_then(|refused| refused.id.as_deref()),
                )
        })
}

/// Peer-chosen text, capped so one field cannot fill the log; the caller
/// renders it with `?` so a newline in it cannot forge a line.
fn for_log(
    value: &str,
    max_chars: usize,
) -> String {
    value
        .chars()
        .take(max_chars)
        .collect()
}

/// The code and explanation to log, read from whichever form the refusal
/// arrived in.
fn refusal_reason(
    message: &DIDCommMessage,
    refusal: Option<&TrustTaskRefusal>,
) -> (String, String) {
    if let Some(refusal) = refusal {
        return (
            refusal
                .mediator_code()
                .to_string(),
            refusal
                .message
                .clone()
                .unwrap_or_default(),
        );
    }
    let field = |name: &str| {
        message
            .body
            .get(name)
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let code = field("code");
    (
        if code.is_empty() {
            "unknown".to_string()
        } else {
            code
        },
        field("comment"),
    )
}

fn sent_by_registry(
    connection: &TrustRegistryConnection,
    sender: Option<&str>,
) -> bool {
    sender.is_some_and(|did| connection.serves(did))
}

/// Whether `sender` may refuse on the registry's behalf: the registry itself,
/// or the mediator that relays its refusals.
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
        sender = ?sender.map(|did| for_log(did, 64)),
        message_type = ?for_log(message_type, 128),
        "TR reader: ignoring a message for '{}' from a sender that is not the registry",
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

    fn problem_report(thid: &str) -> DIDCommMessage {
        DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            MSG_TYPE_PROBLEM_REPORT.to_string(),
            serde_json::json!({ "code": "e.p.rejected", "comment": "rejected" }),
        )
        .thid(thid.to_string())
        .from(REGISTRY.to_string())
        .finalize()
    }

    fn sent_by(
        mut message: DIDCommMessage,
        from: Option<&str>,
    ) -> DIDCommMessage {
        message.from = from.map(str::to_string);
        message
    }

    /// The same refusal in the form a mediator from v0.52 sends: a
    /// `trust-task-error` document under the Trust Tasks envelope type.
    fn trust_task_error(thid: &str) -> DIDCommMessage {
        DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            "https://trusttasks.org/binding/didcomm/0.1/envelope".to_string(),
            serde_json::json!({
                "id": "urn:uuid:00000000-0000-4000-8000-000000000001",
                "type": "https://trusttasks.org/spec/trust-task-error/0.6",
                "payload": {
                    "code": "messaging/account/get:unknownAccount",
                    "message": "account not found",
                    "retryable": false,
                },
            }),
        )
        .thid(thid.to_string())
        .from(REGISTRY.to_string())
        .finalize()
    }

    /// A query built as `send_and_await` builds one: the thread its waiter is
    /// registered under, and what a refusal of it names by `correlator` — the
    /// thread as `threadId`, or the query's own id as `inResponseTo`.
    fn named_query(
        connection: &TrustRegistryConnection,
        correlator: &str,
    ) -> (String, String) {
        let (query, thread) = super::super::communication::query_message(
            &connection.our_did,
            &connection.registry_did,
            "https://example.org/query",
            serde_json::json!({}),
        );
        let named = if correlator == "threadId" {
            thread.clone()
        } else {
            query.id
        };
        (thread, named)
    }

    /// A refusal arriving on `thid` that names `named` in its own
    /// `correlator`, the way only the `trust-task-error` form can.
    fn trust_task_error_naming(
        thid: &str,
        correlator: &str,
        named: &str,
    ) -> DIDCommMessage {
        let mut message = trust_task_error(thid);
        if correlator == "threadId" {
            message.body["threadId"] = serde_json::json!(named);
        } else {
            message.body["payload"]["inResponseTo"] = serde_json::json!({
                "typeUri": "https://trusttasks.org/spec/trust-task/0.6",
                "id": named,
            });
        }
        message
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

    fn setup_message(msg_type: &str) -> DIDCommMessage {
        DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            msg_type.to_string(),
            serde_json::json!({ "channel_did": "did:example:registry" }),
        )
        .thid(uuid::Uuid::new_v4().to_string())
        .from(REGISTRY.to_string())
        .finalize()
    }

    #[tokio::test]
    async fn setup_received_moves_the_registry_to_awaiting_approval() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connecting).await;

        handle_message(setup_message(connection::SETUP_RECEIVED), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::AwaitingApproval);
    }

    #[tokio::test]
    async fn setup_approved_moves_the_registry_to_connected() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::AwaitingApproval).await;

        handle_message(setup_message(connection::SETUP_APPROVED), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    #[tokio::test]
    async fn a_problem_report_answering_a_request_no_longer_awaited_keeps_the_status() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;

        let thid = format!("{}timed-out", super::super::communication::REQUEST_THREAD_PREFIX);
        handle_message(problem_report(&thid), &connection, &store, &None).await;

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

            handle_message(problem_report("thid-rejection"), &connection, &store, &None).await;

            assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Failed);
        }
    }

    #[tokio::test]
    async fn a_trust_task_error_answering_a_request_no_longer_awaited_keeps_the_status() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;

        let thid = format!("{}timed-out", super::super::communication::REQUEST_THREAD_PREFIX);
        handle_message(trust_task_error(&thid), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    #[tokio::test]
    async fn a_trust_task_error_naming_a_query_no_longer_awaited_keeps_the_status() {
        for correlator in ["threadId", "inResponseTo"] {
            let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;
            let named = named_query(&connection, correlator).1;

            handle_message(
                trust_task_error_naming("mediator-thread-1", correlator, &named),
                &connection,
                &store,
                &None,
            )
            .await;

            assert_eq!(
                status_of(&store, &connection).await,
                TrustRegistryConnectionStatus::Connected,
                "a refusal naming a query of the gateway's by {correlator} answers that query"
            );
        }
    }

    #[tokio::test]
    async fn a_trust_task_error_naming_a_request_the_gateway_never_sent_marks_the_registry_failed() {
        for status in [
            TrustRegistryConnectionStatus::Connecting,
            TrustRegistryConnectionStatus::AwaitingApproval,
            TrustRegistryConnectionStatus::Connected,
        ] {
            for correlator in ["threadId", "inResponseTo"] {
                let before = format!("{status:?}");
                let (connection, store, _dir) = registry_with(status.clone()).await;

                handle_message(
                    trust_task_error_naming("mediator-thread-1", correlator, "registry-thread-1"),
                    &connection,
                    &store,
                    &None,
                )
                .await;

                assert_eq!(
                    status_of(&store, &connection).await,
                    TrustRegistryConnectionStatus::Failed,
                    "from {before}, a {correlator} naming no query of the gateway's is a rejection"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_trust_task_error_naming_a_waiting_query_is_delivered_to_it() {
        for correlator in ["threadId", "inResponseTo"] {
            let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;
            let (thread, named) = named_query(&connection, correlator);
            let (waiter, mut answer) = tokio::sync::oneshot::channel();
            connection
                .response_waiters
                .lock()
                .await
                .insert(thread, waiter);

            handle_message(
                trust_task_error_naming("mediator-thread-1", correlator, &named),
                &connection,
                &store,
                &None,
            )
            .await;

            let delivered = answer
                .try_recv()
                .unwrap_or_else(|_| panic!("a refusal naming the query by {correlator} reaches its waiter"));
            assert_eq!(delivered.body["payload"]["code"], "messaging/account/get:unknownAccount");
            assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
        }
    }

    #[tokio::test]
    async fn an_unmatched_trust_task_error_on_any_other_thread_marks_the_registry_failed() {
        for status in [
            TrustRegistryConnectionStatus::Connecting,
            TrustRegistryConnectionStatus::AwaitingApproval,
            TrustRegistryConnectionStatus::Connected,
        ] {
            let before = format!("{status:?}");
            let (connection, store, _dir) = registry_with(status).await;

            handle_message(trust_task_error("thid-rejection"), &connection, &store, &None).await;

            assert_eq!(
                status_of(&store, &connection).await,
                TrustRegistryConnectionStatus::Failed,
                "a refusal from {before} ends the same way in either form"
            );
        }
    }

    #[tokio::test]
    async fn a_message_that_is_not_a_refusal_keeps_the_status() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;
        let unanswered = DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            connection::SETUP.to_string(),
            serde_json::json!({}),
        )
        .thid("thid-unmatched".to_string())
        .finalize();

        handle_message(unanswered, &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    #[test]
    fn a_refusal_is_read_from_whichever_form_it_arrived_in() {
        let document = trust_task_error("thid-rejection");
        let refusal = TrustTaskRefusal::from_document(&document.body).expect("a trust-task-error");
        assert_eq!(
            refusal_reason(&document, Some(&refusal)),
            ("messaging/account/get:unknownAccount".to_string(), "account not found".to_string()),
            "a trust-task-error keeps its code and message under payload"
        );

        assert_eq!(
            refusal_reason(&problem_report("thid-rejection"), None),
            ("e.p.rejected".to_string(), "rejected".to_string())
        );

        let bare = DIDCommMessage::build(
            uuid::Uuid::new_v4().to_string(),
            MSG_TYPE_PROBLEM_REPORT.to_string(),
            serde_json::json!({}),
        )
        .finalize();
        assert_eq!(refusal_reason(&bare, None), ("unknown".to_string(), String::new()));
    }

    #[tokio::test]
    async fn a_refusal_relayed_by_the_registry_mediator_marks_the_registry_failed() {
        for refusal in [problem_report("thid-rejection"), trust_task_error("thid-rejection")] {
            let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connecting).await;
            let mediator = connection
                .mediator_did
                .clone();

            handle_message(sent_by(refusal, Some(&mediator)), &connection, &store, &None).await;

            assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Failed);
        }
    }

    #[tokio::test]
    async fn a_refusal_from_another_sender_or_none_keeps_the_status() {
        for from in [Some(STRANGER), None] {
            for refusal in [problem_report("thid-rejection"), trust_task_error("thid-rejection")] {
                let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;

                handle_message(sent_by(refusal, from), &connection, &store, &None).await;

                assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected, "{from:?}");
            }
        }
    }

    #[tokio::test]
    async fn setup_messages_from_another_sender_or_none_keep_the_status() {
        for from in [Some(STRANGER), None] {
            for message_type in [connection::SETUP_RECEIVED, connection::SETUP_APPROVED] {
                let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connecting).await;

                handle_message(sent_by(setup_message(message_type), from), &connection, &store, &None).await;

                assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connecting, "{from:?}");
            }
        }
    }

    #[tokio::test]
    async fn a_late_setup_received_does_not_downgrade_a_connected_registry() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;

        handle_message(setup_message(connection::SETUP_RECEIVED), &connection, &store, &None).await;

        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }

    #[tokio::test]
    async fn setup_messages_do_not_revive_a_failed_registry() {
        for message_type in [connection::SETUP_RECEIVED, connection::SETUP_APPROVED] {
            let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Failed).await;

            handle_message(setup_message(message_type), &connection, &store, &None).await;

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
    async fn a_refusal_from_another_sender_answers_no_pending_query() {
        let (connection, store, _dir) = registry_with(TrustRegistryConnectionStatus::Connected).await;
        let mut pending = awaiting(&connection, "thid-query").await;

        handle_message(sent_by(problem_report("thid-query"), Some(STRANGER)), &connection, &store, &None).await;
        assert!(pending.try_recv().is_err());

        handle_message(problem_report("thid-query"), &connection, &store, &None).await;
        assert_eq!(
            pending
                .try_recv()
                .unwrap()
                .msg_type,
            MSG_TYPE_PROBLEM_REPORT
        );
        assert_eq!(status_of(&store, &connection).await, TrustRegistryConnectionStatus::Connected);
    }
}
