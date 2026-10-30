//! Trust Registry Connection-Point-Based Communication
//!
//! This module manages DIDComm communication with external trust registries
//! using a connection-point-based approach. Each trust registry gets its own
//! per-registry did:web identity. The trust registry service creates a connection
//! point with an OOB invitation URL, and this gateway accepts that invitation to
//! establish the connection.
//!
//! Follows the same patterns as gateway connection points in
//! src/gateways/connection_points/ but with trust-registry-specific types.

use affinidi_messaging_didcomm::Message as DIDCommMessage;
use affinidi_tdk_common::secrets_resolver::secrets::Secret;
use reqwest::Method;
use reqwest::header::{ACCEPT, HeaderMap, HeaderValue};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock, oneshot, watch};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::comm::connection_health::ReconnectPolicy;
use crate::comm::didcomm::trust_registry::PollResult;

use super::did_manager::{DidMethod, generate_trust_registry_identity, load_trust_registry_secrets};
use super::store::TrustRegistryStore;
use super::types::{
    CreateReferenceFieldRequest, TrAdminListRecordsResponse, TrAdminRecordRequest, TrAdminRecordResponse,
    TrProblemReport, TrqpAuthorizationResponse, TrqpQueryRequest, TrqpRecognitionResponse, TrustRecord,
    TrustRegistryConnectionStatus, UpdateReferenceFieldRequest,
};
use crate::egress::{EgressError, EgressPolicy, bdd_egress_allowlist, guarded_send_inner};
use crate::gateways::connection_points::first_call_retry::FirstCallRetry;
use crate::mediators::utils::{fetch_mediator_did_from_url, set_acl_to_allow_everything_and_more};

// =============================================================================
// Trust Registry DIDComm Protocol Message Types
// =============================================================================

/// Problem report message type (DIDComm standard)
const MSG_TYPE_PROBLEM_REPORT: &str = "https://didcomm.org/report-problem/2.0/problem-report";

/// Maximum number of preflight readiness polls after a fresh WebSocket is opened.
const WS_READY_MAX_ATTEMPTS: u8 = 5;
/// Time to wait for the WebSocket preflight check on each attempt.
const WS_READY_CHECK_TIMEOUT: Duration = Duration::from_secs(2);
/// Back-off delay between failed preflight attempts.
const WS_READY_RETRY_DELAY: Duration = Duration::from_millis(300);
/// How long closing a connection waits for its websocket shutdown.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for a build requested by a manual, startup or promotion reconnect.
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest a build may run, covering the first-call repeat on a listed mediator;
/// a build still running then is aborted and fails, and the clients it has not
/// installed are shut down.
const BUILD_TIMEOUT: Duration = Duration::from_secs(90);
/// Longest wait for the mediator to admit a fresh DID before a query is sent.
const QUERY_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(3);
/// Refusal returned while this node is in Standby.
const STANDBY_REFUSAL: &str = "this node is in Standby and does not open trust registry connections";

/// The clients a build has created and not yet installed. Dropping it shuts
/// them down, so a build aborted at `BUILD_TIMEOUT` does not leave a mediator
/// websocket competing with the next build for the same DID.
pub(super) struct BuildClients {
    label: String,
    atms: std::sync::Mutex<Vec<Arc<affinidi_messaging_sdk::ATM>>>,
}

impl BuildClients {
    fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
            atms: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(super) fn hold(
        &self,
        client: &crate::comm::didcomm::client::DIDCommClient,
    ) {
        self.atms
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::clone(client.atm()));
    }

    /// Hand the held clients over to the connection map, which closes them from here on.
    fn release(&self) {
        self.atms
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

impl Drop for BuildClients {
    fn drop(&mut self) {
        let atms = std::mem::take(
            self.atms
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if atms.is_empty() {
            return;
        }
        debug!("Shutting down {} uninstalled client(s) of the trust registry build for {}", atms.len(), self.label);
        #[cfg(test)]
        super::test_builds::record_shutdown(&self.label);
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        for atm in atms {
            runtime.spawn(async move { atm.graceful_shutdown().await });
        }
    }
}

/// Connection protocol message types
#[allow(dead_code)]
pub(crate) mod connection {
    pub const SETUP: &str = "https://affinidi.com/didcomm/protocols/connection/1.0/setup";
    pub const SETUP_RECEIVED: &str = "https://affinidi.com/didcomm/protocols/connection/1.0/setup/received";
    pub const SETUP_APPROVED: &str = "https://affinidi.com/didcomm/protocols/connection/1.0/setup/approved";
}

/// TR Admin Protocol message types
#[allow(dead_code)]
mod tr_admin {
    pub const CREATE_RECORD: &str = "https://affinidi.com/didcomm/protocols/tr-admin/1.0/create-record";
    pub const CREATE_RECORD_RESPONSE: &str =
        "https://affinidi.com/didcomm/protocols/tr-admin/1.0/create-record/response";
    pub const UPDATE_RECORD: &str = "https://affinidi.com/didcomm/protocols/tr-admin/1.0/update-record";
    pub const UPDATE_RECORD_RESPONSE: &str =
        "https://affinidi.com/didcomm/protocols/tr-admin/1.0/update-record/response";
    pub const DELETE_RECORD: &str = "https://affinidi.com/didcomm/protocols/tr-admin/1.0/delete-record";
    pub const DELETE_RECORD_RESPONSE: &str =
        "https://affinidi.com/didcomm/protocols/tr-admin/1.0/delete-record/response";
    pub const READ_RECORD: &str = "https://affinidi.com/didcomm/protocols/tr-admin/1.0/read-record";
    pub const READ_RECORD_RESPONSE: &str = "https://affinidi.com/didcomm/protocols/tr-admin/1.0/read-record/response";
    pub const LIST_RECORDS: &str = "https://affinidi.com/didcomm/protocols/tr-admin/1.0/list-records";
    pub const LIST_RECORDS_RESPONSE: &str = "https://affinidi.com/didcomm/protocols/tr-admin/1.0/list-records/response";
    pub const CREATE_REFERENCE_FIELD: &str =
        "https://affinidi.com/didcomm/protocols/tr-admin/1.0/create-reference-field";
    pub const UPDATE_REFERENCE_FIELD: &str =
        "https://affinidi.com/didcomm/protocols/tr-admin/1.0/update-reference-field";
}

/// Problem-report code a trust registry returns when a write collides with existing state.
pub const TR_CONFLICT_CODE: &str = "e.p.msg.conflict";

/// TRQP (Trust Registry Query Protocol) message types
#[allow(dead_code)]
mod trqp {
    pub const QUERY_AUTHORIZATION: &str = "https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization";
    pub const QUERY_AUTHORIZATION_RESPONSE: &str =
        "https://affinidi.com/didcomm/protocols/trqp/1.0/query-authorization/response";
    pub const QUERY_RECOGNITION: &str = "https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition";
    pub const QUERY_RECOGNITION_RESPONSE: &str =
        "https://affinidi.com/didcomm/protocols/trqp/1.0/query-recognition/response";
    pub const SEARCH: &str = "https://affinidi.com/didcomm/protocols/trqp/1.0/search";
}

// =============================================================================
// Connection Types
// =============================================================================

/// Result of a successful OOB acceptance and connection establishment
pub struct OobConnectionInfo {
    /// The gateway's per-registry did:web
    pub our_did: String,
    /// The trust registry's secure DID (from connection-accepted)
    pub registry_did: String,
    /// Mediator URL extracted from the OOB invitation
    pub mediator_url: String,
    /// Mediator DID resolved from the mediator URL
    pub mediator_did: String,
    /// The canonical DID of the trust registry (from OOB URL `main_did` query param)
    pub main_did: Option<String>,
    /// Reports `creation_failed` for `our_did` unless the caller reports `created`
    /// once the registry's record is saved.
    pub announcement: crate::event_hook::CreationGuard,
}

/// Parsed data from an OOB invitation URL
struct ParsedOobInvitation {
    /// The inviter's DID (from the OOB invitation `from` field)
    inviter_did: String,
    /// Mediator DID resolved from the mediator URL
    mediator_did: String,
    /// Mediator URL extracted from the OOB invitation URL path
    mediator_url: String,
    /// The canonical DID of the trust registry (from OOB URL `main_did` query param, base64-decoded)
    main_did: Option<String>,
}

/// An active per-registry connection to a trust registry
#[derive(Clone)]
pub(crate) struct TrustRegistryConnection {
    /// Trust registry ID
    pub(crate) trust_registry_id: String,
    /// Our per-registry did:web
    pub(crate) our_did: String,
    /// The trust registry's DID (target for messages)
    pub(crate) registry_did: String,
    /// The canonical DID of the trust registry (used for connection lookup by DID)
    pub(crate) main_did: Option<String>,
    /// Mediator DID for routing
    pub(crate) mediator_did: String,
    /// Whether this is a temporary connection for querying public registries
    #[allow(dead_code)]
    pub(crate) is_temporary: bool,
    /// DIDComm client (wraps ATM + profile)
    pub(crate) client: crate::comm::didcomm::client::DIDCommClient,
    /// In-flight query response waiters keyed by DIDComm thread id (`thid`).
    /// Shared across clones so the single stream reader can deliver a response
    /// to whichever `send_and_await` call registered that thread.
    pub(crate) response_waiters: ResponseWaiters,
    /// The threads of this connection's latest queries that timed out.
    pub(crate) timed_out_queries: TimedOutQueries,
}

/// Maps an in-flight query's `thid` to the oneshot that its `send_and_await`
/// caller is awaiting. The stream reader delivers responses here.
pub(crate) type ResponseWaiters = Arc<Mutex<HashMap<String, oneshot::Sender<PollResult>>>>;

/// How many of a connection's latest timed-out query threads are remembered.
const TIMED_OUT_QUERIES_KEPT: usize = 256;

/// The latest query threads of a connection that timed out, so the reader can
/// tell a late reply to one of them from the registry rejecting the gateway.
#[derive(Clone, Default)]
pub(crate) struct TimedOutQueries(Arc<std::sync::Mutex<std::collections::VecDeque<String>>>);

impl TimedOutQueries {
    pub(crate) fn record(
        &self,
        thid: &str,
    ) {
        let mut threads = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if threads.len() == TIMED_OUT_QUERIES_KEPT {
            threads.pop_front();
        }
        threads.push_back(thid.to_string());
    }

    pub(crate) fn contains(
        &self,
        thid: &str,
    ) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|query| query == thid)
    }
}

/// A query thread that `send_and_await` is waiting on. Unless a response was
/// delivered to it, dropping it records the thread as timed out and only then
/// removes its waiter, so a late reply is never taken for the registry rejecting
/// the gateway, however the query was abandoned: by its own deadline, by a
/// caller's outer timeout dropping the future, or by the reader closing.
struct PendingQuery {
    waiters: ResponseWaiters,
    timed_out_queries: TimedOutQueries,
    thid: String,
    answered: bool,
}

impl Drop for PendingQuery {
    fn drop(&mut self) {
        if self.answered {
            return;
        }
        self.timed_out_queries
            .record(&self.thid);
        if let Ok(mut waiters) = self.waiters.try_lock() {
            waiters.remove(&self.thid);
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let (waiters, thid) = (self.waiters.clone(), std::mem::take(&mut self.thid));
            runtime.spawn(async move {
                waiters
                    .lock()
                    .await
                    .remove(&thid);
            });
        }
    }
}

/// Register a waiter for `thid`, returning the receiver the caller awaits.
async fn register_waiter_in(
    waiters: &ResponseWaiters,
    thid: String,
) -> oneshot::Receiver<PollResult> {
    let (tx, rx) = oneshot::channel();
    waiters
        .lock()
        .await
        .insert(thid, tx);
    rx
}

/// Deliver a response to the waiter for `thid`. Returns `true` when a waiter
/// was found and the value was sent (i.e. the receiver had not been dropped).
async fn deliver_response_in(
    waiters: &ResponseWaiters,
    thid: &str,
    result: PollResult,
) -> bool {
    let sender = waiters
        .lock()
        .await
        .remove(thid);
    match sender {
        Some(tx) => tx.send(result).is_ok(),
        None => false,
    }
}

impl TrustRegistryConnection {
    /// Register a waiter for `thid`, returning the receiver the caller awaits.
    async fn register_waiter(
        &self,
        thid: String,
    ) -> oneshot::Receiver<PollResult> {
        register_waiter_in(&self.response_waiters, thid).await
    }

    /// Deliver a response to the waiter registered for `thid`. Returns `true`
    /// when a waiter was found (and consumed), `false` otherwise.
    pub(crate) async fn deliver_response(
        &self,
        thid: &str,
        result: PollResult,
    ) -> bool {
        deliver_response_in(&self.response_waiters, thid, result).await
    }

    /// Drop every pending waiter so their receivers resolve with a
    /// `RecvError`. Called when the stream reader exits (disconnect) so
    /// outstanding queries fail fast instead of blocking until timeout.
    pub(crate) async fn fail_all_waiters(&self) {
        self.response_waiters
            .lock()
            .await
            .clear();
    }

    /// Fail every pending waiter and stop this connection's mediator websocket.
    ///
    /// Dropping the client is not enough: the SDK keeps its websocket task
    /// alive and reconnecting, so a replaced or removed connection that is not
    /// closed competes with its successor for the mediator's single websocket
    /// per DID.
    async fn close(&self) {
        self.fail_all_waiters().await;
        let atm = Arc::clone(self.client.atm());
        let shutdown = tokio::spawn(async move { atm.graceful_shutdown().await });
        if tokio::time::timeout(CLOSE_TIMEOUT, shutdown)
            .await
            .is_err()
        {
            warn!(
                "Trust registry '{}': websocket shutdown still running after {:?}, continuing in the background",
                self.trust_registry_id, CLOSE_TIMEOUT
            );
        }
    }

    /// Whether `other` is this same connection, i.e. shares its DIDComm client.
    fn is_same_client(
        &self,
        other: &TrustRegistryConnection,
    ) -> bool {
        Arc::ptr_eq(self.client.atm(), other.client.atm())
    }

    /// Whether this connection is addressed to `did`, by its canonical or transport DID.
    fn serves(
        &self,
        did: &str,
    ) -> bool {
        self.main_did.as_deref() == Some(did) || self.registry_did == did
    }

    /// Whether `other` is addressed to the same trust registry.
    fn serves_same_registry(
        &self,
        other: &TrustRegistryConnection,
    ) -> bool {
        self.serves(&other.registry_did)
            || other
                .main_did
                .as_deref()
                .is_some_and(|did| self.serves(did))
    }
}

/// Error type for trust registry communication
#[derive(Clone, Debug, Error)]
pub enum TrustRegistryError {
    #[error("Trust registry not found: {0}")]
    NotFound(String),
    #[error("No connection established: {0}")]
    NoConnection(String),
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Send error: {0}")]
    SendError(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Problem report [{0}]: {1}")]
    ProblemReport(String, String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Stale connection: {0}")]
    StaleConnection(String),
}

impl TrustRegistryError {
    /// True only for a problem report carrying exactly [`TR_CONFLICT_CODE`].
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::ProblemReport(code, _) if code == TR_CONFLICT_CODE)
    }
}

fn problem_report_error(body: serde_json::Value) -> TrustRegistryError {
    match serde_json::from_value::<TrProblemReport>(body) {
        Ok(problem) => TrustRegistryError::ProblemReport(problem.code, problem.comment),
        Err(e) => TrustRegistryError::ParseError(format!("Failed to parse problem report: {}", e)),
    }
}

/// Deserialise a registry response into the expected typed shape, returning
/// a [`TrustRegistryError::ParseError`] with a terse message. The raw
/// response body is logged separately at `debug!` (capped to 512 bytes)
/// so operators can distinguish schema drift, an unexpected error envelope,
/// or a `{}` reply from each other by raising the log level — without
/// leaking response bodies into error strings that may reach clients or
/// audit trails.
fn parse_registry_response<T: serde::de::DeserializeOwned>(
    response: serde_json::Value
) -> Result<T, TrustRegistryError> {
    serde_json::from_value::<T>(response.clone()).map_err(|e| {
        let preview = build_body_preview(&response);
        debug!(body = %preview, "TRQP response parse failure");
        TrustRegistryError::ParseError(format!("Failed to parse response: {}", e))
    })
}

/// Truncated, UTF-8-safe JSON preview of a registry response body, capped
/// at 512 bytes so a pathological reply can't blow up log lines.
fn build_body_preview(response: &serde_json::Value) -> String {
    let mut preview = serde_json::to_string(response).unwrap_or_else(|_| "<unprintable>".to_string());
    const MAX_PREVIEW_BYTES: usize = 512;
    if preview.len() > MAX_PREVIEW_BYTES {
        let mut end = MAX_PREVIEW_BYTES;
        while end > 0 && !preview.is_char_boundary(end) {
            end -= 1;
        }
        preview.truncate(end);
        preview.push_str("…(truncated)");
    }
    preview
}

/// True only when the body is a **literal** JSON object with zero keys
/// (`{}`). Used by the TRQP query paths as the sentinel some registries
/// emit on the "no matching record" case (spec violation, tolerated by
/// the gateway). Every other shape (`null`, `[]`, non-object, object
/// with echoed fields but no boolean) is deliberately NOT matched here
/// so genuine schema drift still surfaces as
/// [`TrustRegistryError::ParseError`].
fn is_empty_object(response: &serde_json::Value) -> bool {
    response
        .as_object()
        .is_some_and(|obj| obj.is_empty())
}

/// Poll the connection's preflight until the WebSocket is ready or attempts are exhausted.
pub(crate) async fn await_websocket_ready(client: &crate::comm::didcomm::client::DIDCommClient) {
    for attempt in 0..WS_READY_MAX_ATTEMPTS {
        if client
            .preflight_check(WS_READY_CHECK_TIMEOUT)
            .await
            .is_ok()
        {
            return;
        }
        if attempt + 1 < WS_READY_MAX_ATTEMPTS {
            tokio::time::sleep(WS_READY_RETRY_DELAY).await;
        }
    }
}

// =============================================================================
// Connection ownership
// =============================================================================

/// What a build is for: a stored registry by ID, or a temporary connection to a
/// public registry by its DID. At most one build runs per key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum BuildKey {
    Stored(String),
    Temporary(String),
}

/// How a build obtains its client.
enum BuildPlan {
    /// From the registry's stored keys. A Failed registry is rebuilt only when
    /// `allow_failed` is set, which only a manual reconnect does.
    Stored { allow_failed: bool },
    /// By accepting the registry's OOB invitation under a new identity.
    Oob { oob_url: String, did_method: DidMethod, extras: oneshot::Sender<OobExtras> },
    /// Under a throwaway identity, for a registry DID no stored registry has.
    Temporary,
}

impl BuildPlan {
    /// Whether a live client for the key satisfies the request instead of a build.
    fn accepts_current(&self) -> bool {
        !matches!(self, Self::Oob { .. })
    }
}

/// The parts of an OOB acceptance that do not live on the connection.
struct OobExtras {
    mediator_url: String,
    announcement: crate::event_hook::CreationGuard,
}

type BuildOutcome = Result<TrustRegistryConnection, TrustRegistryError>;

/// A failed build, and whether the registry is retried in the background.
struct BuildFailure {
    error: TrustRegistryError,
    retry: bool,
}

impl BuildFailure {
    fn retry(error: TrustRegistryError) -> Self {
        Self { error, retry: true }
    }

    fn fatal(error: TrustRegistryError) -> Self {
        Self { error, retry: false }
    }
}

/// Builds in flight, and registries deleted while this process runs.
#[derive(Default)]
struct Ownership {
    builds: HashMap<BuildKey, watch::Receiver<Option<BuildOutcome>>>,
    deleted: HashSet<String>,
}

/// The scheduled background retry of a stored registry whose last build failed.
struct Retry {
    failures: u64,
    task: tokio::task::AbortHandle,
}

/// The live client a request can use, or the build it waits for.
enum Pending {
    Ready(TrustRegistryConnection),
    Building(watch::Receiver<Option<BuildOutcome>>),
}

// =============================================================================
// Listener Manager
// =============================================================================

/// Manages per-registry DIDComm connections to trust registries.
///
/// Each trust registry gets its own connection with a unique did:web identity.
/// Connections are keyed by trust registry ID.
///
/// The manager is the only owner of those connections: every client is built
/// by one build per registry, which callers request and wait for, and installed
/// only while the node is Active and the registry is not deleted.
pub struct TrustRegistryListenerManager {
    /// Active connections keyed by trust registry ID
    connections: Arc<RwLock<HashMap<String, TrustRegistryConnection>>>,
    /// Domain for generating did:web identities
    domain: String,
    /// Base storage path for trust registry keys
    storage_path: PathBuf,
    /// Shared encrypted secrets store for per-registry DIDComm keys
    secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    /// Default timeout for waiting on responses
    default_timeout: Duration,
    /// Optional trust registry store for reconnecting from persisted state
    store: RwLock<Option<Arc<dyn TrustRegistryStore>>>,
    /// DID:webvh identity store (shared with channel identity system)
    #[cfg(feature = "didwebvh")]
    didwebvh_identity_store: RwLock<Option<Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>>,
    /// DID:webvh log storage (shared with channel identity system)
    #[cfg(feature = "didwebvh")]
    didwebvh_log_storage: RwLock<Option<Arc<dyn crate::storage::DidLogStorage>>>,
    /// Dashboard WebSocket broadcaster for connection-status changes, used by
    /// the per-connection stream readers.
    ws_state: RwLock<Option<crate::server::websocket::WsState>>,
    /// Per-registry stream reader tasks keyed by trust registry ID. Each reader
    /// is the sole consumer of its connection's mediator websocket.
    readers: Arc<RwLock<HashMap<String, tokio::task::AbortHandle>>>,
    /// Whether connections may be established; false while in Standby mode.
    listeners_active: Arc<AtomicBool>,
    /// Reports each stored registry's DID to the event hook receiver.
    event_hook: std::sync::OnceLock<Arc<crate::event_hook::EventHook>>,
    /// Tells whether a registry's mediator is one the directory lists.
    mediator_directory: std::sync::OnceLock<Arc<crate::event_hook::MediatorDirectory>>,
    /// Builds in flight and deleted registries. A client is installed only
    /// while this lock is held.
    ownership: Mutex<Ownership>,
    /// Background retries keyed by trust registry ID.
    retries: Mutex<HashMap<String, Retry>>,
    retry_policy: ReconnectPolicy,
    self_ref: Weak<Self>,
}

impl TrustRegistryListenerManager {
    /// Create a listener manager that retries failed builds by `retry_policy`.
    pub(crate) fn with_retry_policy(
        domain: String,
        storage_path: PathBuf,
        secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
        retry_policy: ReconnectPolicy,
    ) -> Arc<Self> {
        Arc::new_cyclic(|self_ref| Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            domain,
            storage_path,
            secrets_store,
            default_timeout: Duration::from_secs(10),
            store: RwLock::new(None),
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: RwLock::new(None),
            #[cfg(feature = "didwebvh")]
            didwebvh_log_storage: RwLock::new(None),
            ws_state: RwLock::new(None),
            readers: Arc::new(RwLock::new(HashMap::new())),
            listeners_active: Arc::new(AtomicBool::new(true)),
            event_hook: std::sync::OnceLock::new(),
            mediator_directory: std::sync::OnceLock::new(),
            ownership: Mutex::new(Ownership::default()),
            retries: Mutex::new(HashMap::new()),
            retry_policy,
            self_ref: self_ref.clone(),
        })
    }

    /// Attach the event hook and the mediator directory, so a stored registry's DID
    /// is announced before the gateway first contacts its mediator.
    pub fn set_event_hook(
        &self,
        hook: Option<Arc<crate::event_hook::EventHook>>,
        directory: Option<Arc<crate::event_hook::MediatorDirectory>>,
    ) {
        if let Some(hook) = hook {
            let _ = self.event_hook.set(hook);
        }
        if let Some(directory) = directory {
            let _ = self
                .mediator_directory
                .set(directory);
        }
    }

    /// Tell the event hook receiver that `trust_registry`'s DID is no longer used.
    pub fn announce_deleted(
        &self,
        trust_registry: &super::types::TrustRegistry,
    ) {
        if let (Some(hook), Some(our_did), Some(mediator_did)) =
            (self.event_hook.get(), &trust_registry.our_did, &trust_registry.mediator_did)
        {
            hook.emit(
                crate::event_hook::EventKind::Deleted,
                trust_registry_payload(&trust_registry.id, mediator_did, our_did),
            );
        }
    }

    /// Set the trust registry store for reconnecting from persisted state.
    /// Called after the store is initialized in the orchestrator.
    pub async fn set_store(
        &self,
        store: Arc<dyn TrustRegistryStore>,
    ) {
        *self.store.write().await = Some(store);
    }

    /// Return the currently attached trust-registry store, if any.
    /// Used by the Trust Recorder stage to resolve `trust_registry_id` →
    /// TR DID without re-plumbing the store as a separate dependency.
    pub async fn store(&self) -> Option<Arc<dyn TrustRegistryStore>> {
        self.store
            .read()
            .await
            .clone()
    }

    /// Attach the dashboard WebSocket broadcaster so stream readers can push
    /// connection-status changes. Called once during orchestrator init.
    pub async fn set_ws_state(
        &self,
        ws_state: crate::server::websocket::WsState,
    ) {
        *self.ws_state.write().await = Some(ws_state);
    }

    /// Ensure a stream reader is running for `trust_registry_id` (idempotent).
    ///
    /// The reader is the sole consumer of the connection's mediator websocket:
    /// it demultiplexes query responses to `send_and_await` waiters and drives
    /// setup/approval status transitions. Safe to call after every
    /// connection-creation site; a second call while a reader is live is a no-op.
    pub(crate) async fn spawn_reader(
        &self,
        trust_registry_id: &str,
    ) {
        let mut readers = self.readers.write().await;
        if readers.contains_key(trust_registry_id) {
            return;
        }

        let connections = self.connections.clone();
        let store = self
            .store
            .read()
            .await
            .clone();
        let ws_state = self
            .ws_state
            .read()
            .await
            .clone();
        let tr_id = trust_registry_id.to_string();
        let readers_ref = self.readers.clone();
        let tr_id_for_task = tr_id.clone();

        let handle = tokio::spawn(async move {
            super::reader::run(connections, tr_id_for_task.clone(), store, ws_state).await;
            readers_ref
                .write()
                .await
                .remove(&tr_id_for_task);
        });

        readers.insert(tr_id, handle.abort_handle());
    }

    /// Abort the stream reader for `trust_registry_id`, if one is running.
    pub(crate) async fn stop_reader(
        &self,
        trust_registry_id: &str,
    ) {
        if let Some(handle) = self
            .readers
            .write()
            .await
            .remove(trust_registry_id)
        {
            handle.abort();
            debug!("TR reader: aborted for '{}'", trust_registry_id);
        }
    }

    pub fn is_active(&self) -> bool {
        self.listeners_active
            .load(Ordering::SeqCst)
    }

    pub fn activate(&self) {
        let was_active = self
            .listeners_active
            .swap(true, Ordering::SeqCst);
        if !was_active {
            info!("Trust registry listeners activated");
        }
    }

    pub fn deactivate(&self) {
        let was_active = self
            .listeners_active
            .swap(false, Ordering::SeqCst);
        if was_active {
            info!("Trust registry listeners deactivated");
        }
    }

    /// Migrates every `did:webvh` registry's DIDComm key off the operator-facing secrets
    /// store onto disk. Idempotent; returns the count migrated. Post-fix registries are no-ops.
    #[cfg(feature = "didwebvh")]
    pub async fn migrate_didcomm_secrets_to_disk(&self) -> usize {
        let store = match self
            .store
            .read()
            .await
            .as_ref()
        {
            Some(store) => store.clone(),
            None => return 0,
        };
        let identity_store = match self
            .didwebvh_identity_store
            .read()
            .await
            .as_ref()
        {
            Some(id_store) => id_store.clone(),
            None => return 0,
        };
        let Some(secrets_store) = self.secrets_store.clone() else {
            return 0;
        };

        let registries = match store.list_all().await {
            Ok(registries) => registries,
            Err(e) => {
                error!("Trust registry: failed to list registries for secret migration: {}", e);
                return 0;
            }
        };

        let mut migrated = 0usize;
        for tr in registries {
            let Some(our_did) = tr.our_did.as_deref() else {
                continue;
            };
            if !our_did.starts_with("did:webvh:") {
                continue;
            }
            match super::did_manager::migrate_didcomm_secret_to_disk(
                &identity_store,
                &secrets_store,
                &self.storage_path,
                &tr.id,
                our_did,
            )
            .await
            {
                Ok(true) => migrated += 1,
                Ok(false) => {}
                Err(e) => warn!("Trust registry: secret migration failed for '{}': {}", tr.id, e),
            }
        }
        migrated
    }

    /// Reconnect every reconnectable trust registry from persisted state.
    /// Idempotent: registries that already have a live connection are skipped.
    /// Returns the number of registries newly reconnected.
    pub async fn reconnect_all_from_store(&self) -> usize {
        // Runs before reconnect so migrated webvh keys load from disk below.
        #[cfg(feature = "didwebvh")]
        {
            let migrated = self
                .migrate_didcomm_secrets_to_disk()
                .await;
            if migrated > 0 {
                info!("Trust registry: migrated {} DIDComm secret(s) off the secrets store to disk", migrated);
            }
        }

        let store = {
            let guard = self.store.read().await;
            match guard.as_ref() {
                Some(store) => store.clone(),
                None => {
                    warn!("Trust registry: reconnection skipped, no store configured");
                    return 0;
                }
            }
        };

        let registries = match store.list_all().await {
            Ok(registries) => registries,
            Err(e) => {
                error!("Trust registry: failed to list registries for reconnection: {}", e);
                return 0;
            }
        };

        let mut reconnected = 0usize;
        for tr in registries {
            if !matches!(
                tr.connection_status,
                TrustRegistryConnectionStatus::Connected
                    | TrustRegistryConnectionStatus::AwaitingApproval
                    | TrustRegistryConnectionStatus::Connecting
            ) {
                continue;
            }

            if self
                .connections
                .read()
                .await
                .contains_key(&tr.id)
            {
                continue;
            }

            if tr.our_did.is_none() || tr.registry_did.is_none() || tr.mediator_did.is_none() {
                warn!(
                    "Trust registry: skipping reconnect for '{}' ({:?}), missing DID fields",
                    tr.id, tr.connection_status
                );
                continue;
            }

            let outcome = match self
                .request_build(BuildKey::Stored(tr.id.clone()), BuildPlan::Stored { allow_failed: false }, None)
                .await
            {
                Ok(pending) => Self::await_build(pending, Some(Instant::now() + RECONNECT_TIMEOUT)).await,
                Err(e) => Err(e),
            };
            match outcome {
                Ok(_) => {
                    info!("🔗 Trust registry: reconnected to '{}'", tr.id);
                    reconnected += 1;
                }
                Err(e) => warn!("Trust registry: reconnect failed for '{}': {}", tr.id, e),
            }
        }

        reconnected
    }

    /// Close every connection and stop every background retry. Call after
    /// [`Self::deactivate`]: a build that finishes afterwards sees the node
    /// inactive and closes its client instead of installing it.
    pub async fn disconnect_all(&self) -> usize {
        drop(self.ownership.lock().await);
        for (_, retry) in self
            .retries
            .lock()
            .await
            .drain()
        {
            retry.task.abort();
        }
        let ids: Vec<String> = self
            .connections
            .read()
            .await
            .keys()
            .cloned()
            .collect();
        let count = ids.len();
        futures::future::join_all(
            ids.iter()
                .map(|id| self.remove_connection(id)),
        )
        .await;
        count
    }

    /// Set the DID:webvh stores for identity creation.
    /// Called after the stores are initialized in the orchestrator.
    #[cfg(feature = "didwebvh")]
    pub async fn set_didwebvh_stores(
        &self,
        identity_store: Option<Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
        log_storage: Option<Arc<dyn crate::storage::DidLogStorage>>,
    ) {
        *self
            .didwebvh_identity_store
            .write()
            .await = identity_store;
        *self
            .didwebvh_log_storage
            .write()
            .await = log_storage;
    }

    // =========================================================================
    // OOB Acceptance & Connection
    // =========================================================================

    /// Accept an OOB invitation from a trust registry and establish a connection.
    ///
    /// 1. Parses the OOB invitation URL to extract inviter's DID and mediator
    /// 2. Generates a per-registry did:web identity
    /// 3. Creates ATM instance and connects to the mediator
    /// 4. Sends connection-setup message with our secure DID
    /// 5. Polls for connection-accepted response with registry's secure DID
    /// 6. Registers the connection for future message exchange
    ///
    /// The owner runs the acceptance as the registry's build, so it is refused
    /// on a Standby node or for a deleted registry.
    pub async fn accept_oob_and_connect(
        &self,
        trust_registry_id: &str,
        oob_url: &str,
        did_method: &DidMethod,
    ) -> Result<OobConnectionInfo, TrustRegistryError> {
        let (extras_tx, extras_rx) = oneshot::channel();
        let plan = BuildPlan::Oob {
            oob_url: oob_url.to_string(),
            did_method: did_method.clone(),
            extras: extras_tx,
        };
        let pending = self
            .request_build(BuildKey::Stored(trust_registry_id.to_string()), plan, None)
            .await?;
        let connection = Self::await_build(pending, None).await?;
        let extras = extras_rx.await.map_err(|_| {
            TrustRegistryError::ConnectionError(format!(
                "trust registry '{}' was connected by another build",
                trust_registry_id
            ))
        })?;
        Ok(OobConnectionInfo {
            our_did: connection.our_did,
            registry_did: connection.registry_did,
            mediator_url: extras.mediator_url,
            mediator_did: connection.mediator_did,
            main_did: connection.main_did,
            announcement: extras.announcement,
        })
    }

    /// Accept the OOB invitation and send connection-setup, returning the
    /// connection for the owner to install.
    async fn connect_oob(
        &self,
        trust_registry_id: &str,
        oob_url: &str,
        did_method: &DidMethod,
        clients: &BuildClients,
    ) -> Result<(TrustRegistryConnection, OobExtras), TrustRegistryError> {
        #[cfg(test)]
        if let Some(built) = super::test_builds::run(trust_registry_id, clients).await {
            let client = built.map_err(TrustRegistryError::ConnectionError)?;
            let our_did = format!("did:example:gateway-{}", trust_registry_id);
            let mediator_did = "did:example:mediator".to_string();
            let announcement = crate::event_hook::CreationGuard::start(
                self.event_hook.get().cloned(),
                trust_registry_payload(trust_registry_id, &mediator_did, &our_did),
            );
            let connection = TrustRegistryConnection {
                trust_registry_id: trust_registry_id.to_string(),
                our_did,
                registry_did: format!("did:example:registry-{}", trust_registry_id),
                main_did: None,
                mediator_did,
                is_temporary: false,
                client,
                response_waiters: Arc::new(Mutex::new(HashMap::new())),
                timed_out_queries: TimedOutQueries::default(),
            };
            let extras = OobExtras {
                mediator_url: "https://mediator.example".to_string(),
                announcement,
            };
            return Ok((connection, extras));
        }

        info!("Accepting OOB invitation for trust registry '{}': {}", trust_registry_id, oob_url);

        // Step 1: Fetch and parse OOB invitation
        let parsed_oob = parse_oob_invitation(oob_url)
            .await
            .map_err(|e| TrustRegistryError::ConnectionError(format!("Failed to parse OOB invitation: {}", e)))?;

        let inviter_did = parsed_oob.inviter_did;
        let mediator_did = parsed_oob.mediator_did;
        let mediator_url = parsed_oob.mediator_url;
        let main_did = parsed_oob.main_did;

        info!(
            "OOB invitation parsed:\n  Inviter DID: {}\n  Mediator DID: {}\n  Mediator URL: {}\n  Main DID: {:?}",
            inviter_did, mediator_did, mediator_url, main_did
        );

        // Step 2: Generate per-registry identity
        let (our_did, secrets, did_doc) = generate_trust_registry_identity(
            trust_registry_id,
            &self.domain,
            &self.storage_path,
            &mediator_url,
            &mediator_did,
            did_method.clone(),
            #[cfg(feature = "didwebvh")]
            self.didwebvh_identity_store
                .read()
                .await
                .clone(),
            #[cfg(feature = "didwebvh")]
            self.didwebvh_log_storage
                .read()
                .await
                .clone(),
        )
        .await
        .map_err(|e| TrustRegistryError::ConnectionError(format!("Failed to generate identity: {}", e)))?;

        info!("Generated per-registry identity: {}", our_did);

        // A retried setup can reuse the registry's DID, and the mediator allows
        // one websocket per DID.
        self.remove_connection(trust_registry_id)
            .await;

        let announcement = crate::event_hook::CreationGuard::start(
            self.event_hook.get().cloned(),
            trust_registry_payload(trust_registry_id, &mediator_did, &our_did),
        );
        let first_call_retry = crate::gateways::connection_points::first_call_retry::policy_for_listed(
            self.mediator_directory.get(),
            &mediator_did,
        )
        .await;

        // Step 3: Create DIDComm client and connect (pre-cache our DID doc to avoid HTTPS resolution)
        let client = create_tr_client(
            trust_registry_id,
            &our_did,
            &mediator_did,
            &secrets,
            Some((&our_did, &did_doc)),
            first_call_retry,
            clients,
        )
        .await
        .map_err(TrustRegistryError::ConnectionError)?;

        // Set ACL to allow messages from the trust registry
        set_acl_to_allow_everything_and_more(client.atm(), client.profile().clone())
            .await
            .map_err(|e| {
                warn!("Could not set ACL for trust registry: {:?}", e);
            })
            .ok();

        // Step 4: Send connection-setup message
        let setup_body = json!({
            "channel_did": our_did,
        });

        let message_id = uuid::Uuid::new_v4().to_string();
        let thread_id = uuid::Uuid::new_v4().to_string();

        let message = DIDCommMessage::build(message_id.clone(), connection::SETUP.to_string(), setup_body)
            .from(our_did.clone())
            .to(inviter_did.clone())
            .thid(thread_id.clone())
            .finalize();

        info!("Sending connection-setup to {} (thid: {})", inviter_did, thread_id);

        if let Err(e) = crate::comm::didcomm::trust_registry::pack_and_forward(
            &client,
            &message,
            &our_did,
            &inviter_did,
            &mediator_did,
        )
        .await
        {
            client
                .atm()
                .graceful_shutdown()
                .await;
            return Err(TrustRegistryError::SendError(e));
        }

        info!("✓ Connection setup sent to trust registry");

        // Step 5: Register the connection using the inviter DID as the registry DID.
        // The trust registry will process the setup asynchronously (approval flow).
        let connection = TrustRegistryConnection {
            trust_registry_id: trust_registry_id.to_string(),
            our_did,
            registry_did: inviter_did,
            main_did,
            mediator_did,
            is_temporary: false,
            client,
            response_waiters: Arc::new(Mutex::new(HashMap::new())),
            timed_out_queries: TimedOutQueries::default(),
        };

        info!("🔗 Trust registry '{}' connection established — awaiting registry-side approval", trust_registry_id);

        Ok((connection, OobExtras { mediator_url, announcement }))
    }

    /// Rebuild a stored registry's client from its stored keys, for a manual
    /// reconnect. Replaces the current client even when it looks healthy, joins a
    /// build already running, ignores the background backoff and restarts it.
    /// A Failed registry is rebuilt too. The identity is never changed.
    pub async fn reconnect(
        &self,
        trust_registry_id: &str,
    ) -> Result<TrustRegistryConnection, TrustRegistryError> {
        debug!("Reconnecting to trust registry '{}'", trust_registry_id);
        self.clear_retry(trust_registry_id)
            .await;
        let current = self
            .connections
            .read()
            .await
            .get(trust_registry_id)
            .cloned();
        let pending = self
            .request_build(
                BuildKey::Stored(trust_registry_id.to_string()),
                BuildPlan::Stored { allow_failed: true },
                current.as_ref(),
            )
            .await?;
        Self::await_build(pending, Some(Instant::now() + RECONNECT_TIMEOUT)).await
    }

    /// Build a stored registry's client from its stored keys. The current
    /// client is closed only once the keys load, because the mediator allows one
    /// websocket per DID.
    async fn connect_stored(
        &self,
        registry: &super::types::TrustRegistry,
        clients: &BuildClients,
    ) -> Result<TrustRegistryConnection, BuildFailure> {
        let (Some(our_did), Some(registry_did), Some(mediator_did)) = (
            registry.our_did.as_deref(),
            registry
                .registry_did
                .as_deref(),
            registry
                .mediator_did
                .as_deref(),
        ) else {
            return Err(BuildFailure::fatal(TrustRegistryError::ConnectionError(format!(
                "trust registry '{}' has no stored identity; delete and recreate it",
                registry.id
            ))));
        };
        let connection = |client| TrustRegistryConnection {
            trust_registry_id: registry.id.clone(),
            our_did: our_did.to_string(),
            registry_did: registry_did.to_string(),
            main_did: registry.main_did.clone(),
            mediator_did: mediator_did.to_string(),
            is_temporary: false,
            client,
            response_waiters: Arc::new(Mutex::new(HashMap::new())),
            timed_out_queries: TimedOutQueries::default(),
        };

        #[cfg(test)]
        if let Some(built) = super::test_builds::run(&registry.id, clients).await {
            self.remove_connection(&registry.id)
                .await;
            return built
                .map(connection)
                .map_err(|e| BuildFailure::retry(TrustRegistryError::ConnectionError(e)));
        }

        let (secrets, did_doc_to_cache) = self
            .load_stored_secrets(&registry.id, our_did, mediator_did)
            .await
            .map_err(BuildFailure::fatal)?;

        self.remove_connection(&registry.id)
            .await;

        let client = create_tr_client(
            &registry.id,
            our_did,
            mediator_did,
            &secrets,
            did_doc_to_cache
                .as_ref()
                .map(|doc| (our_did, doc)),
            FirstCallRetry::never(),
            clients,
        )
        .await
        .map_err(|e| BuildFailure::retry(TrustRegistryError::ConnectionError(e)))?;

        set_acl_to_allow_everything_and_more(client.atm(), client.profile().clone())
            .await
            .map_err(|e| {
                warn!("Could not set ACL for trust registry reconnection: {:?}", e);
            })
            .ok();

        Ok(connection(client))
    }

    /// Load a stored registry's DIDComm keys and the DID document to pre-cache.
    async fn load_stored_secrets(
        &self,
        trust_registry_id: &str,
        our_did: &str,
        mediator_did: &str,
    ) -> Result<(Vec<Secret>, Option<serde_json::Value>), TrustRegistryError> {
        // For did:webvh identities, prefer key material persisted on disk (parity
        // with connection points and did:web/did:peer). Registries created before
        // this kept the X25519 in the shared secrets store, so fall back to the
        // identity store when no disk key files exist.
        #[cfg(feature = "didwebvh")]
        let webvh_data = if our_did.starts_with("did:webvh:") {
            if let Ok(secrets) = load_trust_registry_secrets(trust_registry_id, &self.storage_path).await {
                let did_doc =
                    super::did_manager::build_did_web_document(our_did, &secrets, mediator_did).map_err(|e| {
                        TrustRegistryError::ConnectionError(format!("Failed to build DIDComm DID document: {}", e))
                    })?;
                Some((secrets, did_doc))
            } else {
                let identity_store = self
                    .didwebvh_identity_store
                    .read()
                    .await
                    .clone();
                let log_storage = self
                    .didwebvh_log_storage
                    .read()
                    .await
                    .clone();
                let secrets_store = self.secrets_store.clone();

                match (identity_store, log_storage) {
                    (Some(id_store), Some(_log_store)) => {
                        let secrets = super::did_manager::derive_didcomm_secrets_from_identity_store(
                            &id_store,
                            secrets_store.as_ref(),
                            our_did,
                        )
                        .await
                        .map_err(|e| {
                            TrustRegistryError::ConnectionError(format!(
                                "Failed to derive secrets from identity store: {}",
                                e
                            ))
                        })?;
                        // Build DIDComm-compatible DID document from secrets (uses correct did:webvh IDs)
                        let did_doc = super::did_manager::build_did_web_document(our_did, &secrets, mediator_did)
                            .map_err(|e| {
                                TrustRegistryError::ConnectionError(format!(
                                    "Failed to build DIDComm DID document: {}",
                                    e
                                ))
                            })?;
                        Some((secrets, did_doc))
                    }
                    _ => {
                        warn!("DID:webvh stores not available for reconnect, falling back to disk");
                        None
                    }
                }
            }
        } else {
            None
        };

        #[cfg(feature = "didwebvh")]
        let (secrets, did_doc_to_cache) = if let Some((secrets, did_doc)) = webvh_data {
            (secrets, Some(did_doc))
        } else {
            let secrets = load_trust_registry_secrets(trust_registry_id, &self.storage_path)
                .await
                .map_err(|e| TrustRegistryError::ConnectionError(format!("Failed to load secrets: {}", e)))?;
            let did_doc_to_cache = crate::storage::did_artifacts::read_did_document(
                &self
                    .storage_path
                    .join(trust_registry_id),
            )
            .await
            .ok()
            .flatten()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok());
            (secrets, did_doc_to_cache)
        };

        #[cfg(not(feature = "didwebvh"))]
        let (secrets, did_doc_to_cache) = {
            let secrets = load_trust_registry_secrets(trust_registry_id, &self.storage_path)
                .await
                .map_err(|e| TrustRegistryError::ConnectionError(format!("Failed to load secrets: {}", e)))?;
            let did_doc_to_cache = crate::storage::did_artifacts::read_did_document(
                &self
                    .storage_path
                    .join(trust_registry_id),
            )
            .await
            .ok()
            .flatten()
            .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok());
            (secrets, did_doc_to_cache)
        };

        Ok((secrets, did_doc_to_cache))
    }

    /// Remove a connection by trust registry ID
    pub async fn remove_connection(
        &self,
        trust_registry_id: &str,
    ) {
        self.stop_reader(trust_registry_id)
            .await;
        let removed = {
            let mut connections = self.connections.write().await;
            connections.remove(trust_registry_id)
        };
        if let Some(connection) = removed {
            connection.close().await;
            info!("Removed connection for trust registry {}", trust_registry_id);
        }
    }

    /// Stop owning a deleted registry: builds still running for it close their
    /// client instead of installing it, later build requests are refused, its
    /// background retry stops, and its current connection is closed, failing the
    /// queries waiting on it.
    ///
    /// Returns once a build still running for it has finished, so its keys can
    /// be removed without that build writing them again.
    pub async fn delete_registry(
        &self,
        trust_registry_id: &str,
    ) {
        let running = {
            let mut ownership = self.ownership.lock().await;
            ownership
                .deleted
                .insert(trust_registry_id.to_string());
            ownership
                .builds
                .get(&BuildKey::Stored(trust_registry_id.to_string()))
                .cloned()
        };
        self.clear_retry(trust_registry_id)
            .await;
        self.remove_connection(trust_registry_id)
            .await;
        if let Some(running) = running {
            let _ = Self::await_build(Pending::Building(running), Some(Instant::now() + BUILD_TIMEOUT)).await;
        }
    }

    /// Own a registry again after its record could not be deleted, so the next
    /// query or reconnect can build it.
    pub async fn restore_registry(
        &self,
        trust_registry_id: &str,
    ) {
        self.ownership
            .lock()
            .await
            .deleted
            .remove(trust_registry_id);
    }

    /// Store `connection` under its registry id, closing any connection it
    /// replaces and stopping that connection's reader, and return the
    /// connection that now serves its registry. A stored registry's connection
    /// also replaces the temporary connections to the same registry DID, and a
    /// temporary connection is closed instead when a stored registry's
    /// connection already serves that DID. Refused, and the connection closed,
    /// while the node is Standby or the registry is deleted.
    async fn install_connection(
        &self,
        connection: TrustRegistryConnection,
    ) -> Result<TrustRegistryConnection, TrustRegistryError> {
        let ownership = self.ownership.lock().await;
        if connection.is_temporary
            && let Some(stored) = self
                .connections
                .read()
                .await
                .values()
                .find(|other| !other.is_temporary && other.serves_same_registry(&connection))
                .cloned()
        {
            drop(ownership);
            connection.close().await;
            return Ok(stored);
        }
        let refusal = if !self.is_active() {
            Some(TrustRegistryError::NoConnection(STANDBY_REFUSAL.to_string()))
        } else if !connection.is_temporary
            && ownership
                .deleted
                .contains(&connection.trust_registry_id)
        {
            Some(TrustRegistryError::NotFound(format!("trust registry '{}' was deleted", connection.trust_registry_id)))
        } else {
            None
        };
        if let Some(refusal) = refusal {
            drop(ownership);
            connection.close().await;
            return Err(refusal);
        }

        let displaced = {
            let mut connections = self.connections.write().await;
            let mut displaced: Vec<TrustRegistryConnection> = connections
                .values()
                .filter(|other| {
                    other.is_temporary
                        && other.trust_registry_id != connection.trust_registry_id
                        && other.serves_same_registry(&connection)
                })
                .cloned()
                .collect();
            for other in &displaced {
                connections.remove(&other.trust_registry_id);
            }
            displaced.extend(
                connections.insert(
                    connection
                        .trust_registry_id
                        .clone(),
                    connection.clone(),
                ),
            );
            displaced
        };
        drop(ownership);

        for replaced in displaced {
            self.stop_reader(&replaced.trust_registry_id)
                .await;
            replaced.close().await;
            debug!("Closed replaced connection for trust registry '{}'", replaced.trust_registry_id);
        }
        Ok(connection)
    }

    /// Look up a stored trust registry by DID (checks main_did, registry_did, did).
    /// Without a store no registry is stored; a store that cannot be read is an
    /// error, so a stored registry is never taken for a public one.
    async fn find_stored_trust_registry(
        &self,
        did: &str,
    ) -> Result<Option<super::types::TrustRegistry>, TrustRegistryError> {
        let store = self.store.read().await;
        let Some(store) = store.as_ref() else {
            return Ok(None);
        };
        let registries = store
            .list_all()
            .await
            .map_err(|e| {
                warn!("Failed to query trust registry store for DID '{}': {}", did, e);
                TrustRegistryError::ConnectionError(format!("the trust registry store could not be read: {}", e))
            })?;
        Ok(registries
            .into_iter()
            .find(|tr| {
                tr.main_did.as_deref() == Some(did)
                    || tr.registry_did.as_deref() == Some(did)
                    || tr.did.as_deref() == Some(did)
            }))
    }

    /// The DID queries for a stored registry are addressed to: its live
    /// connection's, else the one stored on its record.
    pub(crate) async fn registry_did_for(
        &self,
        trust_registry_id: &str,
    ) -> Option<String> {
        if let Some(connection) = self
            .connections
            .read()
            .await
            .get(trust_registry_id)
        {
            return Some(
                connection
                    .main_did
                    .clone()
                    .unwrap_or_else(|| {
                        connection
                            .registry_did
                            .clone()
                    }),
            );
        }
        let registry = match self
            .stored_registry(trust_registry_id)
            .await
        {
            Ok(registry) => registry,
            Err(TrustRegistryError::NotFound(_)) => return None,
            Err(e) => {
                warn!("Trust registry '{}' could not be resolved to a DID: {}", trust_registry_id, e);
                return None;
            }
        };
        registry
            .query_did()
            .map(str::to_string)
    }

    /// The stored record of `trust_registry_id`.
    async fn stored_registry(
        &self,
        trust_registry_id: &str,
    ) -> Result<super::types::TrustRegistry, TrustRegistryError> {
        let store = self
            .store()
            .await
            .ok_or_else(|| TrustRegistryError::NoConnection("no trust registry store is configured".to_string()))?;
        store
            .get(trust_registry_id)
            .await
            .map_err(|e| {
                TrustRegistryError::ConnectionError(format!(
                    "failed to read trust registry '{}': {}",
                    trust_registry_id, e
                ))
            })?
            .ok_or_else(|| TrustRegistryError::NotFound(format!("trust registry '{}' not found", trust_registry_id)))
    }

    /// Get active connection count
    #[allow(dead_code)]
    pub async fn active_connection_count(&self) -> usize {
        self.connections
            .read()
            .await
            .len()
    }

    // =========================================================================
    // TRQP Query Methods
    // =========================================================================

    /// Query authorization from a trust registry.
    ///
    /// Returns `Ok(None)` when the registry answers with a literal empty
    /// JSON object `{}`. That shape is not spec-compliant (the TRQP
    /// authorization-response schema requires `authorized`) but some
    /// registries emit it for the "no matching record" case, so the
    /// adapter interprets it as a clean negative verdict rather than a
    /// schema error. Every other shape mismatch still surfaces as
    /// `TrustRegistryError::ParseError`.
    pub async fn query_authorization(
        &self,
        trust_registry_did: &str,
        query: &TrqpQueryRequest,
    ) -> Result<Option<TrqpAuthorizationResponse>, TrustRegistryError> {
        let body = serde_json::to_value(query)
            .map_err(|e| TrustRegistryError::ParseError(format!("Failed to serialize query: {}", e)))?;

        let response = self
            .send_with_reconnect(trust_registry_did, trqp::QUERY_AUTHORIZATION, body, self.default_timeout)
            .await?;

        if is_empty_object(&response) {
            return Ok(None);
        }
        let parsed: TrqpAuthorizationResponse = parse_registry_response(response)?;
        parsed
            .validate_echoes_request(query)
            .map_err(|e| TrustRegistryError::ParseError(e.to_string()))?;
        Ok(Some(parsed))
    }

    /// Query recognition from a trust registry. See [`Self::query_authorization`]
    /// for the `Ok(None)`-on-empty-body contract.
    pub async fn query_recognition(
        &self,
        trust_registry_did: &str,
        query: &TrqpQueryRequest,
    ) -> Result<Option<TrqpRecognitionResponse>, TrustRegistryError> {
        let body = serde_json::to_value(query)
            .map_err(|e| TrustRegistryError::ParseError(format!("Failed to serialize query: {}", e)))?;

        let response = self
            .send_with_reconnect(trust_registry_did, trqp::QUERY_RECOGNITION, body, self.default_timeout)
            .await?;

        if is_empty_object(&response) {
            return Ok(None);
        }
        let parsed: TrqpRecognitionResponse = parse_registry_response(response)?;
        parsed
            .validate_echoes_request(query)
            .map_err(|e| TrustRegistryError::ParseError(e.to_string()))?;
        Ok(Some(parsed))
    }

    // =========================================================================
    // TR Admin Methods
    // =========================================================================

    /// Create a record in a trust registry
    pub async fn create_record(
        &self,
        trust_registry_did: &str,
        record: &TrAdminRecordRequest,
    ) -> Result<TrAdminRecordResponse, TrustRegistryError> {
        let body = serde_json::to_value(record)
            .map_err(|e| TrustRegistryError::ParseError(format!("Failed to serialize record: {}", e)))?;

        let response = self
            .send_with_reconnect(trust_registry_did, tr_admin::CREATE_RECORD, body, self.default_timeout)
            .await?;

        parse_registry_response(response)
    }

    /// Create multiple records in a trust registry sequentially.
    /// Fails fast on the first error — no partial state is silently ignored.
    pub async fn create_records(
        &self,
        trust_registry_did: &str,
        records: &[TrAdminRecordRequest],
    ) -> Result<Vec<TrAdminRecordResponse>, TrustRegistryError> {
        let mut responses = Vec::with_capacity(records.len());
        for record in records {
            responses.push(
                self.create_record(trust_registry_did, record)
                    .await?,
            );
        }
        Ok(responses)
    }

    /// Delete multiple records from a trust registry sequentially.
    /// Fails fast on the first error.
    pub async fn delete_records(
        &self,
        trust_registry_did: &str,
        records: &[TrAdminRecordRequest],
    ) -> Result<Vec<TrAdminRecordResponse>, TrustRegistryError> {
        let mut responses = Vec::with_capacity(records.len());
        for record in records {
            responses.push(
                self.delete_record(trust_registry_did, record)
                    .await?,
            );
        }
        Ok(responses)
    }

    /// Update a record in a trust registry
    #[allow(dead_code)]
    pub async fn update_record(
        &self,
        trust_registry_did: &str,
        record: &TrAdminRecordRequest,
    ) -> Result<TrAdminRecordResponse, TrustRegistryError> {
        let body = serde_json::to_value(record)
            .map_err(|e| TrustRegistryError::ParseError(format!("Failed to serialize record: {}", e)))?;

        let response = self
            .send_with_reconnect(trust_registry_did, tr_admin::UPDATE_RECORD, body, self.default_timeout)
            .await?;

        parse_registry_response(response)
    }

    /// Delete a record from a trust registry
    pub async fn delete_record(
        &self,
        trust_registry_did: &str,
        record: &TrAdminRecordRequest,
    ) -> Result<TrAdminRecordResponse, TrustRegistryError> {
        let body = serde_json::to_value(record)
            .map_err(|e| TrustRegistryError::ParseError(format!("Failed to serialize record: {}", e)))?;

        let response = self
            .send_with_reconnect(trust_registry_did, tr_admin::DELETE_RECORD, body, self.default_timeout)
            .await?;

        parse_registry_response(response)
    }

    /// Read a record from a trust registry
    #[allow(dead_code)]
    pub async fn read_record(
        &self,
        trust_registry_did: &str,
        record: &TrAdminRecordRequest,
    ) -> Result<TrAdminRecordResponse, TrustRegistryError> {
        let body = serde_json::to_value(record)
            .map_err(|e| TrustRegistryError::ParseError(format!("Failed to serialize record: {}", e)))?;

        let response = self
            .send_with_reconnect(trust_registry_did, tr_admin::READ_RECORD, body, self.default_timeout)
            .await?;

        parse_registry_response(response)
    }

    /// Search trust registry records using a CEL filter query
    #[allow(dead_code)]
    pub async fn search_records(
        &self,
        trust_registry_did: &str,
        cel_query: &str,
        include_vcs: bool,
    ) -> Result<Vec<TrustRecord>, TrustRegistryError> {
        let body = json!({
            "query":       cel_query,
            "include_vcs": include_vcs,
            "limit":       100,
            "offset":      0,
        });

        let response = self
            .send_with_reconnect(trust_registry_did, trqp::SEARCH, body, self.default_timeout)
            .await?;

        let records: Vec<TrustRecord> = response
            .get("trust_records")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        Ok(records)
    }

    /// List all records from a trust registry
    #[allow(dead_code)]
    pub async fn list_records(
        &self,
        trust_registry_did: &str,
    ) -> Result<TrAdminListRecordsResponse, TrustRegistryError> {
        let response = self
            .send_with_reconnect(trust_registry_did, tr_admin::LIST_RECORDS, json!({}), self.default_timeout)
            .await?;

        parse_registry_response(response)
    }

    /// Create a reference field in a trust registry
    pub async fn create_reference_field(
        &self,
        trust_registry_did: &str,
        request: &CreateReferenceFieldRequest,
    ) -> Result<(), TrustRegistryError> {
        let body = serde_json::to_value(request)
            .map_err(|e| TrustRegistryError::ParseError(format!("Failed to serialize reference field: {}", e)))?;

        self.send_with_reconnect(trust_registry_did, tr_admin::CREATE_REFERENCE_FIELD, body, self.default_timeout)
            .await?;
        Ok(())
    }

    /// Update an existing reference field in a trust registry
    pub async fn update_reference_field(
        &self,
        trust_registry_did: &str,
        request: &UpdateReferenceFieldRequest,
    ) -> Result<(), TrustRegistryError> {
        let body = serde_json::to_value(request)
            .map_err(|e| TrustRegistryError::ParseError(format!("Failed to serialize reference field: {}", e)))?;

        self.send_with_reconnect(trust_registry_did, tr_admin::UPDATE_REFERENCE_FIELD, body, self.default_timeout)
            .await?;
        Ok(())
    }

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /// Ask the owner for `key`'s client. Returns the live client when it can be
    /// used, otherwise joins the build running for `key` or starts one. `stale` is
    /// the client the caller found unusable: a different live client is returned
    /// without a rebuild, because another build already replaced it.
    async fn request_build(
        &self,
        key: BuildKey,
        plan: BuildPlan,
        stale: Option<&TrustRegistryConnection>,
    ) -> Result<Pending, TrustRegistryError> {
        let mut ownership = self.ownership.lock().await;
        if !self.is_active() {
            return Err(TrustRegistryError::NoConnection(STANDBY_REFUSAL.to_string()));
        }
        if let BuildKey::Stored(id) = &key
            && ownership.deleted.contains(id)
        {
            return Err(TrustRegistryError::NotFound(format!("trust registry '{}' was deleted", id)));
        }
        if let Some(building) = ownership.builds.get(&key) {
            return Ok(Pending::Building(building.clone()));
        }
        if matches!(plan, BuildPlan::Oob { .. })
            && self
                .current_connection(&key)
                .await
                .is_some()
        {
            return Err(TrustRegistryError::ConnectionError(format!(
                "trust registry {:?} is already connected, so its OOB invitation is not accepted again",
                key
            )));
        }
        if plan.accepts_current()
            && let Some(current) = self
                .current_connection(&key)
                .await
            && stale.is_none_or(|stale| !current.is_same_client(stale))
        {
            return Ok(Pending::Ready(current));
        }
        let Some(manager) = self.self_ref.upgrade() else {
            return Err(TrustRegistryError::NoConnection("the trust registry manager is shutting down".to_string()));
        };

        let (outcome_tx, outcome_rx) = watch::channel(None);
        ownership
            .builds
            .insert(key.clone(), outcome_rx.clone());
        tokio::spawn(async move {
            manager
                .run_build(key, plan, outcome_tx)
                .await
        });
        Ok(Pending::Building(outcome_rx))
    }

    /// Wait for a requested client, until `deadline` when one is given.
    async fn await_build(
        pending: Pending,
        deadline: Option<Instant>,
    ) -> BuildOutcome {
        let mut outcome = match pending {
            Pending::Ready(connection) => return Ok(connection),
            Pending::Building(outcome) => outcome,
        };
        let finished = outcome.wait_for(Option::is_some);
        let finished = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, finished)
                .await
                .map_err(|_| {
                    TrustRegistryError::Timeout("the trust registry connection is still being built".to_string())
                })?,
            None => finished.await,
        };
        finished
            .ok()
            .and_then(|outcome| outcome.clone())
            .unwrap_or_else(|| {
                Err(TrustRegistryError::ConnectionError("the trust registry build ended without a result".to_string()))
            })
    }

    /// The live client `key` currently resolves to.
    async fn current_connection(
        &self,
        key: &BuildKey,
    ) -> Option<TrustRegistryConnection> {
        let connections = self.connections.read().await;
        match key {
            BuildKey::Stored(id) => connections.get(id).cloned(),
            BuildKey::Temporary(did) => connections
                .values()
                .find(|c| c.is_temporary && c.serves(did))
                .cloned(),
        }
    }

    /// Run one build to completion, whether or not anyone still waits for it,
    /// then publish its outcome and retire it. Boxed because a failed build
    /// schedules a retry that requests a build again.
    fn run_build(
        self: Arc<Self>,
        key: BuildKey,
        plan: BuildPlan,
        outcome_tx: watch::Sender<Option<BuildOutcome>>,
    ) -> futures::future::BoxFuture<'static, ()> {
        Box::pin(self.run_build_inner(key, plan, outcome_tx))
    }

    async fn run_build_inner(
        self: Arc<Self>,
        key: BuildKey,
        plan: BuildPlan,
        outcome_tx: watch::Sender<Option<BuildOutcome>>,
    ) {
        let builder = Arc::clone(&self);
        let build_key = key.clone();
        let retry_on_timeout = matches!(plan, BuildPlan::Stored { .. });
        let mut build = tokio::spawn(async move {
            builder
                .build_and_install(&build_key, plan)
                .await
        });
        let result = match tokio::time::timeout(BUILD_TIMEOUT, &mut build).await {
            Ok(joined) => joined.unwrap_or_else(|e| {
                Err(BuildFailure::fatal(TrustRegistryError::ConnectionError(format!(
                    "the trust registry build failed: {}",
                    e
                ))))
            }),
            Err(_) => {
                build.abort();
                Err(BuildFailure {
                    error: TrustRegistryError::Timeout(format!(
                        "the trust registry build did not finish within {:?}",
                        BUILD_TIMEOUT
                    )),
                    retry: retry_on_timeout,
                })
            }
        };

        if let BuildKey::Stored(id) = &key {
            match &result {
                Ok(_) => self.clear_retry(id).await,
                Err(failure) if failure.retry => self.schedule_retry(id).await,
                Err(_) => {}
            }
        }
        let outcome = result.map_err(|failure| failure.error);
        if let Err(e) = &outcome {
            warn!("Trust registry build for {:?} failed: {}", key, e);
        }

        let mut ownership = self.ownership.lock().await;
        ownership.builds.remove(&key);
        outcome_tx.send_replace(Some(outcome));
    }

    /// Build `key`'s client by `plan`, install it and start its reader.
    async fn build_and_install(
        &self,
        key: &BuildKey,
        plan: BuildPlan,
    ) -> Result<TrustRegistryConnection, BuildFailure> {
        let clients = BuildClients::new(match key {
            BuildKey::Stored(id) => id,
            BuildKey::Temporary(did) => did,
        });
        let (connection, extras) = match (key, plan) {
            (BuildKey::Stored(id), BuildPlan::Stored { allow_failed }) => {
                let registry = self
                    .buildable_registry(id, allow_failed)
                    .await?;
                let connection = self
                    .connect_stored(&registry, &clients)
                    .await?;
                if let Err(refusal) = self
                    .buildable_registry(id, allow_failed)
                    .await
                {
                    connection.close().await;
                    return Err(refusal);
                }
                (connection, None)
            }
            (BuildKey::Stored(id), BuildPlan::Oob { oob_url, did_method, extras }) => {
                let (connection, oob) = self
                    .connect_oob(id, &oob_url, &did_method, &clients)
                    .await
                    .map_err(BuildFailure::fatal)?;
                (connection, Some((extras, oob)))
            }
            (BuildKey::Temporary(did), BuildPlan::Temporary) => {
                let stale: Vec<String> = self
                    .connections
                    .read()
                    .await
                    .values()
                    .filter(|c| c.is_temporary && c.serves(did))
                    .map(|c| c.trust_registry_id.clone())
                    .collect();
                for stale_id in stale {
                    self.remove_connection(&stale_id)
                        .await;
                }
                (
                    self.connect_temporary(did, &clients)
                        .await
                        .map_err(BuildFailure::fatal)?,
                    None,
                )
            }
            (key, _) => {
                return Err(BuildFailure::fatal(TrustRegistryError::ConnectionError(format!(
                    "no build plan applies to {:?}",
                    key
                ))));
            }
        };

        let installed = self
            .install_connection(connection)
            .await;
        clients.release();
        let connection = installed.map_err(BuildFailure::fatal)?;
        self.spawn_reader(&connection.trust_registry_id)
            .await;
        if let Some((extras_tx, extras)) = extras {
            let _ = extras_tx.send(extras);
        }
        Ok(connection)
    }

    /// The stored record of a registry a stored build may connect: it exists,
    /// and is not Failed unless `allow_failed`.
    async fn buildable_registry(
        &self,
        trust_registry_id: &str,
        allow_failed: bool,
    ) -> Result<super::types::TrustRegistry, BuildFailure> {
        let registry = self
            .stored_registry(trust_registry_id)
            .await
            .map_err(BuildFailure::fatal)?;
        if registry.connection_status == TrustRegistryConnectionStatus::Failed && !allow_failed {
            return Err(BuildFailure::fatal(TrustRegistryError::NoConnection(format!(
                "trust registry '{}' is marked Failed; reconnect it to retry",
                trust_registry_id
            ))));
        }
        Ok(registry)
    }

    /// Retry `trust_registry_id` in the background after its latest build
    /// failed, waiting longer after each consecutive failure. Nothing is
    /// scheduled for a deleted registry or on a Standby node.
    async fn schedule_retry(
        &self,
        trust_registry_id: &str,
    ) {
        let Some(manager) = self.self_ref.upgrade() else {
            return;
        };
        if !self.is_active()
            || self
                .ownership
                .lock()
                .await
                .deleted
                .contains(trust_registry_id)
        {
            return;
        }
        let mut retries = self.retries.lock().await;
        let failures = retries
            .get(trust_registry_id)
            .map_or(0, |retry| retry.failures)
            + 1;
        let delay = Duration::from_secs(
            self.retry_policy
                .backoff_seconds(failures),
        );
        let id = trust_registry_id.to_string();
        let task = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            debug!("Trust registry: background retry {} for '{}'", failures, id);
            if let Err(e) = manager
                .request_build(BuildKey::Stored(id.clone()), BuildPlan::Stored { allow_failed: false }, None)
                .await
            {
                debug!("Trust registry: background retry for '{}' not started: {}", id, e);
                manager
                    .retries
                    .lock()
                    .await
                    .remove(&id);
            }
        });
        if let Some(previous) = retries.insert(
            trust_registry_id.to_string(),
            Retry {
                failures,
                task: task.abort_handle(),
            },
        ) {
            previous.task.abort();
        }
        info!("Trust registry: retrying '{}' in {:?}", trust_registry_id, delay);
    }

    /// Stop `trust_registry_id`'s background retry and reset its backoff.
    async fn clear_retry(
        &self,
        trust_registry_id: &str,
    ) {
        if let Some(retry) = self
            .retries
            .lock()
            .await
            .remove(trust_registry_id)
        {
            retry.task.abort();
        }
    }

    /// The live client addressed to `trust_registry_did`, or the one the owner
    /// builds for it by `deadline`: from the stored registry with that DID, or a
    /// temporary connection when no stored registry has it.
    async fn connection_for_did(
        &self,
        trust_registry_did: &str,
        deadline: Instant,
    ) -> BuildOutcome {
        if let Some(connection) = self
            .connections
            .read()
            .await
            .values()
            .find(|c| !c.is_temporary && c.serves(trust_registry_did))
        {
            return Ok(connection.clone());
        }
        let pending = match self
            .find_stored_trust_registry(trust_registry_did)
            .await?
        {
            Some(registry) if registry.connection_status == TrustRegistryConnectionStatus::Failed => {
                return Err(TrustRegistryError::NoConnection(format!(
                    "trust registry '{}' is marked Failed; reconnect it to retry",
                    registry.id
                )));
            }
            Some(registry) => {
                self.request_build(BuildKey::Stored(registry.id), BuildPlan::Stored { allow_failed: false }, None)
                    .await?
            }
            None => {
                let key = BuildKey::Temporary(trust_registry_did.to_string());
                if let Some(temporary) = self
                    .current_connection(&key)
                    .await
                {
                    return Ok(temporary);
                }
                self.request_build(key, BuildPlan::Temporary, None)
                    .await?
            }
        };
        Self::await_build(pending, Some(deadline)).await
    }

    /// A replacement for `stale`, built by `deadline` unless another build
    /// already replaced it.
    async fn rebuild_for_did(
        &self,
        trust_registry_did: &str,
        stale: &TrustRegistryConnection,
        deadline: Instant,
    ) -> BuildOutcome {
        let (key, plan) = if stale.is_temporary {
            (BuildKey::Temporary(trust_registry_did.to_string()), BuildPlan::Temporary)
        } else {
            (
                BuildKey::Stored(
                    stale
                        .trust_registry_id
                        .clone(),
                ),
                BuildPlan::Stored { allow_failed: false },
            )
        };
        let pending = self
            .request_build(key, plan, Some(stale))
            .await?;
        Self::await_build(pending, Some(deadline)).await
    }

    /// Build a temporary connection to a public trust registry under a
    /// throwaway did:peer identity, for the owner to install.
    async fn connect_temporary(
        &self,
        trust_registry_did: &str,
        clients: &BuildClients,
    ) -> Result<TrustRegistryConnection, TrustRegistryError> {
        let temp_id = format!("temp-{}", uuid::Uuid::new_v4());

        #[cfg(test)]
        if let Some(built) = super::test_builds::run(trust_registry_did, clients).await {
            return built
                .map(|client| TrustRegistryConnection {
                    trust_registry_id: temp_id.clone(),
                    our_did: "did:example:temporary".to_string(),
                    registry_did: trust_registry_did.to_string(),
                    main_did: Some(trust_registry_did.to_string()),
                    mediator_did: "did:example:mediator".to_string(),
                    is_temporary: true,
                    client,
                    response_waiters: Arc::new(Mutex::new(HashMap::new())),
                    timed_out_queries: TimedOutQueries::default(),
                })
                .map_err(TrustRegistryError::ConnectionError);
        }

        info!("Creating temporary connection for public trust registry '{}'", trust_registry_did);

        // Step 1: Resolve the trust registry DID to discover mediator
        let (mediator_url, mediator_did) = resolve_mediator_from_did(trust_registry_did).await?;

        info!("Resolved mediator for '{}': url={}, did={}", trust_registry_did, mediator_url, mediator_did);

        // Step 2: Generate ephemeral did:peer identity (not persisted to disk)
        let temp_storage = std::env::temp_dir().join("affinidi-tr-temp");
        let (our_did, secrets, did_doc) = generate_trust_registry_identity(
            &temp_id,
            &self.domain,
            &temp_storage,
            &mediator_url,
            &mediator_did,
            DidMethod::Peer,
            #[cfg(feature = "didwebvh")]
            None,
            #[cfg(feature = "didwebvh")]
            None,
        )
        .await
        .map_err(|e| TrustRegistryError::ConnectionError(format!("Failed to generate ephemeral identity: {}", e)))?;

        // Clean up temp keys from disk (ephemeral, not needed after ATM creation)
        let temp_keys_path = temp_storage.join(&temp_id);
        if temp_keys_path.exists() {
            let _ = tokio::fs::remove_dir_all(&temp_keys_path).await;
        }

        // Step 3: Create DIDComm client
        let client = create_tr_client(
            &temp_id,
            &our_did,
            &mediator_did,
            &secrets,
            Some((&our_did, &did_doc)),
            FirstCallRetry::never(),
            clients,
        )
        .await
        .map_err(TrustRegistryError::ConnectionError)?;

        set_acl_to_allow_everything_and_more(client.atm(), client.profile().clone())
            .await
            .map_err(|e| {
                warn!("Could not set ACL for temporary trust registry connection: {:?}", e);
            })
            .ok();

        info!("✓ Temporary connection created for public trust registry '{}' (id: {})", trust_registry_did, temp_id);
        Ok(TrustRegistryConnection {
            trust_registry_id: temp_id,
            our_did,
            registry_did: trust_registry_did.to_string(),
            main_did: Some(trust_registry_did.to_string()),
            mediator_did,
            is_temporary: true,
            client,
            response_waiters: Arc::new(Mutex::new(HashMap::new())),
            timed_out_queries: TimedOutQueries::default(),
        })
    }

    /// Send with stale connection recovery, all within `timeout`. A missing
    /// client, and on StaleConnection a replacement, is requested from the owner
    /// and waited for, then the send is retried once. Queries never build
    /// clients themselves; a build that outlives the call still installs its
    /// client for the next one.
    async fn send_with_reconnect(
        &self,
        trust_registry_did: &str,
        message_type: &str,
        body: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, TrustRegistryError> {
        let deadline = Instant::now() + timeout;
        let connection = self
            .connection_for_did(trust_registry_did, deadline)
            .await?;

        match self
            .send_and_await(&connection, message_type, body.clone(), deadline)
            .await
        {
            Err(TrustRegistryError::StaleConnection(reason)) => {
                warn!("Stale connection to '{}': {}. Reconnecting (one attempt).", trust_registry_did, reason);

                let fresh = self
                    .rebuild_for_did(trust_registry_did, &connection, deadline)
                    .await?;

                // enable_websocket() may return before the WS is fully ready.
                tokio::time::timeout_at(deadline, await_websocket_ready(&fresh.client))
                    .await
                    .map_err(|_| {
                        TrustRegistryError::Timeout("the rebuilt trust registry connection is not ready".to_string())
                    })?;

                self.send_and_await(&fresh, message_type, body, deadline)
                    .await
            }
            other => other,
        }
    }

    /// Send a DIDComm message and await the response the stream reader
    /// demultiplexes back to us by thread id (`thid`).
    ///
    /// The per-connection stream reader ([`super::reader`]) is the sole
    /// consumer of the mediator websocket; it delivers each response to the
    /// waiter registered here. This means the reader **must** be running for
    /// the connection or the response is cached in the SDK and never arrives
    /// (surfacing as a timeout).
    async fn send_and_await(
        &self,
        connection: &TrustRegistryConnection,
        message_type: &str,
        body: serde_json::Value,
        deadline: Instant,
    ) -> Result<serde_json::Value, TrustRegistryError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TrustRegistryError::Timeout("no time left to send to the trust registry".to_string()));
        }
        let message_id = uuid::Uuid::new_v4().to_string();
        let thread_id = uuid::Uuid::new_v4().to_string();

        let message = DIDCommMessage::build(message_id.clone(), message_type.to_string(), body)
            .from(connection.our_did.clone())
            .to(connection
                .registry_did
                .clone())
            .thid(thread_id.clone())
            .finalize();

        debug!("Sending {} to trust registry {} (thid: {})", message_type, connection.registry_did, thread_id);

        // Stale-connection detection so `send_with_reconnect` can recover. The
        // status response is matched via the SDK `wanted_list`, which has
        // priority over the reader's `next` waiter, so this never steals a
        // query response from the reader.
        connection
            .client
            .preflight_check(QUERY_PREFLIGHT_TIMEOUT.min(remaining))
            .await
            .map_err(TrustRegistryError::StaleConnection)?;

        // Register the waiter BEFORE forwarding so a fast response can't race
        // ahead of us and be dropped by the reader as unmatched.
        let rx = connection
            .register_waiter(thread_id.clone())
            .await;
        let mut pending = PendingQuery {
            waiters: connection
                .response_waiters
                .clone(),
            timed_out_queries: connection
                .timed_out_queries
                .clone(),
            thid: thread_id.clone(),
            answered: false,
        };

        if let Err(e) = crate::comm::didcomm::trust_registry::pack_and_forward(
            &connection.client,
            &message,
            &connection.our_did,
            &connection.registry_did,
            &connection.mediator_did,
        )
        .await
        {
            return Err(TrustRegistryError::SendError(e));
        }

        info!(
            "Message forwarded via mediator, waiting for response (timeout: {:?})",
            deadline.saturating_duration_since(Instant::now())
        );

        match tokio::time::timeout_at(deadline, rx).await {
            Ok(Ok(result)) => {
                pending.answered = true;
                if result.msg_type == MSG_TYPE_PROBLEM_REPORT {
                    return Err(problem_report_error(result.body));
                }
                info!("Received response: {}", result.msg_type);
                Ok(result.body)
            }
            Ok(Err(_recv_err)) => {
                // Sender dropped: the reader exited (disconnect) and failed all
                // waiters. Treat as stale so `send_with_reconnect` reconnects.
                Err(TrustRegistryError::StaleConnection("stream reader closed before a response arrived".to_string()))
            }
            Err(_elapsed) => {
                Err(TrustRegistryError::Timeout(format!("No response within {:?} for thread {}", remaining, thread_id)))
            }
        }
    }
}

// =============================================================================
// OOB Invitation Parsing
// =============================================================================

/// Dev/test escape hatch: when `AG_ALLOW_LOCAL_OOB` is set to `1`/`true`/`yes`
/// (case-insensitive), OOB-invitation URLs bypass the SSRF check so BDD and
/// local development can point at loopback / private-IP mediators. Never set
/// in production.
fn skip_outbound_url_validation() -> bool {
    let enabled = std::env::var("AG_ALLOW_LOCAL_OOB")
        .map(|v| {
            matches!(
                v.to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false);
    if enabled {
        warn!(
            "AG_ALLOW_LOCAL_OOB is set: OOB URL SSRF validation is DISABLED. \
             This is for dev/test only and must never be set in production."
        );
    }
    enabled
}

/// Validate that a caller-supplied URL is safe for outbound HTTP requests (SSRF prevention).
///
/// Enforces:
/// - Scheme allowlist: only `http` and `https`.
/// - Blocks `localhost` / `*.localhost` domain names.
/// - Blocks all IPv4 private, loopback, link-local (169.254/16 — covers AWS/GCP metadata),
///   unspecified, broadcast, and CGN (100.64/10) ranges.
/// - Blocks IPv6 loopback, unspecified, unique-local (fc00::/7), and link-local (fe80::/10).
fn validate_outbound_url(url: &url::Url) -> Result<(), String> {
    match url.scheme() {
        "http" | "https" => {}
        scheme => return Err(format!("OOB URL scheme '{}' is not allowed; only http and https are permitted", scheme)),
    }

    let host = url
        .host()
        .ok_or_else(|| "OOB URL missing host".to_string())?;

    match host {
        url::Host::Domain(domain) => {
            let lower = domain.to_lowercase();
            if lower == "localhost" || lower.ends_with(".localhost") {
                return Err(format!("OOB URL host '{}' is not permitted (loopback)", domain));
            }
        }
        url::Host::Ipv4(addr) => {
            if is_blocked_ipv4(addr) {
                return Err(format!("OOB URL host '{}' is in a blocked IP range", addr));
            }
        }
        url::Host::Ipv6(addr) => {
            if is_blocked_ipv6(addr) {
                return Err(format!("OOB URL host '{}' is in a blocked IP range", addr));
            }
        }
    }

    Ok(())
}

fn is_blocked_ipv4(addr: std::net::Ipv4Addr) -> bool {
    addr.is_loopback()                                                     // 127.0.0.0/8
        || addr.is_private()                                               // 10/8, 172.16/12, 192.168/16
        || addr.is_link_local()                                            // 169.254.0.0/16 (AWS/GCP metadata)
        || addr.is_unspecified()                                           // 0.0.0.0
        || addr.is_broadcast()                                             // 255.255.255.255
        || (addr.octets()[0] == 100 && (addr.octets()[1] & 0xC0) == 64) // 100.64.0.0/10 CGN
}

fn is_blocked_ipv6(addr: std::net::Ipv6Addr) -> bool {
    addr.is_loopback()                               // ::1
        || addr.is_unspecified()                     // ::
        || (addr.segments()[0] & 0xFE00) == 0xFC00  // fc00::/7 unique-local
        || (addr.segments()[0] & 0xFFC0) == 0xFE80 // fe80::/10 link-local
}

/// Parse an OOB invitation URL and extract the inviter's DID, mediator DID, and mediator URL.
///
/// Supports two OOB URL formats:
///   1. Inline: `https://mediator.example.com?_oob=<base64_encoded_invitation>`
///   2. Referenced: `https://mediator.example.com/oob?_oobid=<id>` (fetches invitation from the URL)
///
/// The invitation JSON contains:
///   { "from": "did:...", "body": { "accept": [...] } }
///
/// The mediator DID is resolved from the mediator URL's DID document.
/// Decode a base64-encoded string, trying URL_SAFE_NO_PAD, URL_SAFE, then STANDARD encodings.
fn decode_base64(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
}

async fn parse_oob_invitation(oob_url: &str) -> Result<ParsedOobInvitation, String> {
    let url = url::Url::parse(oob_url).map_err(|e| format!("Invalid OOB URL: {}", e))?;
    if !skip_outbound_url_validation() {
        validate_outbound_url(&url)?;
    }

    // Extract optional main_did query parameter (base64-encoded DID string)
    let main_did = url
        .query_pairs()
        .find(|(key, _)| key == "main_did")
        .and_then(|(_, value)| {
            let decoded_bytes = decode_base64(value.as_ref()).ok()?;
            String::from_utf8(decoded_bytes).ok()
        });

    // Check for inline _oob parameter first, then referenced _oobid
    let oob_inline = url
        .query_pairs()
        .find(|(key, _)| key == "_oob")
        .map(|(_, value)| value.to_string());

    let oob_id = url
        .query_pairs()
        .find(|(key, _)| key == "_oobid")
        .map(|(_, value)| value.to_string());

    let invitation: serde_json::Value = if let Some(oob_param) = oob_inline {
        // Inline: decode base64 from _oob parameter
        let decoded = decode_base64(&oob_param).map_err(|e| format!("Failed to decode OOB base64: {}", e))?;

        serde_json::from_slice(&decoded).map_err(|e| format!("Failed to parse OOB JSON: {}", e))?
    } else if oob_id.is_some() {
        // Referenced: fetch the invitation from the full (attacker-supplied) OOB
        // URL through the SSRF egress guard (DNS-pinned, redirect-revalidated).
        let response = guarded_oob_get(oob_url, true).await?;

        if !response.status().is_success() {
            return Err(format!("OOB invitation fetch failed with status {}", response.status()));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse OOB invitation response: {}", e))?;

        // The mediator may return the invitation directly or wrapped in a response envelope
        // with the invitation base64-encoded in a "data" field.
        if body.get("from").is_some() {
            // Direct invitation JSON
            body
        } else if let Some(data_str) = body
            .get("data")
            .and_then(|v| v.as_str())
        {
            // Envelope format: { "data": "<base64_encoded_invitation>" }
            let decoded = decode_base64(data_str).map_err(|e| format!("Failed to decode OOB data base64: {}", e))?;

            serde_json::from_slice(&decoded)
                .map_err(|e| format!("Failed to parse OOB invitation from data field: {}", e))?
        } else {
            return Err(format!(
                "OOB response has no 'from' field or 'data' envelope. Keys: {:?}",
                body.as_object()
                    .map(|o| o.keys().collect::<Vec<_>>())
                    .unwrap_or_default()
            ));
        }
    } else {
        return Err("OOB URL missing _oob or _oobid parameter".to_string());
    };

    // Extract inviter's DID
    let inviter_did = invitation
        .get("from")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "OOB invitation missing 'from' field".to_string())?;

    // Extract mediator URL from the OOB URL path (everything up to the last path segment)
    // e.g. http://localhost:7037/mediator/v1/oob?... → http://localhost:7037/mediator/v1
    let base = format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str()
            .ok_or_else(|| "OOB URL missing host".to_string())?,
        url.port()
            .map(|p| format!(":{}", p))
            .unwrap_or_default()
    );
    let path = url
        .path()
        .trim_end_matches('/');
    let mediator_url = if let Some(pos) = path.rfind('/') {
        format!("{}{}", base, &path[..pos])
    } else {
        base
    };

    // Resolve mediator DID from the mediator's well-known endpoint
    let mediator_did = fetch_mediator_did_from_url(&mediator_url)
        .await
        .map_err(|e| format!("Failed to resolve mediator DID: {}", e))?;

    Ok(ParsedOobInvitation {
        inviter_did,
        mediator_did,
        mediator_url,
        main_did,
    })
}

/// Extract a DIDComm service endpoint URL from a DID document.
///
/// Looks for services with type `DIDCommMessaging` or `dm` and returns the `serviceEndpoint` string.
fn extract_didcomm_service_endpoint(
    did_doc: &serde_json::Value,
    did: &str,
) -> Result<String, TrustRegistryError> {
    let services = did_doc
        .get("service")
        .and_then(|s| s.as_array())
        .ok_or_else(|| {
            TrustRegistryError::ConnectionError(format!("DID document for '{}' has no 'service' array", did))
        })?;

    services
        .iter()
        .find_map(|svc| {
            let type_matches = match svc.get("type") {
                Some(serde_json::Value::String(s)) => s == "DIDCommMessaging" || s == "dm",
                Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| {
                    v.as_str()
                        .map(|s| s == "DIDCommMessaging" || s == "dm")
                        .unwrap_or(false)
                }),
                _ => false,
            };
            if type_matches {
                svc.get("serviceEndpoint")
                    .and_then(|ep| match ep {
                        // Format 1: serviceEndpoint is a plain string URI
                        serde_json::Value::String(s) => Some(s.clone()),
                        // Format 2: serviceEndpoint is an array of objects with "uri" fields
                        serde_json::Value::Array(arr) => arr.iter().find_map(|entry| {
                            entry
                                .get("uri")
                                .and_then(|u| u.as_str())
                                .map(|s| s.to_string())
                        }),
                        _ => None,
                    })
            } else {
                None
            }
        })
        .ok_or_else(|| {
            TrustRegistryError::ConnectionError(format!(
                "DID document for '{}' has no DIDCommMessaging/dm service endpoint",
                did
            ))
        })
}

/// Resolve a trust registry DID to discover its mediator endpoint and DID.
///
/// Supported DID methods:
/// - `did:web` — fetches DID document via HTTPS, extracts `DIDCommMessaging` service endpoint.
/// - `did:peer` — self-describing; resolves the DID document from the DID string itself,
///   extracts the `dm` service endpoint.
///
/// The mediator DID is resolved from the discovered service endpoint.
async fn resolve_mediator_from_did(did: &str) -> Result<(String, String), TrustRegistryError> {
    let did_doc: serde_json::Value = if did.starts_with("did:web:") {
        resolve_did_web_document(did).await?
    } else if did.starts_with("did:peer:") {
        resolve_did_peer_document(did)?
    } else {
        return Err(TrustRegistryError::ConnectionError(format!(
            "Temporary connections only supported for did:web and did:peer registries, got '{}'",
            did
        )));
    };

    let mediator_url = extract_didcomm_service_endpoint(&did_doc, did)?;

    // Resolve mediator DID from the service endpoint
    let mediator_did = fetch_mediator_did_from_url(&mediator_url)
        .await
        .map_err(|e| {
            TrustRegistryError::ConnectionError(format!(
                "Failed to resolve mediator DID from '{}': {}",
                mediator_url, e
            ))
        })?;

    Ok((mediator_url, mediator_did))
}

/// GET an attacker-influenceable OOB / did:web URL through the shared SSRF
/// egress guard (`EgressPolicy::Strict`): the host is validated, DNS-resolved
/// once and pinned, and every redirect hop is re-validated — closing the
/// DNS-rebinding and public→internal-redirect gaps that a static URL check
/// (`validate_outbound_url`) leaves open.
///
/// The dev/test escape hatch `AG_ALLOW_LOCAL_OOB` (see
/// [`skip_outbound_url_validation`]) falls back to the plain short-timeout
/// client so local loopback fixtures keep resolving; production (env unset)
/// always goes through the guard.
///
/// On a guard block the detailed reason (including the resolved internal IP) is
/// logged server-side only and a generic message is returned, so the HTTP body
/// can't be used as a DNS-rebind / SSRF oracle.
async fn guarded_oob_get(
    url: &str,
    accept_json: bool,
) -> Result<reqwest::Response, String> {
    guarded_oob_get_inner(url, accept_json, skip_outbound_url_validation(), bdd_egress_allowlist().as_deref()).await
}

async fn guarded_oob_get_inner(
    url: &str,
    accept_json: bool,
    skip_guard: bool,
    exact_allowlist: Option<&str>,
) -> Result<reqwest::Response, String> {
    if skip_guard {
        let client =
            crate::http_client::with_short_timeout().map_err(|e| format!("Failed to create HTTP client: {}", e))?;
        let mut request = client.get(url);
        if accept_json {
            request = request.header(ACCEPT, "application/json");
        }
        return request
            .send()
            .await
            .map_err(|e| format!("Failed to fetch {}: {}", url, e));
    }

    let mut headers = HeaderMap::new();
    if accept_json {
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    }

    match guarded_send_inner(
        Method::GET,
        url,
        headers,
        None,
        EgressPolicy::Strict,
        Duration::from_secs(crate::http_client::SHORT_TIMEOUT_SECS),
        exact_allowlist,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(EgressError::Blocked(reason)) => {
            warn!("OOB/did:web fetch blocked by egress policy for {}: {}", url, reason);
            Err("URL blocked by egress policy".to_string())
        }
        Err(other) => Err(format!("Failed to fetch {}: {}", url, other)),
    }
}

/// Resolve a did:web to its DID document via HTTPS.
async fn resolve_did_web_document(did: &str) -> Result<serde_json::Value, TrustRegistryError> {
    resolve_did_web_document_inner(did, skip_outbound_url_validation(), bdd_egress_allowlist().as_deref()).await
}

async fn resolve_did_web_document_inner(
    did: &str,
    skip_guard: bool,
    exact_allowlist: Option<&str>,
) -> Result<serde_json::Value, TrustRegistryError> {
    let method_specific = &did["did:web:".len()..];
    let decoded = method_specific.replace("%3A", ":");
    let parts: Vec<&str> = decoded.split(':').collect();
    let did_doc_url = if parts.len() == 1 {
        format!("https://{}/.well-known/did.json", parts[0])
    } else {
        let host = parts[0];
        let path = parts[1..].join("/");
        format!("https://{}/{}/did.json", host, path)
    };

    debug!("Resolving DID document for '{}' from: {}", did, did_doc_url);

    let response = guarded_oob_get_inner(&did_doc_url, false, skip_guard, exact_allowlist)
        .await
        .map_err(TrustRegistryError::ConnectionError)?;

    if !response.status().is_success() {
        return Err(TrustRegistryError::ConnectionError(format!(
            "DID document fetch failed with status {} for '{}'",
            response.status(),
            did
        )));
    }

    response
        .json()
        .await
        .map_err(|e| TrustRegistryError::ConnectionError(format!("Failed to parse DID document for '{}': {}", did, e)))
}

/// Resolve a did:peer to its DID document (self-describing, no network call).
fn resolve_did_peer_document(did: &str) -> Result<serde_json::Value, TrustRegistryError> {
    use std::str::FromStr;
    let peer_did = affinidi_did_common::DID::from_str(did)
        .map_err(|e| TrustRegistryError::ConnectionError(format!("Failed to parse did:peer '{}': {:?}", did, e)))?;
    let doc = peer_did
        .resolve()
        .map_err(|e| TrustRegistryError::ConnectionError(format!("Failed to resolve did:peer '{}': {:?}", did, e)))?;
    serde_json::to_value(&doc)
        .map_err(|e| TrustRegistryError::ConnectionError(format!("Failed to serialize did:peer document: {}", e)))
}

// =============================================================================
// ATM Instance Creation
// =============================================================================

pub(crate) fn trust_registry_payload(
    trust_registry_id: &str,
    mediator_did: &str,
    our_did: &str,
) -> crate::event_hook::ConnectionPointPayload {
    crate::event_hook::ConnectionPointPayload::minted(
        trust_registry_id,
        &format!("Trust registry {trust_registry_id}"),
        "",
        "",
        "",
        mediator_did,
        our_did,
    )
}

/// Create a DIDComm client for trust registry communication.
///
/// Wraps `DIDCommClient::new` + optional DID doc pre-caching + `enable_websocket`.
/// The DID document must be cached **before** enabling the WebSocket —
/// `enable_websocket` triggers mediator authentication which resolves our
/// `did:web` over HTTPS. At startup the gateway's own HTTP server may not
/// be ready yet, so the resolver must find the document in cache.
async fn create_tr_client(
    registry_name: &str,
    our_did: &str,
    mediator_did: &str,
    secrets: &[Secret],
    did_doc_to_cache: Option<(&str, &serde_json::Value)>,
    first_call_retry: FirstCallRetry,
    clients: &BuildClients,
) -> Result<crate::comm::didcomm::client::DIDCommClient, String> {
    let mut client = crate::comm::didcomm::client::DIDCommClient::new(
        our_did.to_string(),
        secrets.to_vec(),
        Some(mediator_did.to_string()),
        Some(format!("trust-registry-{}", registry_name)),
    )
    .await?;
    clients.hold(&client);

    // Cache the DID document BEFORE enabling the WebSocket so the
    // mediator authentication flow finds it without a network fetch.
    let prepared = async {
        if let Some((did, doc)) = did_doc_to_cache {
            client
                .cache_did_document(did, doc.clone())
                .await?;
            info!("✓ Pre-cached DID document for {} in ATM resolver", did);
        }
        client
            .enable_websocket_with(first_call_retry)
            .await
    }
    .await;

    // A failed enable may already have started the websocket transport.
    if let Err(e) = prepared {
        client
            .atm()
            .graceful_shutdown()
            .await;
        return Err(e);
    }

    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: &str) -> url::Url {
        url::Url::parse(url).expect("test URL must be syntactically valid")
    }

    // --- Active/Standby gate ---

    async fn deleted_events_after(
        registries: &[super::super::types::TrustRegistry],
        expected: usize,
    ) -> Vec<String> {
        let manager = test_manager();
        let (url, captured) = crate::event_hook::tests_support::serve(204, "").await;
        let hook = crate::event_hook::EventHook::new(crate::event_hook::EventHookSettings {
            hook_url: Some(url),
            ..crate::event_hook::EventHookSettings::default()
        });
        manager.set_event_hook(hook, None);
        for registry in registries {
            manager.announce_deleted(registry);
        }
        for _ in 0..100 {
            if captured.lock().unwrap().len() >= expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        captured
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.body.clone())
            .collect()
    }

    fn stored_registry(
        our_did: Option<&str>,
        mediator_did: Option<&str>,
    ) -> super::super::types::TrustRegistry {
        let mut registry = super::super::types::TrustRegistry::new(
            "tr".into(),
            String::new(),
            "https://oob.example".into(),
            DidMethod::Peer,
        );
        registry.our_did = our_did.map(str::to_string);
        registry.mediator_did = mediator_did.map(str::to_string);
        registry
    }

    #[tokio::test]
    async fn deleting_a_connected_registry_reports_its_did() {
        let bodies =
            deleted_events_after(&[stored_registry(Some("did:peer:2.ours"), Some("did:web:mediator.example"))], 1)
                .await;
        assert_eq!(bodies.len(), 1, "one event: {bodies:?}");
        let event: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
        assert_eq!(event["event"], "connection_point.deleted");
        assert_eq!(event["connection_point"]["did"], "did:peer:2.ours");
        assert_eq!(event["connection_point"]["mediator_did"], "did:web:mediator.example");
    }

    #[tokio::test]
    async fn deleting_a_registry_that_never_connected_reports_nothing() {
        let bodies = deleted_events_after(
            &[
                stored_registry(None, None),
                stored_registry(Some("did:peer:2.half"), None),
                stored_registry(Some("did:peer:2.sentinel"), Some("did:web:mediator.example")),
            ],
            1,
        )
        .await;
        assert_eq!(bodies.len(), 1, "only the connected registry is reported: {bodies:?}");
        assert!(bodies[0].contains("did:peer:2.sentinel"));
    }

    fn test_manager() -> Arc<TrustRegistryListenerManager> {
        let dir = tempfile::tempdir().expect("tempdir");
        TrustRegistryListenerManager::with_retry_policy(
            "example.com".to_string(),
            dir.path().to_path_buf(),
            None,
            ReconnectPolicy::default(),
        )
    }

    #[test]
    fn active_flag_defaults_true_and_toggles_idempotently() {
        let mgr = test_manager();
        assert!(mgr.is_active(), "a fresh manager is active by default");

        mgr.deactivate();
        assert!(!mgr.is_active());
        mgr.deactivate();
        assert!(!mgr.is_active(), "deactivate is idempotent");

        mgr.activate();
        assert!(mgr.is_active());
        mgr.activate();
        assert!(mgr.is_active(), "activate is idempotent");
    }

    #[tokio::test]
    async fn reconnect_all_from_store_returns_zero_without_store() {
        let mgr = test_manager();
        assert_eq!(
            mgr.reconnect_all_from_store()
                .await,
            0
        );
    }

    #[tokio::test]
    async fn disconnect_all_on_empty_is_noop() {
        let mgr = test_manager();
        mgr.disconnect_all().await;
        assert_eq!(
            mgr.active_connection_count()
                .await,
            0
        );
    }

    // --- connection lifecycle: one live mediator session per registry ---

    async fn test_connection(trust_registry_id: &str) -> TrustRegistryConnection {
        connection_to(trust_registry_id, "did:example:registry").await
    }

    async fn connection_to(
        trust_registry_id: &str,
        registry_did: &str,
    ) -> TrustRegistryConnection {
        TrustRegistryConnection {
            trust_registry_id: trust_registry_id.to_string(),
            our_did: "did:example:gateway".to_string(),
            registry_did: registry_did.to_string(),
            main_did: None,
            mediator_did: "did:example:mediator".to_string(),
            is_temporary: false,
            client: super::super::test_builds::offline_client().await,
            response_waiters: empty_waiters(),
            timed_out_queries: TimedOutQueries::default(),
        }
    }

    async fn temporary_connection_to(registry_did: &str) -> TrustRegistryConnection {
        let mut connection = connection_to(&format!("temp-{}", uuid::Uuid::new_v4()), registry_did).await;
        connection.is_temporary = true;
        connection.main_did = Some(registry_did.to_string());
        connection
    }

    async fn connection_of(
        mgr: &TrustRegistryListenerManager,
        trust_registry_id: &str,
    ) -> Option<TrustRegistryConnection> {
        mgr.connections
            .read()
            .await
            .get(trust_registry_id)
            .cloned()
    }

    #[tokio::test]
    async fn installing_a_connection_closes_the_one_it_replaces() {
        let mgr = test_manager();
        let first = test_connection("tr-1").await;
        let pending = first
            .register_waiter("thread-1".to_string())
            .await;
        mgr.install_connection(first.clone())
            .await
            .expect("an Active node installs");

        mgr.spawn_reader("tr-1").await;

        let second = test_connection("tr-1").await;
        mgr.install_connection(second.clone())
            .await
            .expect("an Active node installs");

        assert!(pending.await.is_err(), "the replaced connection must be closed");
        assert!(
            !mgr.readers
                .read()
                .await
                .contains_key("tr-1"),
            "the replaced connection's reader must be stopped"
        );
        let stored = connection_of(&mgr, "tr-1")
            .await
            .expect("the replacement is stored");
        assert!(stored.is_same_client(&second));
        assert_eq!(
            mgr.active_connection_count()
                .await,
            1
        );
    }

    #[tokio::test]
    async fn installing_a_connection_keeps_other_registries_open() {
        let mgr = test_manager();
        let first = test_connection("tr-1").await;
        let _pending = first
            .register_waiter("thread-1".to_string())
            .await;
        mgr.install_connection(first.clone())
            .await
            .expect("an Active node installs");

        mgr.install_connection(connection_to("tr-2", "did:example:other-registry").await)
            .await
            .expect("an Active node installs");

        assert!(
            first
                .response_waiters
                .lock()
                .await
                .contains_key("thread-1"),
            "a connection for another registry must stay open"
        );
        assert_eq!(
            mgr.active_connection_count()
                .await,
            2
        );
    }

    #[tokio::test]
    async fn remove_connection_closes_the_removed_connection() {
        let mgr = test_manager();
        let connection = test_connection("tr-1").await;
        let pending = connection
            .register_waiter("thread-1".to_string())
            .await;
        mgr.install_connection(connection)
            .await
            .expect("an Active node installs");

        mgr.remove_connection("tr-1")
            .await;

        assert!(pending.await.is_err(), "the removed connection must be closed");
        assert!(
            connection_of(&mgr, "tr-1")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_stale_temporary_connection_is_removed_when_it_cannot_be_replaced() {
        let mgr = test_manager();
        let connection = temporary_connection_to("did:example:registry").await;
        let temp_id = connection
            .trust_registry_id
            .clone();
        mgr.install_connection(connection)
            .await
            .expect("an Active node installs");

        let result = mgr
            .send_with_reconnect("did:example:registry", trqp::QUERY_AUTHORIZATION, json!({}), Duration::from_secs(1))
            .await;

        assert!(result.is_err(), "an unresolvable registry DID cannot get a new temporary connection");
        assert!(
            connection_of(&mgr, &temp_id)
                .await
                .is_none(),
            "the stale temporary connection must be removed"
        );
    }

    // --- ownership: one build per registry, owned by the manager ---

    /// A manager with a store, whose background retries wait `retry_seconds`.
    async fn owned_manager(
        retry_seconds: u64
    ) -> (Arc<TrustRegistryListenerManager>, Arc<super::super::FileSystemTrustRegistryStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mgr = TrustRegistryListenerManager::with_retry_policy(
            "example.com".to_string(),
            dir.path().join("keys"),
            None,
            ReconnectPolicy {
                initial_backoff_seconds: retry_seconds,
                max_backoff_seconds: retry_seconds,
                backoff_multiplier: 1.0,
            },
        );
        let store = Arc::new(
            super::super::FileSystemTrustRegistryStore::new(dir.path().join("records"))
                .await
                .expect("store"),
        );
        mgr.set_store(store.clone())
            .await;
        (mgr, store, dir)
    }

    /// A stored registry with an identity, addressed to a DID unique to the test.
    async fn stored_with_identity(
        store: &super::super::FileSystemTrustRegistryStore,
        status: TrustRegistryConnectionStatus,
    ) -> super::super::types::TrustRegistry {
        let mut registry = stored_registry(Some("did:example:gateway"), Some("did:example:mediator"));
        registry.registry_did = Some(format!("did:example:registry-{}", registry.id));
        registry.connection_status = status;
        store
            .create(&registry)
            .await
            .expect("create");
        registry
    }

    fn registry_did_of(registry: &super::super::types::TrustRegistry) -> String {
        registry
            .registry_did
            .clone()
            .expect("the registry has a DID")
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    async fn eventually_connected(
        mgr: &TrustRegistryListenerManager,
        trust_registry_id: &str,
    ) -> Option<TrustRegistryConnection> {
        for _ in 0..100 {
            if let Some(connection) = connection_of(mgr, trust_registry_id).await {
                return Some(connection);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }

    #[tokio::test]
    async fn concurrent_rebuilds_of_a_stale_registry_share_one_build() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let did = registry_did_of(&registry);
        let stale = connection_to(&registry.id, &did).await;
        mgr.install_connection(stale.clone())
            .await
            .expect("an Active node installs");
        let gate = Arc::new(tokio::sync::Notify::new());
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Hold(gate.clone())]);

        let callers: Vec<_> = (0..5)
            .map(|_| {
                let (mgr, did, stale) = (mgr.clone(), did.clone(), stale.clone());
                tokio::spawn(async move {
                    mgr.rebuild_for_did(&did, &stale, soon())
                        .await
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(200)).await;
        gate.notify_one();

        let mut rebuilt = Vec::new();
        for caller in callers {
            rebuilt.push(
                caller
                    .await
                    .unwrap()
                    .expect("every caller gets the rebuilt client"),
            );
        }
        assert_eq!(super::super::test_builds::calls(&registry.id), 1, "exactly one build runs");
        assert!(
            rebuilt
                .iter()
                .all(|c| c.is_same_client(&rebuilt[0]) && !c.is_same_client(&stale)),
            "every caller uses the same new client"
        );
        let current = connection_of(&mgr, &registry.id)
            .await
            .expect("installed");
        assert!(current.is_same_client(&rebuilt[0]));
    }

    #[tokio::test]
    async fn a_rebuild_request_for_a_replaced_client_returns_the_replacement_without_a_build() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let did = registry_did_of(&registry);
        let stale = connection_to(&registry.id, &did).await;
        let fresh = connection_to(&registry.id, &did).await;
        mgr.install_connection(stale.clone())
            .await
            .expect("an Active node installs");
        mgr.install_connection(fresh.clone())
            .await
            .expect("an Active node installs");
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Connect]);

        let current = mgr
            .rebuild_for_did(&did, &stale, soon())
            .await
            .expect("the replacement is returned");

        assert!(current.is_same_client(&fresh));
        assert_eq!(super::super::test_builds::calls(&registry.id), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_build_aborted_at_its_timeout_shuts_down_the_client_it_created() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let held = Arc::new(tokio::sync::Notify::new());
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Stall(held.clone())]);

        let pending = mgr
            .request_build(BuildKey::Stored(registry.id.clone()), BuildPlan::Stored { allow_failed: false }, None)
            .await
            .expect("the build starts");
        held.notified().await;
        assert_eq!(super::super::test_builds::shutdowns(&registry.id), 0);

        tokio::time::advance(BUILD_TIMEOUT + Duration::from_secs(1)).await;
        let outcome = TrustRegistryListenerManager::await_build(pending, None).await;

        assert!(matches!(outcome, Err(TrustRegistryError::Timeout(_))), "got {:?}", outcome.err());
        assert_eq!(super::super::test_builds::shutdowns(&registry.id), 1);
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_build_that_installs_its_client_does_not_shut_it_down() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Connect]);

        let pending = mgr
            .request_build(BuildKey::Stored(registry.id.clone()), BuildPlan::Stored { allow_failed: false }, None)
            .await
            .expect("the build starts");
        let installed = TrustRegistryListenerManager::await_build(pending, None)
            .await
            .expect("the build installs its client");

        assert_eq!(super::super::test_builds::shutdowns(&registry.id), 0);
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .is_some_and(|current| current.is_same_client(&installed))
        );
    }

    #[tokio::test]
    async fn a_query_never_waits_past_its_timeout_and_the_build_is_installed_afterwards() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let gate = Arc::new(tokio::sync::Notify::new());
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Hold(gate.clone())]);

        let started = Instant::now();
        let result = mgr
            .send_with_reconnect(
                &registry_did_of(&registry),
                trqp::QUERY_AUTHORIZATION,
                json!({}),
                Duration::from_millis(300),
            )
            .await;

        assert!(matches!(result, Err(TrustRegistryError::Timeout(_))), "got {:?}", result.err());
        assert!(started.elapsed() < Duration::from_secs(2), "the query gave up within its own timeout");
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .is_none()
        );
        gate.notify_one();
        assert!(
            eventually_connected(&mgr, &registry.id)
                .await
                .is_some(),
            "the build completes and installs its client for the next query"
        );
        assert_eq!(super::super::test_builds::calls(&registry.id), 1);
    }

    /// A store that cannot be read.
    struct UnreadableStore;

    #[async_trait::async_trait]
    impl TrustRegistryStore for UnreadableStore {
        async fn create(
            &self,
            _trust_registry: &super::super::types::TrustRegistry,
        ) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("the disk is unreadable"))
        }

        async fn get(
            &self,
            _id: &str,
        ) -> anyhow::Result<Option<super::super::types::TrustRegistry>> {
            Err(anyhow::anyhow!("the disk is unreadable"))
        }

        async fn get_by_did(
            &self,
            _did: &str,
        ) -> anyhow::Result<Option<super::super::types::TrustRegistry>> {
            Err(anyhow::anyhow!("the disk is unreadable"))
        }

        async fn list_all(&self) -> anyhow::Result<Vec<super::super::types::TrustRegistry>> {
            Err(anyhow::anyhow!("the disk is unreadable"))
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("the disk is unreadable"))
        }

        async fn update_if_exists(
            &self,
            _trust_registry: &super::super::types::TrustRegistry,
        ) -> anyhow::Result<bool> {
            Err(anyhow::anyhow!("the disk is unreadable"))
        }
        async fn modify(
            &self,
            _id: &str,
            _change: super::super::store::RegistryChange,
        ) -> anyhow::Result<Option<super::super::types::TrustRegistry>> {
            Err(anyhow::anyhow!("the disk is unreadable"))
        }
    }

    #[tokio::test]
    async fn an_unreadable_store_fails_the_query_instead_of_using_a_temporary_identity() {
        let mgr = test_manager();
        mgr.set_store(Arc::new(UnreadableStore))
            .await;
        let did = format!("did:example:stored-{}", uuid::Uuid::new_v4());
        super::super::test_builds::install(&did, vec![super::super::test_builds::Outcome::Connect]);

        let result = mgr
            .connection_for_did(&did, soon())
            .await;

        assert!(matches!(result, Err(TrustRegistryError::ConnectionError(_))), "got {:?}", result.err());
        assert_eq!(super::super::test_builds::calls(&did), 0, "no temporary connection is built");
    }

    #[tokio::test]
    async fn without_a_store_a_registry_is_queried_as_a_public_one() {
        let mgr = test_manager();
        let did = format!("did:example:public-{}", uuid::Uuid::new_v4());
        super::super::test_builds::install(&did, vec![super::super::test_builds::Outcome::Connect]);

        let connection = mgr
            .connection_for_did(&did, soon())
            .await
            .expect("a temporary connection is built");

        assert!(connection.is_temporary);
        assert_eq!(super::super::test_builds::calls(&did), 1);
    }

    #[tokio::test]
    async fn concurrent_queries_to_a_public_registry_share_one_temporary_connection() {
        let (mgr, _store, _dir) = owned_manager(60).await;
        let did = format!("did:example:public-{}", uuid::Uuid::new_v4());
        let gate = Arc::new(tokio::sync::Notify::new());
        super::super::test_builds::install(&did, vec![super::super::test_builds::Outcome::Hold(gate.clone())]);

        let callers: Vec<_> = (0..4)
            .map(|_| {
                let (mgr, did) = (mgr.clone(), did.clone());
                tokio::spawn(async move {
                    mgr.connection_for_did(&did, soon())
                        .await
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(200)).await;
        gate.notify_one();

        let mut connections = Vec::new();
        for caller in callers {
            connections.push(
                caller
                    .await
                    .unwrap()
                    .expect("connected"),
            );
        }
        assert_eq!(super::super::test_builds::calls(&did), 1, "one temporary connection is built");
        assert!(
            connections
                .iter()
                .all(|c| c.is_temporary && c.is_same_client(&connections[0]))
        );
        assert_eq!(
            mgr.active_connection_count()
                .await,
            1
        );
    }

    #[tokio::test]
    async fn a_stored_registry_replaces_the_temporary_connection_to_its_did() {
        let mgr = test_manager();
        let did = format!("did:example:public-{}", uuid::Uuid::new_v4());
        let temporary = temporary_connection_to(&did).await;
        let pending = temporary
            .register_waiter("thread-1".to_string())
            .await;
        mgr.install_connection(temporary.clone())
            .await
            .expect("an Active node installs");

        let stored = connection_to("tr-1", &did).await;
        mgr.install_connection(stored.clone())
            .await
            .expect("an Active node installs");

        assert!(pending.await.is_err(), "the temporary connection is closed");
        assert!(
            connection_of(&mgr, &temporary.trust_registry_id)
                .await
                .is_none()
        );
        let found = mgr
            .connection_for_did(&did, soon())
            .await
            .expect("the DID is served");
        assert!(found.is_same_client(&stored), "queries for the DID use the stored registry's client");
    }

    #[tokio::test]
    async fn a_query_for_a_stored_registry_rebuilds_it_under_its_stored_identity() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::AwaitingApproval).await;
        let did = registry_did_of(&registry);
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Connect]);
        super::super::test_builds::install(&did, vec![super::super::test_builds::Outcome::Connect]);

        let connection = mgr
            .connection_for_did(&did, soon())
            .await
            .expect("rebuilt");

        assert_eq!(connection.trust_registry_id, registry.id);
        assert!(!connection.is_temporary);
        assert_eq!(connection.our_did, "did:example:gateway", "the stored identity is used");
        assert_eq!(super::super::test_builds::calls(&did), 0, "no temporary connection is built");
    }

    #[tokio::test]
    async fn a_query_for_a_failed_registry_fails_fast_without_a_build() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Failed).await;
        let did = registry_did_of(&registry);
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Connect]);
        super::super::test_builds::install(&did, vec![super::super::test_builds::Outcome::Connect]);

        let result = mgr
            .connection_for_did(&did, soon())
            .await;

        assert!(matches!(result, Err(TrustRegistryError::NoConnection(_))), "got {:?}", result.err());
        assert_eq!(super::super::test_builds::calls(&registry.id), 0);
        assert_eq!(super::super::test_builds::calls(&did), 0);
    }

    #[tokio::test]
    async fn automatic_builds_skip_a_failed_registry_and_manual_reconnect_rebuilds_it() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Failed).await;
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Connect]);

        let automatic = TrustRegistryListenerManager::await_build(
            mgr.request_build(BuildKey::Stored(registry.id.clone()), BuildPlan::Stored { allow_failed: false }, None)
                .await
                .expect("requested"),
            Some(soon()),
        )
        .await;
        assert!(matches!(automatic, Err(TrustRegistryError::NoConnection(_))));
        assert_eq!(super::super::test_builds::calls(&registry.id), 0);
        assert!(
            !mgr.retries
                .lock()
                .await
                .contains_key(&registry.id),
            "a Failed registry is not retried in the background"
        );

        let manual = mgr
            .reconnect(&registry.id)
            .await
            .expect("a manual reconnect rebuilds a Failed registry");
        assert_eq!(super::super::test_builds::calls(&registry.id), 1);
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .expect("installed")
                .is_same_client(&manual)
        );
    }

    #[tokio::test]
    async fn reconnect_without_a_stored_identity_fails_without_a_retry() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_registry(None, None);
        store
            .create(&registry)
            .await
            .expect("create");

        let result = mgr
            .reconnect(&registry.id)
            .await;

        assert!(
            matches!(&result, Err(TrustRegistryError::ConnectionError(reason)) if reason.contains("delete and recreate")),
            "got {:?}",
            result.err()
        );
        assert!(
            !mgr.retries
                .lock()
                .await
                .contains_key(&registry.id)
        );
    }

    #[tokio::test]
    async fn reconnect_keeps_the_current_connection_when_secrets_cannot_load() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let connection = connection_to(&registry.id, &registry_did_of(&registry)).await;
        let _pending = connection
            .register_waiter("thread-1".to_string())
            .await;
        mgr.install_connection(connection.clone())
            .await
            .expect("an Active node installs");

        let result = mgr
            .reconnect(&registry.id)
            .await;

        assert!(result.is_err(), "missing key files fail the reconnect");
        assert!(
            connection
                .response_waiters
                .lock()
                .await
                .contains_key("thread-1"),
            "the current connection must stay open"
        );
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .expect("the current connection stays stored")
                .is_same_client(&connection)
        );
    }

    #[tokio::test]
    async fn reconnect_closes_the_current_connection_before_building_a_new_one() {
        let (mgr, store, dir) = owned_manager(60).await;
        let mut registry = stored_registry(None, Some("did:example:mediator"));
        let (our_did, _, _) = generate_trust_registry_identity(
            &registry.id,
            "example.com",
            &dir.path().join("keys"),
            "https://mediator.example.com",
            "did:example:mediator",
            DidMethod::Peer,
            #[cfg(feature = "didwebvh")]
            None,
            #[cfg(feature = "didwebvh")]
            None,
        )
        .await
        .expect("a did:peer identity generates offline");
        registry.our_did = Some(our_did);
        registry.registry_did = Some("did:example:registry".to_string());
        store
            .create(&registry)
            .await
            .expect("create");
        let connection = test_connection(&registry.id).await;
        let pending = connection
            .register_waiter("thread-1".to_string())
            .await;
        mgr.install_connection(connection)
            .await
            .expect("an Active node installs");

        let result = mgr
            .reconnect(&registry.id)
            .await;

        assert!(result.is_err(), "an unresolvable mediator cannot connect");
        let closed = tokio::time::timeout(Duration::from_secs(5), pending).await;
        assert!(matches!(closed, Ok(Err(_))), "the current connection must be closed");
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn reconnect_ignores_the_backoff_and_restarts_it() {
        let (mgr, store, _dir) = owned_manager(600).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        super::super::test_builds::install(
            &registry.id,
            vec![super::super::test_builds::Outcome::Fail("mediator unreachable".to_string())],
        );
        for _ in 0..2 {
            let _ = TrustRegistryListenerManager::await_build(
                mgr.request_build(
                    BuildKey::Stored(registry.id.clone()),
                    BuildPlan::Stored { allow_failed: false },
                    None,
                )
                .await
                .expect("requested"),
                Some(soon()),
            )
            .await;
        }
        let failures = |mgr: Arc<TrustRegistryListenerManager>, id: String| async move {
            mgr.retries
                .lock()
                .await
                .get(&id)
                .map(|retry| retry.failures)
        };
        assert_eq!(failures(mgr.clone(), registry.id.clone()).await, Some(2));

        let result = mgr
            .reconnect(&registry.id)
            .await;

        assert!(result.is_err());
        assert_eq!(super::super::test_builds::calls(&registry.id), 3, "the reconnect builds at once");
        assert_eq!(failures(mgr.clone(), registry.id.clone()).await, Some(1), "the backoff restarts");
    }

    #[tokio::test]
    async fn a_background_retry_recovers_a_registry_without_traffic() {
        let (mgr, store, _dir) = owned_manager(1).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        super::super::test_builds::install(
            &registry.id,
            vec![
                super::super::test_builds::Outcome::Fail("mediator unreachable".to_string()),
                super::super::test_builds::Outcome::Connect,
            ],
        );

        let first = TrustRegistryListenerManager::await_build(
            mgr.request_build(BuildKey::Stored(registry.id.clone()), BuildPlan::Stored { allow_failed: false }, None)
                .await
                .expect("requested"),
            Some(soon()),
        )
        .await;
        assert!(first.is_err());

        assert!(
            eventually_connected(&mgr, &registry.id)
                .await
                .is_some(),
            "the background retry installs the client"
        );
        assert_eq!(super::super::test_builds::calls(&registry.id), 2);
        assert!(
            !mgr.retries
                .lock()
                .await
                .contains_key(&registry.id),
            "a successful build stops the retries"
        );
    }

    #[tokio::test]
    async fn a_standby_node_refuses_to_build() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let did = registry_did_of(&registry);
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Connect]);
        mgr.deactivate();

        let query = mgr
            .connection_for_did(&did, soon())
            .await;
        let reconnect = mgr
            .reconnect(&registry.id)
            .await;

        assert!(matches!(query, Err(TrustRegistryError::NoConnection(_))));
        assert!(matches!(reconnect, Err(TrustRegistryError::NoConnection(_))));
        assert_eq!(super::super::test_builds::calls(&registry.id), 0, "no client is built");
        assert_eq!(
            store
                .get(&registry.id)
                .await
                .unwrap()
                .unwrap()
                .connection_status,
            TrustRegistryConnectionStatus::Connected,
            "nothing is written"
        );
    }

    #[tokio::test]
    async fn a_build_running_when_the_node_steps_down_is_not_installed() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let gate = Arc::new(tokio::sync::Notify::new());
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Hold(gate.clone())]);
        let pending = mgr
            .request_build(BuildKey::Stored(registry.id.clone()), BuildPlan::Stored { allow_failed: false }, None)
            .await
            .expect("requested");
        tokio::time::sleep(Duration::from_millis(100)).await;

        mgr.deactivate();
        mgr.disconnect_all().await;
        gate.notify_one();

        let outcome = TrustRegistryListenerManager::await_build(pending, Some(soon())).await;
        assert!(matches!(outcome, Err(TrustRegistryError::NoConnection(_))), "got {:?}", outcome.err());
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_delete_is_final() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let gate = Arc::new(tokio::sync::Notify::new());
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Hold(gate.clone())]);
        let pending = mgr
            .request_build(BuildKey::Stored(registry.id.clone()), BuildPlan::Stored { allow_failed: false }, None)
            .await
            .expect("requested");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let delete = {
            let (mgr, id) = (mgr.clone(), registry.id.clone());
            tokio::spawn(async move { mgr.delete_registry(&id).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        gate.notify_one();
        delete
            .await
            .expect("delete task");
        store
            .delete(&registry.id)
            .await
            .expect("delete");

        let outcome = TrustRegistryListenerManager::await_build(pending, Some(soon())).await;
        assert!(matches!(outcome, Err(TrustRegistryError::NotFound(_))), "got {:?}", outcome.err());
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .is_none(),
            "the running build's client is never installed"
        );
        let later = mgr
            .request_build(BuildKey::Stored(registry.id.clone()), BuildPlan::Stored { allow_failed: true }, None)
            .await;
        assert!(matches!(later, Err(TrustRegistryError::NotFound(_))), "later rebuilds are refused");
        assert_eq!(super::super::test_builds::calls(&registry.id), 1);
        assert!(
            store
                .get(&registry.id)
                .await
                .unwrap()
                .is_none(),
            "nothing brings the record back"
        );
    }

    #[tokio::test]
    async fn deleting_a_registry_fails_the_queries_waiting_on_it() {
        let mgr = test_manager();
        let connection = test_connection("tr-1").await;
        let pending = connection
            .register_waiter("thread-1".to_string())
            .await;
        mgr.install_connection(connection)
            .await
            .expect("an Active node installs");

        mgr.delete_registry("tr-1")
            .await;

        assert!(pending.await.is_err());
        let reinstalled = mgr
            .install_connection(test_connection("tr-1").await)
            .await;
        assert!(matches!(reinstalled, Err(TrustRegistryError::NotFound(_))));
    }

    #[tokio::test]
    async fn registry_did_for_prefers_the_live_connection_and_falls_back_to_the_record() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        assert_eq!(
            mgr.registry_did_for(&registry.id)
                .await,
            Some(registry_did_of(&registry))
        );

        let mut live = connection_to(&registry.id, "did:example:transport").await;
        live.main_did = Some("did:example:canonical".to_string());
        mgr.install_connection(live)
            .await
            .expect("an Active node installs");
        assert_eq!(
            mgr.registry_did_for(&registry.id)
                .await,
            Some("did:example:canonical".to_string())
        );
        assert_eq!(
            mgr.registry_did_for("missing")
                .await,
            None
        );
    }

    #[tokio::test]
    async fn a_leftover_temporary_connection_does_not_serve_a_failed_stored_registry() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Failed).await;
        let did = registry_did_of(&registry);
        mgr.install_connection(temporary_connection_to(&did).await)
            .await
            .expect("an Active node installs");

        let result = mgr
            .connection_for_did(&did, soon())
            .await;

        assert!(
            matches!(result, Err(TrustRegistryError::NoConnection(_))),
            "got {:?}",
            result
                .ok()
                .map(|c| c.trust_registry_id)
        );
    }

    #[tokio::test]
    async fn a_temporary_connection_is_closed_when_a_stored_registry_already_serves_its_did() {
        let mgr = test_manager();
        let did = format!("did:example:public-{}", uuid::Uuid::new_v4());
        let stored = connection_to("tr-1", &did).await;
        mgr.install_connection(stored.clone())
            .await
            .expect("an Active node installs");
        let temporary = temporary_connection_to(&did).await;
        let pending = temporary
            .register_waiter("thread-1".to_string())
            .await;

        let serving = mgr
            .install_connection(temporary.clone())
            .await
            .expect("the stored connection serves the DID");

        assert!(serving.is_same_client(&stored));
        assert!(pending.await.is_err(), "the temporary connection is closed");
        assert!(
            connection_of(&mgr, &temporary.trust_registry_id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_build_whose_registry_is_marked_failed_meanwhile_is_not_installed() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let mut registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let gate = Arc::new(tokio::sync::Notify::new());
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Hold(gate.clone())]);
        let pending = mgr
            .request_build(BuildKey::Stored(registry.id.clone()), BuildPlan::Stored { allow_failed: false }, None)
            .await
            .expect("requested");
        tokio::time::sleep(Duration::from_millis(100)).await;

        registry.connection_status = TrustRegistryConnectionStatus::Failed;
        assert!(
            store
                .update_if_exists(&registry)
                .await
                .expect("update")
        );
        gate.notify_one();

        let outcome = TrustRegistryListenerManager::await_build(pending, Some(soon())).await;
        assert!(matches!(outcome, Err(TrustRegistryError::NoConnection(_))), "got {:?}", outcome.err());
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn delete_waits_for_a_running_build_to_finish() {
        let (mgr, store, _dir) = owned_manager(60).await;
        let registry = stored_with_identity(&store, TrustRegistryConnectionStatus::Connected).await;
        let gate = Arc::new(tokio::sync::Notify::new());
        super::super::test_builds::install(&registry.id, vec![super::super::test_builds::Outcome::Hold(gate.clone())]);
        let _pending = mgr
            .request_build(BuildKey::Stored(registry.id.clone()), BuildPlan::Stored { allow_failed: false }, None)
            .await
            .expect("requested");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let delete = {
            let (mgr, id) = (mgr.clone(), registry.id.clone());
            tokio::spawn(async move { mgr.delete_registry(&id).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!delete.is_finished(), "delete waits while the build runs");

        gate.notify_one();
        tokio::time::timeout(Duration::from_secs(5), delete)
            .await
            .expect("delete returns once the build finishes")
            .expect("delete task");
        assert!(
            connection_of(&mgr, &registry.id)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn no_retry_is_scheduled_for_a_deleted_registry_or_on_a_standby_node() {
        let (mgr, _store, _dir) = owned_manager(60).await;
        mgr.delete_registry("tr-deleted")
            .await;
        mgr.schedule_retry("tr-deleted")
            .await;
        mgr.deactivate();
        mgr.schedule_retry("tr-standby")
            .await;

        assert!(
            mgr.retries
                .lock()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_refused_background_retry_leaves_no_entry() {
        let (mgr, _store, _dir) = owned_manager(1).await;
        mgr.schedule_retry("tr-1")
            .await;
        mgr.deactivate();

        for _ in 0..60 {
            if mgr
                .retries
                .lock()
                .await
                .is_empty()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the refused retry's entry was left behind");
    }

    #[test]
    fn problem_report_error_detects_exact_conflict_code() {
        let body = json!({ "code": "e.p.msg.conflict", "comment": "Reference field already exists" });

        let error = problem_report_error(body);

        assert!(error.is_conflict());
        match error {
            TrustRegistryError::ProblemReport(code, comment) => {
                assert_eq!(code, TR_CONFLICT_CODE);
                assert_eq!(comment, "Reference field already exists");
            }
            other => panic!("Expected ProblemReport, got {other:?}"),
        }
    }

    #[test]
    fn problem_report_error_rejects_non_exact_conflict_codes() {
        for code in ["e.p.msg.internal-error", "conflict", "e.p.msg.conflict-x", "E.P.MSG.CONFLICT"] {
            let error = problem_report_error(json!({ "code": code, "comment": "x" }));
            assert!(!error.is_conflict(), "{code} must not be treated as a conflict");
        }
    }

    #[test]
    fn problem_report_error_reports_malformed_body_as_parse_error() {
        let error = problem_report_error(json!({ "unexpected": true }));

        assert!(matches!(error, TrustRegistryError::ParseError(_)), "got {error:?}");
        assert!(!error.is_conflict());
    }

    #[test]
    fn non_problem_report_errors_are_not_conflicts() {
        assert!(!TrustRegistryError::Timeout("e.p.msg.conflict".to_string()).is_conflict());
        assert!(!TrustRegistryError::SendError("e.p.msg.conflict".to_string()).is_conflict());
    }

    // --- response-waiter demux: the contract send_and_await + reader rely on ---

    fn empty_waiters() -> ResponseWaiters {
        Arc::new(Mutex::new(HashMap::new()))
    }

    #[test]
    fn timed_out_queries_keep_only_the_latest_threads() {
        let threads = TimedOutQueries::default();
        for i in 0..=TIMED_OUT_QUERIES_KEPT {
            threads.record(&format!("thid-{i}"));
        }

        assert!(!threads.contains("thid-0"), "the oldest thread is forgotten");
        assert!(threads.contains("thid-1"));
        assert!(threads.contains(&format!("thid-{TIMED_OUT_QUERIES_KEPT}")));
        assert!(!threads.contains("thid-unknown"));
    }

    fn pending_query(
        waiters: &ResponseWaiters,
        threads: &TimedOutQueries,
        thid: &str,
    ) -> PendingQuery {
        PendingQuery {
            waiters: waiters.clone(),
            timed_out_queries: threads.clone(),
            thid: thid.to_string(),
            answered: false,
        }
    }

    fn problem_report() -> PollResult {
        PollResult {
            msg_type: MSG_TYPE_PROBLEM_REPORT.to_string(),
            body: json!({ "code": "e.p.req.time" }),
        }
    }

    #[tokio::test]
    async fn a_query_dropped_by_an_outer_timeout_is_recorded_and_its_waiter_removed() {
        let (waiters, threads) = (empty_waiters(), TimedOutQueries::default());
        let rx = register_waiter_in(&waiters, "thid-dropped".to_string()).await;
        let pending = pending_query(&waiters, &threads, "thid-dropped");

        let outer = tokio::time::timeout(std::time::Duration::from_millis(20), async move {
            let _pending = pending;
            rx.await
        })
        .await;

        assert!(outer.is_err(), "the outer timeout dropped the query");
        assert!(threads.contains("thid-dropped"), "the late reply is recognised");
        assert!(
            waiters
                .lock()
                .await
                .is_empty(),
            "the waiter is removed"
        );
        assert!(!deliver_response_in(&waiters, "thid-dropped", problem_report()).await);
    }

    #[tokio::test]
    async fn a_query_whose_reader_closed_is_recorded() {
        let (waiters, threads) = (empty_waiters(), TimedOutQueries::default());
        let rx = register_waiter_in(&waiters, "thid-closed".to_string()).await;
        let pending = pending_query(&waiters, &threads, "thid-closed");

        waiters.lock().await.clear();
        assert!(rx.await.is_err());
        drop(pending);

        assert!(threads.contains("thid-closed"), "a reply after the socket reconnects is recognised");
    }

    #[tokio::test]
    async fn an_answered_query_is_not_recorded() {
        let (waiters, threads) = (empty_waiters(), TimedOutQueries::default());
        let rx = register_waiter_in(&waiters, "thid-answered".to_string()).await;
        let mut pending = pending_query(&waiters, &threads, "thid-answered");

        assert!(deliver_response_in(&waiters, "thid-answered", problem_report()).await);
        assert!(rx.await.is_ok());
        pending.answered = true;
        drop(pending);

        assert!(!threads.contains("thid-answered"));
    }

    #[tokio::test]
    async fn a_dropped_query_is_recorded_before_its_waiter_is_removed_while_the_waiters_are_locked() {
        let (waiters, threads) = (empty_waiters(), TimedOutQueries::default());
        let _rx = register_waiter_in(&waiters, "thid-busy".to_string()).await;
        let pending = pending_query(&waiters, &threads, "thid-busy");

        let held = waiters.lock().await;
        drop(pending);
        assert!(threads.contains("thid-busy"), "recorded while the waiter is still registered");
        drop(held);

        for _ in 0..100 {
            if waiters
                .lock()
                .await
                .is_empty()
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the waiter was never removed");
    }

    #[tokio::test]
    async fn an_oob_invitation_is_not_accepted_again_while_the_registry_is_connected() {
        let mgr = test_manager();
        let id = format!("tr-{}", uuid::Uuid::new_v4());
        mgr.install_connection(test_connection(&id).await)
            .await
            .expect("installed");
        super::super::test_builds::install(&id, vec![super::super::test_builds::Outcome::Connect]);

        let result = mgr
            .accept_oob_and_connect(&id, "https://registry.example/oob", &DidMethod::Peer)
            .await;

        assert!(matches!(result, Err(TrustRegistryError::ConnectionError(_))));
        assert_eq!(super::super::test_builds::calls(&id), 0, "no OOB build runs");
    }

    #[tokio::test]
    async fn deliver_routes_response_to_matching_thid() {
        let waiters = empty_waiters();
        let rx = register_waiter_in(&waiters, "thread-1".to_string()).await;

        let delivered = deliver_response_in(
            &waiters,
            "thread-1",
            PollResult {
                msg_type: "resp".to_string(),
                body: json!({ "ok": true }),
            },
        )
        .await;

        assert!(delivered, "a registered waiter must receive its response");
        let received = rx
            .await
            .expect("waiter receives the value");
        assert_eq!(received.msg_type, "resp");
        assert_eq!(received.body, json!({ "ok": true }));
    }

    #[tokio::test]
    async fn deliver_to_unknown_thid_reports_no_waiter() {
        let waiters = empty_waiters();
        let delivered = deliver_response_in(
            &waiters,
            "no-such-thread",
            PollResult {
                msg_type: "resp".to_string(),
                body: json!({}),
            },
        )
        .await;
        assert!(!delivered, "an unmatched thid must report false so the reader logs+drops");
    }

    #[tokio::test]
    async fn concurrent_waiters_are_demuxed_independently() {
        let waiters = empty_waiters();
        let rx_a = register_waiter_in(&waiters, "a".to_string()).await;
        let rx_b = register_waiter_in(&waiters, "b".to_string()).await;

        // Deliver out of registration order to prove routing is keyed by thid.
        assert!(
            deliver_response_in(
                &waiters,
                "b",
                PollResult {
                    msg_type: "B".into(),
                    body: json!(2)
                }
            )
            .await
        );
        assert!(
            deliver_response_in(
                &waiters,
                "a",
                PollResult {
                    msg_type: "A".into(),
                    body: json!(1)
                }
            )
            .await
        );

        assert_eq!(rx_a.await.expect("a").body, json!(1));
        assert_eq!(rx_b.await.expect("b").body, json!(2));
    }

    #[tokio::test]
    async fn clearing_waiters_makes_receivers_fail_fast() {
        let waiters = empty_waiters();
        let rx = register_waiter_in(&waiters, "orphan".to_string()).await;

        // fail_all_waiters drops every sender.
        waiters.lock().await.clear();

        assert!(
            rx.await.is_err(),
            "a dropped sender must resolve the receiver as RecvError so send_and_await returns StaleConnection"
        );
    }

    // --- parse_registry_response: terse error message; body preview lives in debug log ---

    #[test]
    fn parse_error_message_is_terse_and_does_not_leak_body() {
        let body = json!({ "authority_id": "did:web:authority", "entity_id": "did:web:agent" });
        let err = parse_registry_response::<TrqpRecognitionResponse>(body).unwrap_err();
        let msg = match err {
            TrustRegistryError::ParseError(m) => m,
            other => panic!("expected ParseError, got: {:?}", other),
        };
        assert!(msg.starts_with("Failed to parse response: "), "unexpected prefix: {}", msg);
        assert!(msg.contains("missing field"), "expected serde detail in: {}", msg);
        assert!(!msg.contains("body:"), "body preview must not appear in error message: {}", msg);
        assert!(!msg.contains("did:web:authority"), "body content must not appear in error message: {}", msg);
        assert!(!msg.contains("did:web:agent"), "body content must not appear in error message: {}", msg);
    }

    #[test]
    fn parse_error_message_does_not_leak_error_envelope() {
        let body = json!({ "error": "registry unavailable" });
        let err = parse_registry_response::<TrqpRecognitionResponse>(body).unwrap_err();
        let msg = match err {
            TrustRegistryError::ParseError(m) => m,
            other => panic!("expected ParseError, got: {:?}", other),
        };
        assert!(msg.starts_with("Failed to parse response: "), "unexpected prefix: {}", msg);
        assert!(!msg.contains("registry unavailable"), "body content must not appear in error message: {}", msg);
    }

    // --- is_empty_object: only the literal `{}` counts (guardrail 1) ---

    #[test]
    fn is_empty_object_matches_only_the_literal_empty_object() {
        assert!(is_empty_object(&json!({})), "literal {{}} is the sentinel");
        assert!(!is_empty_object(&json!(null)), "null must not match");
        assert!(!is_empty_object(&json!([])), "empty array must not match");
        assert!(!is_empty_object(&json!("")), "empty string must not match");
        assert!(!is_empty_object(&json!({ "recognized": null })), "explicit null field is spec drift, not empty");
        assert!(
            !is_empty_object(&json!({ "entity_id": "did:web:agent" })),
            "partial object (echoed field, no boolean) is spec drift, not empty"
        );
        assert!(!is_empty_object(&json!({ "totally_unrelated": true })), "wrong-shape object is spec drift, not empty");
    }

    #[test]
    fn body_preview_truncates_long_bodies_at_char_boundary() {
        let long_value = "x".repeat(2_000);
        let body = json!({ "noise": long_value });
        let preview = build_body_preview(&body);
        assert!(preview.contains("…(truncated)"), "expected truncation marker in: {}", preview);
        assert!(preview.len() < 1_500, "preview should be capped, got len={}", preview.len());
    }

    #[test]
    fn body_preview_is_verbatim_when_short() {
        let body = json!({ "authority_id": "did:web:a", "entity_id": "did:web:e" });
        let preview = build_body_preview(&body);
        assert_eq!(preview, "{\"authority_id\":\"did:web:a\",\"entity_id\":\"did:web:e\"}");
        assert!(!preview.contains("…(truncated)"));
    }

    #[test]
    fn parse_success_returns_typed_value() {
        let body = json!({ "recognized": true });
        let resp: TrqpRecognitionResponse = parse_registry_response(body).expect("must parse");
        assert!(resp.recognized);
    }

    // --- allowed schemes ---

    #[test]
    fn allows_https() {
        assert!(validate_outbound_url(&parse("https://mediator.example.com/oob?_oobid=abc")).is_ok());
    }

    #[test]
    fn allows_http() {
        assert!(validate_outbound_url(&parse("http://mediator.example.com/oob?_oob=abc")).is_ok());
    }

    // --- scheme blocklist (gadget 1: verbatim fetch) ---

    #[test]
    fn rejects_file_scheme() {
        let err = validate_outbound_url(&parse("file:///etc/passwd")).unwrap_err();
        assert!(err.contains("not allowed"), "unexpected error: {}", err);
    }

    #[test]
    fn rejects_ftp_scheme() {
        let err = validate_outbound_url(&parse("ftp://example.com/resource")).unwrap_err();
        assert!(err.contains("not allowed"), "unexpected error: {}", err);
    }

    // --- localhost (both gadgets) ---

    #[test]
    fn rejects_localhost() {
        let err = validate_outbound_url(&parse("http://localhost/oob?_oobid=x")).unwrap_err();
        assert!(err.contains("not permitted"), "unexpected error: {}", err);
    }

    #[test]
    fn rejects_localhost_subdomain() {
        let err = validate_outbound_url(&parse("http://evil.localhost/oob?_oobid=x")).unwrap_err();
        assert!(err.contains("not permitted"), "unexpected error: {}", err);
    }

    // --- IPv4 loopback (gadget 1 + gadget 2 via mediator_url) ---

    #[test]
    fn rejects_ipv4_loopback_127_0_0_1() {
        assert!(validate_outbound_url(&parse("http://127.0.0.1/oob?_oobid=x")).is_err());
    }

    #[test]
    fn rejects_ipv4_loopback_127_1_2_3() {
        assert!(validate_outbound_url(&parse("http://127.1.2.3/oob?_oobid=x")).is_err());
    }

    // --- IPv4 private ranges ---

    #[test]
    fn rejects_rfc1918_10_block() {
        assert!(validate_outbound_url(&parse("http://10.0.0.1/oob?_oobid=x")).is_err());
    }

    #[test]
    fn rejects_rfc1918_172_16_block() {
        assert!(validate_outbound_url(&parse("http://172.16.0.1/oob?_oobid=x")).is_err());
    }

    #[test]
    fn rejects_rfc1918_192_168_block() {
        assert!(validate_outbound_url(&parse("http://192.168.1.1/oob?_oobid=x")).is_err());
    }

    // --- link-local / cloud metadata (gadget 2: mediator did.json probe) ---

    #[test]
    fn rejects_aws_metadata_ip() {
        assert!(validate_outbound_url(&parse("http://169.254.169.254/latest/meta-data/")).is_err());
    }

    #[test]
    fn rejects_link_local_169_254() {
        assert!(validate_outbound_url(&parse("http://169.254.0.1/oob?_oobid=x")).is_err());
    }

    // --- other blocked IPv4 ---

    #[test]
    fn rejects_unspecified_0_0_0_0() {
        assert!(validate_outbound_url(&parse("http://0.0.0.0/oob?_oobid=x")).is_err());
    }

    #[test]
    fn rejects_cgn_100_64_block() {
        assert!(validate_outbound_url(&parse("http://100.64.0.1/oob?_oobid=x")).is_err());
    }

    // --- IPv6 blocked ranges ---

    #[test]
    fn rejects_ipv6_loopback() {
        assert!(validate_outbound_url(&parse("http://[::1]/oob?_oobid=x")).is_err());
    }

    #[test]
    fn rejects_ipv6_unique_local_fc00() {
        assert!(validate_outbound_url(&parse("http://[fc00::1]/oob?_oobid=x")).is_err());
    }

    #[test]
    fn rejects_ipv6_link_local_fe80() {
        assert!(validate_outbound_url(&parse("http://[fe80::1]/oob?_oobid=x")).is_err());
    }

    // --- public addresses must pass ---

    #[test]
    fn allows_public_ipv4() {
        assert!(validate_outbound_url(&parse("https://203.0.113.1/oob?_oob=abc")).is_ok());
    }

    #[test]
    fn allows_public_domain() {
        assert!(validate_outbound_url(&parse("https://mediator.affinidi.com/oob?_oob=abc")).is_ok());
    }

    // --- AG_ALLOW_LOCAL_OOB env-gated bypass (dev/test only) ---

    /// Serialises env-var toggles so parallel tests don't observe each other's
    /// AG_ALLOW_LOCAL_OOB state.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env<T>(
        key: &str,
        value: Option<&str>,
        f: impl FnOnce() -> T,
    ) -> T {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var(key).ok();
        // SAFETY: serialised via ENV_LOCK; no other thread reads AG_ALLOW_LOCAL_OOB while the guard is held.
        unsafe {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        let result = f();
        // SAFETY: still under ENV_LOCK.
        unsafe {
            match previous {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        result
    }

    #[test]
    fn skip_outbound_url_validation_defaults_off() {
        with_env("AG_ALLOW_LOCAL_OOB", None, || {
            assert!(!skip_outbound_url_validation());
        });
    }

    #[test]
    fn skip_outbound_url_validation_accepts_truthy_values() {
        for v in ["1", "true", "TRUE", "yes", "YES", "Yes"] {
            with_env("AG_ALLOW_LOCAL_OOB", Some(v), || {
                assert!(skip_outbound_url_validation(), "expected true for {v:?}");
            });
        }
    }

    #[test]
    fn skip_outbound_url_validation_rejects_other_values() {
        for v in ["0", "false", "no", "", "on", "enabled"] {
            with_env("AG_ALLOW_LOCAL_OOB", Some(v), || {
                assert!(!skip_outbound_url_validation(), "expected false for {v:?}");
            });
        }
    }

    // --- did:web / OOB egress guard (SSRF) --------------------------------------

    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Loopback server answering every request with `response`. Loops for reuse.
    async fn spawn_oob_server(response: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(response.as_bytes())
                    .await;
                let _ = sock.flush().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn resolve_did_web_blocks_loopback_fail_closed() {
        // did:web:127.0.0.1 → https://127.0.0.1/.well-known/did.json — blocked
        // before any connection is attempted.
        let err = resolve_did_web_document_inner("did:web:127.0.0.1", false, None)
            .await
            .expect_err("loopback did:web must be rejected");
        let msg = err.to_string();
        assert!(
            msg.to_lowercase()
                .contains("blocked by egress policy"),
            "expected a generic egress-block message, got: {msg}"
        );
        // M-1: the resolved internal address must never leak to the caller.
        assert!(!msg.contains("127.0.0.1"), "error body must not leak the resolved IP, got: {msg}");
    }

    #[tokio::test]
    async fn resolve_did_web_blocks_private_and_metadata_fail_closed() {
        for did in ["did:web:10.0.0.1", "did:web:169.254.169.254", "did:web:192.168.1.1"] {
            let result = resolve_did_web_document_inner(did, false, None).await;
            assert!(result.is_err(), "{did} must be blocked by the egress guard");
        }
    }

    #[tokio::test]
    async fn guarded_oob_get_blocks_loopback_and_hides_ip() {
        let result = guarded_oob_get_inner("http://127.0.0.1:1/oob", true, false, None).await;
        let err = result.expect_err("loopback OOB URL must be blocked");
        assert_eq!(err, "URL blocked by egress policy", "must return a generic message with no address");
    }

    #[tokio::test]
    async fn guarded_oob_get_resolves_allowlisted_loopback() {
        let addr = spawn_oob_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let url = format!("http://{addr}/oob");
        let allow = url.clone();
        let response = guarded_oob_get_inner(&url, true, false, Some(&allow))
            .await
            .expect("allow-listed loopback OOB URL must resolve");
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn guarded_oob_get_skip_hatch_permits_loopback() {
        // Dev/test escape hatch (AG_ALLOW_LOCAL_OOB) falls back to the legacy
        // client so local fixtures keep resolving without the egress guard.
        let addr = spawn_oob_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let url = format!("http://{addr}/oob");
        let response = guarded_oob_get_inner(&url, false, true, None)
            .await
            .expect("skip hatch must allow loopback fetch");
        assert_eq!(response.status(), 200);
    }
}
