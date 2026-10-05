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
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock, oneshot};
use tracing::{debug, error, info, warn};

use crate::comm::didcomm::trust_registry::PollResult;

use super::did_manager::{DidMethod, generate_trust_registry_identity, load_trust_registry_secrets};
use super::store::TrustRegistryStore;
use super::types::{
    TrAdminListRecordsResponse, TrAdminRecordRequest, TrAdminRecordResponse, TrProblemReport,
    TrqpAuthorizationResponse, TrqpQueryRequest, TrqpRecognitionResponse, TrustRecord, TrustRegistryConnectionStatus,
};
use crate::egress::{EgressError, EgressPolicy, bdd_egress_allowlist, guarded_send_inner};
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
}

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
}

/// Maps an in-flight query's `thid` to the oneshot that its `send_and_await`
/// caller is awaiting. The stream reader delivers responses here.
pub(crate) type ResponseWaiters = Arc<Mutex<HashMap<String, oneshot::Sender<PollResult>>>>;

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

    /// Remove a still-pending waiter for `thid` (on timeout / send failure).
    async fn remove_waiter(
        &self,
        thid: &str,
    ) {
        self.response_waiters
            .lock()
            .await
            .remove(thid);
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
}

/// Error type for trust registry communication
#[derive(Debug, Error)]
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
// Listener Manager
// =============================================================================

/// Manages per-registry DIDComm connections to trust registries.
///
/// Each trust registry gets its own connection with a unique did:web identity.
/// Connections are keyed by trust registry ID.
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
}

impl TrustRegistryListenerManager {
    /// Create a new listener manager
    pub fn new(
        domain: String,
        storage_path: PathBuf,
        secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    ) -> Self {
        Self {
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

            let (our_did, registry_did, mediator_did) = match (&tr.our_did, &tr.registry_did, &tr.mediator_did) {
                (Some(o), Some(r), Some(m)) => (o.as_str(), r.as_str(), m.as_str()),
                _ => {
                    warn!(
                        "Trust registry: skipping reconnect for '{}' ({:?}), missing DID fields",
                        tr.id, tr.connection_status
                    );
                    continue;
                }
            };

            match self
                .reconnect(&tr.id, our_did, registry_did, mediator_did, tr.main_did.clone())
                .await
            {
                Ok(()) => {
                    info!("🔗 Trust registry: reconnected to '{}'", tr.id);
                    reconnected += 1;
                }
                Err(e) => warn!("Trust registry: reconnect failed for '{}': {}", tr.id, e),
            }
        }

        reconnected
    }

    pub async fn disconnect_all(&self) -> usize {
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
    pub async fn accept_oob_and_connect(
        &self,
        trust_registry_id: &str,
        oob_url: &str,
        did_method: &DidMethod,
    ) -> Result<OobConnectionInfo, TrustRegistryError> {
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

        // Step 3: Create DIDComm client and connect (pre-cache our DID doc to avoid HTTPS resolution)
        let client = create_tr_client(trust_registry_id, &our_did, &mediator_did, &secrets, Some((&our_did, &did_doc)))
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

        crate::comm::didcomm::trust_registry::pack_and_forward(
            &client,
            &message,
            &our_did,
            &inviter_did,
            &mediator_did,
        )
        .await
        .map_err(TrustRegistryError::SendError)?;

        info!("✓ Connection setup sent to trust registry");

        // Step 5: Register the connection using the inviter DID as the registry DID.
        // The trust registry will process the setup asynchronously (approval flow).
        let registry_did = inviter_did.clone();

        let connection = TrustRegistryConnection {
            trust_registry_id: trust_registry_id.to_string(),
            our_did: our_did.clone(),
            registry_did: registry_did.clone(),
            main_did: main_did.clone(),
            mediator_did: mediator_did.clone(),
            is_temporary: false,
            client,
            response_waiters: Arc::new(Mutex::new(HashMap::new())),
        };

        {
            let mut connections = self.connections.write().await;
            connections.insert(trust_registry_id.to_string(), connection);
        }

        // Start the sole stream reader for this connection so setup/approval
        // responses and future query responses are demultiplexed.
        self.spawn_reader(trust_registry_id)
            .await;

        info!("🔗 Trust registry '{}' connection established — awaiting registry-side approval", trust_registry_id,);

        Ok(OobConnectionInfo {
            our_did,
            registry_did,
            mediator_url,
            mediator_did,
            main_did,
        })
    }

    /// Reconnect to a trust registry using stored secrets (for startup recovery).
    pub async fn reconnect(
        &self,
        trust_registry_id: &str,
        our_did: &str,
        registry_did: &str,
        mediator_did: &str,
        main_did: Option<String>,
    ) -> Result<(), TrustRegistryError> {
        debug!("Reconnecting to trust registry '{}'", trust_registry_id);

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

        let client = create_tr_client(
            trust_registry_id,
            our_did,
            mediator_did,
            &secrets,
            did_doc_to_cache
                .as_ref()
                .map(|doc| (our_did, doc)),
        )
        .await
        .map_err(TrustRegistryError::ConnectionError)?;

        set_acl_to_allow_everything_and_more(client.atm(), client.profile().clone())
            .await
            .map_err(|e| {
                warn!("Could not set ACL for trust registry reconnection: {:?}", e);
            })
            .ok();

        let connection = TrustRegistryConnection {
            trust_registry_id: trust_registry_id.to_string(),
            our_did: our_did.to_string(),
            registry_did: registry_did.to_string(),
            main_did,
            mediator_did: mediator_did.to_string(),
            is_temporary: false,
            client,
            response_waiters: Arc::new(Mutex::new(HashMap::new())),
        };

        {
            let mut connections = self.connections.write().await;
            connections.insert(trust_registry_id.to_string(), connection);
        }

        // Replace any reader bound to the previous (now-evicted) client so the
        // new connection's stream is drained.
        self.stop_reader(trust_registry_id)
            .await;
        self.spawn_reader(trust_registry_id)
            .await;

        debug!("🔗 Trust registry: reconnected to '{}'", trust_registry_id);
        Ok(())
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
            connection
                .fail_all_waiters()
                .await;
            info!("Removed connection for trust registry {}", trust_registry_id);
        }
    }

    /// Look up a stored trust registry by DID (checks main_did, registry_did, did).
    /// Used to reconnect from persisted state when no in-memory connection exists.
    async fn find_stored_trust_registry(
        &self,
        did: &str,
    ) -> Option<super::types::TrustRegistry> {
        let store = self.store.read().await;
        let store = store.as_ref()?;
        match store.list_all().await {
            Ok(registries) => registries
                .into_iter()
                .find(|tr| {
                    tr.connection_status == TrustRegistryConnectionStatus::Connected
                        && (tr.main_did.as_deref() == Some(did)
                            || tr.registry_did.as_deref() == Some(did)
                            || tr.did.as_deref() == Some(did))
                }),
            Err(e) => {
                warn!("Failed to query trust registry store for DID '{}': {}", did, e);
                None
            }
        }
    }

    /// Get active connection count
    #[allow(dead_code)]
    pub async fn active_connection_count(&self) -> usize {
        self.connections
            .read()
            .await
            .len()
    }

    /// Get a clone of a connection by trust registry ID (for the background worker).
    ///
    /// Looks up first by HashMap key (the stored `trust_registry_id`). When
    /// that misses — as happens with temporary connections created by
    /// [`Self::create_temporary_connection`], which are keyed by an
    /// ephemeral `temp-{uuid}` — the method resolves the dashboard trust
    /// registry's DID from the persisted store and retries via
    /// `find_connection_by_did`. This lets the Trust Check stage discover
    /// connections that the legacy path auto-created by DID.
    pub(crate) async fn get_connection_clone(
        &self,
        trust_registry_id: &str,
    ) -> Option<TrustRegistryConnection> {
        let connections = self.connections.read().await;
        if let Some(conn) = connections.get(trust_registry_id) {
            return Some(conn.clone());
        }
        // Fallback: resolve the dashboard trust registry's DID from the
        // persisted store and search by DID instead.
        let store_guard = self.store.read().await;
        let store = store_guard.as_ref()?;
        let registry = store
            .get(trust_registry_id)
            .await
            .ok()??;
        let did = registry
            .main_did
            .as_deref()
            .or(registry
                .registry_did
                .as_deref())
            .or(registry.did.as_deref())?;
        Self::find_connection_by_did(&connections, did)
            .ok()
            .cloned()
    }

    /// Get a connection by trust registry ID
    fn get_connection_by_id<'a>(
        connections: &'a HashMap<String, TrustRegistryConnection>,
        trust_registry_id: &str,
    ) -> Result<&'a TrustRegistryConnection, TrustRegistryError> {
        connections
            .get(trust_registry_id)
            .ok_or_else(|| {
                TrustRegistryError::NoConnection(format!(
                    "No active connection for trust registry '{}'",
                    trust_registry_id
                ))
            })
    }

    /// Find a connection by the trust registry's canonical DID (`main_did`) or transport DID (`registry_did`).
    fn find_connection_by_did<'a>(
        connections: &'a HashMap<String, TrustRegistryConnection>,
        registry_did: &str,
    ) -> Result<&'a TrustRegistryConnection, TrustRegistryError> {
        connections
            .values()
            .find(|c| c.main_did.as_deref() == Some(registry_did) || c.registry_did == registry_did)
            .ok_or_else(|| {
                let known: Vec<String> = connections
                    .values()
                    .map(|c| {
                        format!("id={} registry_did={} main_did={:?}", c.trust_registry_id, c.registry_did, c.main_did)
                    })
                    .collect();
                warn!("No connection found for DID '{}'. Active connections: {:?}", registry_did, known);
                TrustRegistryError::NotFound(format!("No connection found for registry DID '{}'", registry_did))
            })
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

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /// Recover a connection by reconnecting from persisted state or creating a temporary connection.
    async fn recover_or_create_connection(
        &self,
        trust_registry_did: &str,
    ) -> Result<TrustRegistryConnection, TrustRegistryError> {
        if let Some(tr) = self
            .find_stored_trust_registry(trust_registry_did)
            .await
        {
            if let (Some(our_did), Some(registry_did), Some(mediator_did)) =
                (&tr.our_did, &tr.registry_did, &tr.mediator_did)
            {
                info!("Reconnecting to stored trust registry '{}' for DID '{}'", tr.name, trust_registry_did);
                self.reconnect(&tr.id, our_did, registry_did, mediator_did, tr.main_did.clone())
                    .await?;
            } else {
                warn!("Stored trust registry '{}' missing DID fields, falling back to temporary connection", tr.name);
                self.create_temporary_connection(trust_registry_did)
                    .await?;
            }
        } else {
            warn!("No registered connection for DID '{}', creating temporary connection", trust_registry_did);
            self.create_temporary_connection(trust_registry_did)
                .await?;
        }

        let connections = self.connections.read().await;
        Ok(Self::find_connection_by_did(&connections, trust_registry_did)?.clone())
    }

    /// Create a temporary DIDComm connection for querying a public trust registry
    /// that has no pre-established connection.
    ///
    /// The temporary connection is inserted into the connections HashMap so that
    /// subsequent queries (e.g. Q2, Q3 in a 3-query verification flow) reuse it.
    async fn create_temporary_connection(
        &self,
        trust_registry_did: &str,
    ) -> Result<(), TrustRegistryError> {
        info!("Creating temporary connection for public trust registry '{}'", trust_registry_did);

        // Step 1: Resolve the trust registry DID to discover mediator
        let (mediator_url, mediator_did) = resolve_mediator_from_did(trust_registry_did).await?;

        info!("Resolved mediator for '{}': url={}, did={}", trust_registry_did, mediator_url, mediator_did);

        // Step 2: Generate ephemeral did:peer identity (not persisted to disk)
        let temp_id = format!("temp-{}", uuid::Uuid::new_v4());
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
        let client = create_tr_client(&temp_id, &our_did, &mediator_did, &secrets, Some((&our_did, &did_doc)))
            .await
            .map_err(TrustRegistryError::ConnectionError)?;

        set_acl_to_allow_everything_and_more(client.atm(), client.profile().clone())
            .await
            .map_err(|e| {
                warn!("Could not set ACL for temporary trust registry connection: {:?}", e);
            })
            .ok();

        // Step 4: Register the temporary connection
        let connection = TrustRegistryConnection {
            trust_registry_id: temp_id.clone(),
            our_did,
            registry_did: trust_registry_did.to_string(),
            main_did: Some(trust_registry_did.to_string()),
            mediator_did,
            is_temporary: true,
            client,
            response_waiters: Arc::new(Mutex::new(HashMap::new())),
        };

        {
            let mut connections = self.connections.write().await;
            connections.insert(temp_id.clone(), connection);
        }

        // Temporary connections serve queries too, so they need a reader.
        self.spawn_reader(&temp_id)
            .await;

        info!("✓ Temporary connection created for public trust registry '{}' (id: {})", trust_registry_did, temp_id);
        Ok(())
    }

    /// Send with stale connection recovery. On StaleConnection, evicts the dead
    /// connection, reloads secrets from disk, and retries once.
    async fn send_with_reconnect(
        &self,
        trust_registry_did: &str,
        message_type: &str,
        body: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, TrustRegistryError> {
        let connection = {
            let connections = self.connections.read().await;
            match Self::find_connection_by_did(&connections, trust_registry_did) {
                Ok(conn) => conn.clone(),
                Err(TrustRegistryError::NotFound(_)) => {
                    drop(connections);
                    self.recover_or_create_connection(trust_registry_did)
                        .await?
                }
                Err(e) => return Err(e),
            }
        };

        match self
            .send_and_await(&connection, message_type, body.clone(), timeout)
            .await
        {
            Err(TrustRegistryError::StaleConnection(reason)) => {
                warn!("Stale connection to '{}': {}. Reconnecting (one attempt).", trust_registry_did, reason);

                // Evict and reconnect
                self.remove_connection(&connection.trust_registry_id)
                    .await;
                self.reconnect(
                    &connection.trust_registry_id,
                    &connection.our_did,
                    &connection.registry_did,
                    &connection.mediator_did,
                    connection.main_did.clone(),
                )
                .await?;

                let fresh = {
                    let connections = self.connections.read().await;
                    Self::get_connection_by_id(&connections, &connection.trust_registry_id)?.clone()
                };

                // enable_websocket() may return before the WS is fully ready.
                await_websocket_ready(&fresh.client).await;

                self.send_and_await(&fresh, message_type, body, timeout)
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
        timeout: Duration,
    ) -> Result<serde_json::Value, TrustRegistryError> {
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
            .preflight_check(Duration::from_secs(3))
            .await
            .map_err(TrustRegistryError::StaleConnection)?;

        // Register the waiter BEFORE forwarding so a fast response can't race
        // ahead of us and be dropped by the reader as unmatched.
        let rx = connection
            .register_waiter(thread_id.clone())
            .await;

        if let Err(e) = crate::comm::didcomm::trust_registry::pack_and_forward(
            &connection.client,
            &message,
            &connection.our_did,
            &connection.registry_did,
            &connection.mediator_did,
        )
        .await
        {
            connection
                .remove_waiter(&thread_id)
                .await;
            return Err(TrustRegistryError::SendError(e));
        }

        info!("Message forwarded via mediator, waiting for response (timeout: {:?})", timeout);

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => {
                if result.msg_type == MSG_TYPE_PROBLEM_REPORT {
                    let problem: TrProblemReport = serde_json::from_value(result.body).map_err(|e| {
                        TrustRegistryError::ParseError(format!("Failed to parse problem report: {}", e))
                    })?;
                    return Err(TrustRegistryError::ProblemReport(problem.code, problem.comment));
                }
                info!("Received response: {}", result.msg_type);
                Ok(result.body)
            }
            Ok(Err(_recv_err)) => {
                // Sender dropped: the reader exited (disconnect) and failed all
                // waiters. Treat as stale so `send_with_reconnect` reconnects.
                connection
                    .remove_waiter(&thread_id)
                    .await;
                Err(TrustRegistryError::StaleConnection("stream reader closed before a response arrived".to_string()))
            }
            Err(_elapsed) => {
                connection
                    .remove_waiter(&thread_id)
                    .await;
                Err(TrustRegistryError::Timeout(format!("No response within {:?} for thread {}", timeout, thread_id)))
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
) -> Result<crate::comm::didcomm::client::DIDCommClient, String> {
    let mut client = crate::comm::didcomm::client::DIDCommClient::new(
        our_did.to_string(),
        secrets.to_vec(),
        Some(mediator_did.to_string()),
        Some(format!("trust-registry-{}", registry_name)),
    )
    .await?;

    // Cache the DID document BEFORE enabling the WebSocket so the
    // mediator authentication flow finds it without a network fetch.
    if let Some((did, doc)) = did_doc_to_cache {
        client
            .cache_did_document(did, doc.clone())
            .await?;
        info!("✓ Pre-cached DID document for {} in ATM resolver", did);
    }

    client
        .enable_websocket()
        .await?;

    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(url: &str) -> url::Url {
        url::Url::parse(url).expect("test URL must be syntactically valid")
    }

    // --- Active/Standby gate ---

    fn test_manager() -> TrustRegistryListenerManager {
        let dir = tempfile::tempdir().expect("tempdir");
        TrustRegistryListenerManager::new("example.com".to_string(), dir.path().to_path_buf(), None)
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

    // --- response-waiter demux: the contract send_and_await + reader rely on ---

    fn empty_waiters() -> ResponseWaiters {
        Arc::new(Mutex::new(HashMap::new()))
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
