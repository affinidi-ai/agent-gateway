//! WebSocket listener for connection points
//!
//! This module manages WebSocket connections to mediators on behalf of gateway DIDs.
//! When a connection point is created, a WebSocket listener is started that will receive
//! incoming DIDComm messages through the mediator.

use affinidi_messaging_sdk::ATM;
use affinidi_tdk_common::secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::task::AbortHandle;
use tracing::{debug, error, info, instrument, warn};

use super::filesystem::ConnectionPointStore;
use super::message_processor;
use super::messages::{MessageMetadata, MessageStore, ReceivedMessage};
use super::types::GatewayConnectionPoint;
use super::webhook::WebhookClient;
use crate::comm::didcomm::client::DIDCommClient;
use crate::gateways::filesystem::GatewayStore;
use crate::identity::VCIssuer;
use crate::mediators::utils::set_acl_to_allow_everything_and_more;
use crate::messages::MessageType;

/// Emit a WARN reconnect summary every Nth consecutive failure, so a long
/// outage keeps a periodic heartbeat in the logs without one WARN per attempt.
const RECONNECT_SUMMARY_EVERY: u64 = 10;

/// Metrics for a connection point WebSocket listener
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionPointMetrics {
    /// Current status of the listener
    pub status: ConnectionStatus,
    /// When the listener was started
    pub started_at: DateTime<Utc>,
    /// Last time a message was received
    pub last_activity: Option<DateTime<Utc>>,
    /// Total number of messages received
    pub message_count: u64,
    /// Total number of errors encountered
    pub error_count: u64,
    /// Current reconnect attempt number (0 if connected)
    pub reconnect_attempts: u64,
    /// Number of dispatches currently running concurrently for this listener
    #[serde(default)]
    pub in_flight_dispatches: u64,
    /// High-watermark of concurrent in-flight dispatches
    #[serde(default)]
    pub max_in_flight_dispatches: u64,
}

/// Status of a WebSocket connection
pub use crate::comm::connection_health::ConnectionStatus;

impl Default for ConnectionPointMetrics {
    fn default() -> Self {
        Self {
            status: ConnectionStatus::Reconnecting,
            started_at: Utc::now(),
            last_activity: None,
            message_count: 0,
            error_count: 0,
            reconnect_attempts: 0,
            in_flight_dispatches: 0,
            max_in_flight_dispatches: 0,
        }
    }
}

/// Information about an active WebSocket listener
#[derive(Clone)]
pub struct ListenerInfo {
    /// Unique identifier for this listener (same as connection point ID)
    pub id: String,
    /// Runtime instance identifier used to avoid stale listener task cleanup.
    pub instance_id: String,
    /// Gateway ID this connection point belongs to
    pub gateway_id: String,
    /// Connection point ID
    pub connection_point_id: String,
    /// Gateway DID being monitored
    pub gateway_did: String,
    /// Mediator DID being used
    pub mediator_did: String,
    /// Connection point name
    pub name: String,
    /// Connection point type (user-created, OOB inviter, OOB responder, etc.)
    pub cp_type: super::types::ConnectionPointType,
    /// Task abort handle for cleanup
    pub abort_handle: AbortHandle,
    /// Metrics for this listener
    pub metrics: Arc<RwLock<ConnectionPointMetrics>>,
    /// DIDComm client for this connection
    pub client: DIDCommClient,
}

fn listener_index_priority(cp_type: &super::types::ConnectionPointType) -> u8 {
    match cp_type {
        super::types::ConnectionPointType::OobInviter
        | super::types::ConnectionPointType::OobResponder
        | super::types::ConnectionPointType::OobAcceptor => 2,
        super::types::ConnectionPointType::User | super::types::ConnectionPointType::System => 1,
    }
}

fn should_replace_gateway_index(
    existing: Option<&ListenerInfo>,
    incoming: &ListenerInfo,
) -> bool {
    existing
        .is_none_or(|existing| listener_index_priority(&incoming.cp_type) >= listener_index_priority(&existing.cp_type))
}

fn preferred_gateway_listener_id<'a, I>(
    listeners: I,
    gateway_id: &str,
) -> Option<String>
where
    I: IntoIterator<Item = (&'a str, &'a str, &'a super::types::ConnectionPointType)>,
{
    listeners
        .into_iter()
        .filter(|(_, listener_gateway_id, _)| *listener_gateway_id == gateway_id)
        .max_by(|(left_id, _, left_type), (right_id, _, right_type)| {
            listener_index_priority(left_type)
                .cmp(&listener_index_priority(right_type))
                .then_with(|| left_id.cmp(right_id))
        })
        .map(|(id, _, _)| id.to_string())
}

fn recompute_gateway_index_for(
    listeners: &HashMap<String, ListenerInfo>,
    gateway_index: &mut HashMap<String, String>,
    gateway_id: &str,
) {
    if let Some(cp_id) = preferred_gateway_listener_id(
        listeners
            .values()
            .map(|listener| (listener.id.as_str(), listener.gateway_id.as_str(), &listener.cp_type)),
        gateway_id,
    ) {
        gateway_index.insert(gateway_id.to_string(), cp_id);
    } else {
        gateway_index.remove(gateway_id);
    }
}

fn index_gateway_listener(
    listeners: &HashMap<String, ListenerInfo>,
    gateway_index: &mut HashMap<String, String>,
    incoming: &ListenerInfo,
) {
    let existing = gateway_index
        .get(&incoming.gateway_id)
        .and_then(|cp_id| listeners.get(cp_id));

    if should_replace_gateway_index(existing, incoming) {
        gateway_index.insert(incoming.gateway_id.clone(), incoming.id.clone());
    } else if let Some(existing) = existing {
        debug!(
            gateway_id = %incoming.gateway_id,
            existing_cp_id = %existing.id,
            existing_cp_type = ?existing.cp_type,
            incoming_cp_id = %incoming.id,
            incoming_cp_type = ?incoming.cp_type,
            "Keeping existing gateway listener index entry with higher priority"
        );
    }
}

/// Manages WebSocket listeners for connection points
#[derive(Clone)]
pub struct ConnectionPointListenerManager {
    /// Active listeners keyed by connection point ID
    listeners: Arc<RwLock<HashMap<String, ListenerInfo>>>,
    /// Secondary index mapping `gateway_id` → `connection_point_id` for O(1)
    /// reverse lookups in [`Self::get_listener`]. Maintained in lock-step
    /// with `listeners` at every insert / remove site.
    gateway_index: Arc<RwLock<HashMap<String, String>>>,
    /// Identity orchestrator for accessing gateway DID secrets
    #[allow(dead_code)]
    vc_issuer: Arc<VCIssuer>,
    /// Message store for persisting received messages
    message_store: Arc<MessageStore>,
    /// Connection point store for managing connection points
    cp_store: Arc<crate::gateways::FileSystemConnectionPointStore>,
    /// Gateway store for managing gateway connections (optional)
    gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    /// Pending connection store for tracking OOB handshakes (optional)
    pending_connection_store: Option<Arc<crate::gateways::PendingConnectionStore>>,
    /// Mediator store for resolving mediator IDs
    mediator_store: Option<Arc<crate::mediators::FileSystemMediatorStore>>,
    /// Notification store for sending system notifications (optional)
    notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    /// Bootstrap config for storage paths
    bootstrap_config: Option<Arc<crate::config::BootstrapConfig>>,
    /// Network config for DID domain and WebAuthn settings
    network_config: Option<Arc<crate::config::NetworkConfig>>,
    /// Self-reference for starting new listeners from within message handlers
    self_ref: Option<std::sync::Weak<Self>>,
    /// Channel for starting listeners from within async contexts
    listener_start_tx: Option<tokio::sync::mpsc::UnboundedSender<ListenerStartCommand>>,
    /// DID document cache for resilient gateway communication
    did_cache: Arc<crate::gateways::did_cache::DIDCache>,
    /// Whether listeners may be started; false while in Standby mode.
    listeners_active: Arc<AtomicBool>,
    /// Connection point IDs that currently have a listener startup in progress.
    starting_listeners: Arc<Mutex<HashSet<String>>>,
    /// Notifies concurrent startup callers when an in-flight startup completes.
    starting_listeners_notify: Arc<Notify>,
    event_hook: Option<Arc<crate::event_hook::EventHook>>,
}

/// Command to start a new listener
pub struct ListenerStartCommand {
    pub connection_point: super::types::GatewayConnectionPoint,
    pub mediator_did: String,
    pub mediator_url: String,
    /// Oneshot channel to notify when listener is started (or failed)
    pub completion_tx: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

impl ConnectionPointListenerManager {
    /// Create a new listener manager
    pub async fn new(
        vc_issuer: Arc<VCIssuer>,
        message_store: Arc<MessageStore>,
        cp_store: Arc<crate::gateways::FileSystemConnectionPointStore>,
        did_cache_config: crate::gateways::did_cache::DIDCacheConfig,
    ) -> anyhow::Result<Self> {
        // Create DID cache with provided configuration
        let did_cache = Arc::new(crate::gateways::did_cache::DIDCache::new(did_cache_config).await?);

        Ok(Self {
            listeners: Arc::new(RwLock::new(HashMap::new())),
            gateway_index: Arc::new(RwLock::new(HashMap::new())),
            vc_issuer,
            message_store,
            cp_store,
            gateway_store: None,
            pending_connection_store: None,
            mediator_store: None,
            notification_store: None,
            bootstrap_config: None,
            network_config: None,
            self_ref: None,
            listener_start_tx: None,
            did_cache,
            listeners_active: Arc::new(AtomicBool::new(true)),
            starting_listeners: Arc::new(Mutex::new(HashSet::new())),
            starting_listeners_notify: Arc::new(Notify::new()),
            event_hook: None,
        })
    }

    /// Set self-reference and create listener start channel
    pub fn with_self_ref_and_channel(
        mut self,
        self_ref: std::sync::Weak<Self>,
    ) -> (Self, tokio::sync::mpsc::UnboundedReceiver<ListenerStartCommand>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.self_ref = Some(self_ref);
        self.listener_start_tx = Some(tx);
        (self, rx)
    }

    /// Request to start a listener asynchronously
    /// Returns a oneshot receiver that will be notified when the listener is started
    pub fn request_start_listener(
        &self,
        connection_point: super::types::GatewayConnectionPoint,
        mediator_did: String,
        mediator_url: String,
    ) -> Result<tokio::sync::oneshot::Receiver<Result<(), String>>, String> {
        if !self.is_active() {
            return Err("Connection point listeners are currently deactivated".to_string());
        }

        if let Some(tx) = &self.listener_start_tx {
            let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();

            tx.send(ListenerStartCommand {
                connection_point,
                mediator_did,
                mediator_url,
                completion_tx: Some(completion_tx),
            })
            .map_err(|e| format!("Failed to send listener start command: {}", e))?;

            Ok(completion_rx)
        } else {
            Err("Listener start channel not initialized".to_string())
        }
    }

    /// Set the gateway store (for OOB connection finalization)
    pub fn with_gateway_store(
        mut self,
        store: Arc<crate::gateways::FileSystemGatewayStore>,
    ) -> Self {
        self.gateway_store = Some(store);
        self
    }

    /// Set the pending connection store (for OOB handshake tracking)
    pub fn with_pending_connection_store(
        mut self,
        store: Arc<crate::gateways::PendingConnectionStore>,
    ) -> Self {
        self.pending_connection_store = Some(store);
        self
    }

    /// Set the mediator store (for mediator lookup during listener startup)
    pub fn with_mediator_store(
        mut self,
        store: Arc<crate::mediators::FileSystemMediatorStore>,
    ) -> Self {
        self.mediator_store = Some(store);
        self
    }

    /// Set the notification store (for system notifications)
    pub fn with_notification_store(
        mut self,
        store: Arc<crate::integrations::FileSystemNotificationStore>,
    ) -> Self {
        self.notification_store = Some(store);
        self
    }

    /// Set the bootstrap config (for storage paths)
    pub fn with_bootstrap_config(
        mut self,
        config: Arc<crate::config::BootstrapConfig>,
    ) -> Self {
        self.bootstrap_config = Some(config);
        self
    }

    pub fn with_event_hook(
        mut self,
        hook: Arc<crate::event_hook::EventHook>,
    ) -> Self {
        self.event_hook = Some(hook);
        self
    }

    pub(crate) fn event_hook(&self) -> Option<&Arc<crate::event_hook::EventHook>> {
        self.event_hook.as_ref()
    }

    /// Set the network config (for DID domain and WebAuthn settings)
    pub fn with_network_config(
        mut self,
        config: Arc<crate::config::NetworkConfig>,
    ) -> Self {
        self.network_config = Some(config);
        self
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
            info!("Connection point listeners activated");
        }
    }

    pub fn deactivate(&self) {
        let was_active = self
            .listeners_active
            .swap(false, Ordering::SeqCst);
        if was_active {
            info!("Connection point listeners deactivated");
        }
    }

    pub async fn deactivate_and_stop_all_listeners(&self) {
        self.deactivate();
        self.stop_all_listeners()
            .await;
    }

    pub async fn activate_and_start_all_listeners(&self) {
        self.activate();

        let Some(config) = self.bootstrap_config.clone() else {
            warn!("Cannot activate connection-point listeners: bootstrap config not set");
            return;
        };

        if let Err(e) = self
            .cp_store
            .refresh_from_disk()
            .await
        {
            warn!("Connection point store refresh during activate failed: {e} — using cached state");
        }

        let now = chrono::Utc::now();
        let mut connection_points = match self.cp_store.list_all().await {
            Ok(points) => points,
            Err(e) => {
                error!("Failed to list connection points for activation: {}", e);
                return;
            }
        };

        let mut expired_count = 0usize;
        for cp in &connection_points {
            let is_expired = if let Some(struct_expires_at) = cp.expires_at {
                struct_expires_at < now
            } else if let Some(expires_at_value) = cp
                .oob_message
                .get("expires_at")
            {
                if let Ok(json_expires_at) =
                    serde_json::from_value::<chrono::DateTime<chrono::Utc>>(expires_at_value.clone())
                {
                    json_expires_at < now
                } else {
                    false
                }
            } else {
                false
            };

            if is_expired {
                if let Err(e) = self
                    .cp_store
                    .delete(&cp.id)
                    .await
                {
                    warn!("Failed to delete expired connection point '{}': {}", cp.id, e);
                } else {
                    expired_count += 1;
                }
            }
        }

        if expired_count > 0 {
            info!(
                "Cleaned up {} expired connection point{}",
                expired_count,
                if expired_count == 1 {
                    ""
                } else {
                    "s"
                }
            );
        }

        connection_points = match self.cp_store.list_all().await {
            Ok(points) => points,
            Err(e) => {
                error!("Failed to re-fetch connection points for activation: {}", e);
                return;
            }
        };

        let mut started = 0usize;
        let mut failed = 0usize;
        for cp in connection_points {
            let (mediator_did, mediator_url) = match self
                .resolve_mediator_for_cp(&cp)
                .await
            {
                Ok(values) => values,
                Err(e) => {
                    warn!("Skipping connection point '{}' during activation: {}", cp.id, e);
                    failed += 1;
                    continue;
                }
            };

            if let Err(e) = self
                .start_listener(&cp, mediator_did, mediator_url, config.clone())
                .await
            {
                warn!("Failed to start listener for connection point '{}' during activation: {}", cp.id, e);
                failed += 1;
            } else {
                started += 1;
            }
        }

        info!("Connection-point listener activation complete: {} started, {} failed", started, failed);
    }

    /// Start the background check that the mediator still holds every active
    /// listener's account (see [`super::account_watch`]).
    pub fn start_account_watch_task(&self) {
        if let Some(manager) = &self.self_ref {
            super::account_watch::spawn(manager.clone());
        }
    }

    /// Start background cache maintenance task
    /// This task periodically evicts expired DID cache entries
    pub fn start_cache_maintenance_task(&self) {
        let did_cache = Arc::clone(&self.did_cache);

        crate::observability::spawn_traced_task("did_cache.maintenance", async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                interval.tick().await;

                // Evict expired entries
                let evicted = did_cache
                    .evict_expired()
                    .await;
                if evicted > 0 {
                    info!("DID cache maintenance: evicted {} expired entries", evicted);
                }

                // Get cache stats
                let stats = did_cache.stats().await;
                debug!(
                    "DID cache stats: {} total ({} fresh, {} stale, {} expired)",
                    stats.total_entries, stats.fresh_entries, stats.stale_entries, stats.expired_entries
                );

                // Log stale DIDs that should be refreshed
                let stale_dids = did_cache
                    .get_stale_dids()
                    .await;
                if !stale_dids.is_empty() {
                    debug!("DIDs approaching expiration (stale): {}", stale_dids.len());
                    for did in stale_dids.iter().take(5) {
                        debug!("  - {}", did);
                    }
                }
            }
        });

        info!("✓ DID cache maintenance task started (runs every 5 minutes)");
    }

    async fn reserve_listener_start(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<(), String> {
        let cp_id = connection_point.id.as_str();
        loop {
            let startup_finished = self
                .starting_listeners_notify
                .notified();

            {
                let listeners = self.listeners.read().await;
                if listeners.contains_key(cp_id) {
                    info!(
                        "WebSocket listener already active for connection point '{}' (ID: {})",
                        connection_point.name, cp_id
                    );
                    return Err("already-active".to_string());
                }
            }

            let should_start = {
                let mut starting = self
                    .starting_listeners
                    .lock()
                    .await;
                if starting.contains(cp_id) {
                    false
                } else {
                    starting.insert(cp_id.to_string());
                    true
                }
            };

            if should_start {
                let became_active = {
                    let listeners = self.listeners.read().await;
                    listeners.contains_key(cp_id)
                };
                if became_active {
                    self.finish_listener_start(cp_id)
                        .await;
                    info!(
                        "WebSocket listener already active for connection point '{}' (ID: {})",
                        connection_point.name, cp_id
                    );
                    return Err("already-active".to_string());
                }
                return Ok(());
            }

            debug!(
                connection_point_id = cp_id,
                "WebSocket listener startup already in progress; waiting for existing startup"
            );
            startup_finished.await;
        }
    }

    async fn finish_listener_start(
        &self,
        connection_point_id: &str,
    ) {
        let removed = self
            .starting_listeners
            .lock()
            .await
            .remove(connection_point_id);
        if removed {
            self.starting_listeners_notify
                .notify_waiters();
        }
    }

    /// Start a WebSocket listener for a connection point
    pub async fn start_listener(
        &self,
        connection_point: &GatewayConnectionPoint,
        mediator_did: String,
        mediator_url: String,
        config: Arc<crate::config::BootstrapConfig>,
    ) -> Result<(), String> {
        if !self.is_active() {
            return Err("Connection point listeners are currently deactivated".to_string());
        }

        let cp_id = connection_point.id.clone();
        if let Err(e) = self
            .reserve_listener_start(connection_point)
            .await
        {
            if e == "already-active" {
                return Ok(());
            }
            return Err(e);
        }

        info!(
            "Starting WebSocket listener for connection point '{}' (Gateway: {}, Mediator: {})",
            connection_point.name, connection_point.gateway_id, mediator_did
        );

        // Load connection point's unique DID and secrets
        // Each connection point has its own DID to avoid duplicate WebSocket connections
        let connection_point_did = connection_point
            .connection_point_did
            .clone();

        info!("Loading secrets for connection point DID: {}", connection_point_did);

        // Load connection point secrets from storage
        let storage_path_str = config
            .storage_paths
            .connection_points
            .clone();
        let storage_path = std::path::PathBuf::from(storage_path_str);
        let cp_storage_id = connection_point.id.clone();

        let secrets = match tokio::task::spawn_blocking(
            move || -> Result<Vec<affinidi_tdk_common::secrets_resolver::secrets::Secret>, String> {
                // This needs to be sync because we're calling blocking file operations
                tokio::runtime::Handle::current().block_on(async {
                    super::handlers::load_connection_point_secrets(&cp_storage_id, &storage_path)
                        .await
                        .map_err(|e| format!("Failed to load connection point secrets: {}", e))
                })
            },
        )
        .await
        .map_err(|e| format!("Task join error: {}", e))
        .and_then(|result| result)
        {
            Ok(secrets) => secrets,
            Err(e) => {
                self.finish_listener_start(&cp_id)
                    .await;
                return Err(e);
            }
        };

        info!("✓ Loaded {} secret(s) for connection point DID", secrets.len());

        let mediator_did_document = match &self.mediator_store {
            Some(store) => {
                listener_mediator_document(store, &connection_point.mediator_id, &mediator_did, &connection_point.name)
                    .await
            }
            None => None,
        };

        // did:key DIDs are self-describing - no need to build/cache DID document
        // The SDK's DID resolver automatically generates it from the DID string

        // Spawn the WebSocket listener task
        let listener_instance_id = uuid::Uuid::new_v4().to_string();
        let listeners_clone = Arc::clone(&self.listeners);
        let gateway_index_clone = Arc::clone(&self.gateway_index);
        let starting_listeners_clone = Arc::clone(&self.starting_listeners);
        let starting_listeners_notify_clone = Arc::clone(&self.starting_listeners_notify);
        let message_store_clone = Arc::clone(&self.message_store);
        let cp_clone = connection_point.clone();
        let cp_id_clone = cp_id.clone();
        let listener_instance_id_clone = listener_instance_id.clone();
        let cp_name = connection_point.name.clone();
        let gateway_id_clone = connection_point
            .gateway_id
            .clone();
        let connection_point_did_clone = connection_point_did.clone();
        let mediator_did_clone = mediator_did.clone();
        let mediator_did_document_clone = mediator_did_document.clone();

        // Create metrics tracker
        let metrics = Arc::new(RwLock::new(ConnectionPointMetrics::default()));
        let metrics_clone = Arc::clone(&metrics);

        // Clone stores for the spawned task
        let gateway_store_clone = self.gateway_store.clone();
        let pending_store_clone = self
            .pending_connection_store
            .clone();
        let notification_store_clone = self
            .notification_store
            .clone();
        let bootstrap_config_clone = self.bootstrap_config.clone();
        let cp_store_clone = Some(Arc::clone(&self.cp_store));
        let manager_weak = self.self_ref.clone();

        // Create a channel to receive DIDCommClient from the spawned task
        let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<DIDCommClient>(1);

        let handle = crate::observability::spawn_traced_task_with_fields(
            "connection_point.listener",
            vec![
                ("cp.name", cp_name.clone()),
                ("cp.id", cp_id_clone.clone()),
                ("cp.did", connection_point_did_clone.clone()),
            ],
            async move {
                if let Err(e) = run_websocket_listener(
                    &cp_clone,
                    &connection_point_did_clone, // Use connection point DID, not gateway DID
                    &mediator_did_clone,
                    &mediator_url,
                    mediator_did_document_clone,
                    secrets,
                    message_store_clone,
                    metrics_clone,
                    client_tx,
                    gateway_store_clone,
                    pending_store_clone,
                    notification_store_clone,
                    bootstrap_config_clone,
                    cp_store_clone,
                    manager_weak,
                )
                .await
                {
                    error!("WebSocket listener error for connection point '{}': {}", cp_name, e);
                }

                // Clean up listener info when task completes — keep the
                // gateway_index in lock-step with `listeners`.
                let mut listeners = listeners_clone.write().await;
                let remove_listener = listeners
                    .get(&cp_id_clone)
                    .is_some_and(|listener| listener.instance_id == listener_instance_id_clone);
                if remove_listener {
                    listeners.remove(&cp_id_clone);
                    let mut idx = gateway_index_clone
                        .write()
                        .await;
                    if idx.get(&gateway_id_clone) == Some(&cp_id_clone) {
                        recompute_gateway_index_for(&listeners, &mut idx, &gateway_id_clone);
                    }
                }
                drop(listeners);
                let removed_start = starting_listeners_clone
                    .lock()
                    .await
                    .remove(&cp_id_clone);
                if removed_start {
                    starting_listeners_notify_clone.notify_waiters();
                }
                info!("WebSocket listener stopped for connection point '{}'", cp_name);
            },
        );

        // Wait for ATM and profile to be sent from the spawned task (with timeout)
        // Use a longer timeout to allow WebSocket connections to establish
        // Authentication can take several seconds, so we give it 30 seconds
        // If it times out, we'll still register the listener so it appears in the UI
        // and pings will wait for actual connection rather than failing immediately
        let client = match tokio::time::timeout(std::time::Duration::from_secs(30), client_rx.recv()).await {
            Ok(Some(client)) => client,
            Ok(None) => {
                self.finish_listener_start(&cp_id)
                    .await;
                return Err("Channel closed before receiving DIDComm client".to_string());
            }
            Err(_) => {
                // Timeout - wait for the connection in a non-blocking way
                // The listener task will keep trying to connect in the background
                warn!(
                    "Timeout waiting for initial connection for connection point '{}', will wait for connection in background",
                    cp_id
                );

                // Spawn a task to wait for the ATM and register the listener once connected
                let listeners_clone = Arc::clone(&self.listeners);
                let gateway_index_clone = Arc::clone(&self.gateway_index);
                let cp_id_clone = cp_id.clone();
                let connection_point_clone = connection_point.clone();
                let connection_point_did_clone = connection_point_did.clone();
                let mediator_did_clone = mediator_did.clone();
                let handle_clone = handle.abort_handle();
                let metrics_clone = Arc::clone(&metrics);
                let cp_store_clone = Arc::clone(&self.cp_store);
                let listener_instance_id_clone = listener_instance_id.clone();
                let starting_listeners_clone = Arc::clone(&self.starting_listeners);
                let starting_listeners_notify_clone = Arc::clone(&self.starting_listeners_notify);
                let self_ref_clone = self.self_ref.clone();

                tokio::spawn(async move {
                    // No abort timeout: the listener task keeps retrying under the
                    // reconnect policy, so we wait for it to connect however long
                    // that takes and register it then (finding #4). If the task
                    // ends first, the channel closes and we simply stop waiting.
                    let received_client = client_rx.recv().await;

                    match received_client {
                        Some(client) => {
                            // Before registering, verify the connection point still exists
                            // If it was deleted while we were connecting, don't register the listener
                            match cp_store_clone
                                .get(&cp_id_clone)
                                .await
                            {
                                Ok(Some(_)) => {
                                    // Connection point still exists, register the listener
                                    let listener_info = ListenerInfo {
                                        id: cp_id_clone.clone(),
                                        instance_id: listener_instance_id_clone.clone(),
                                        gateway_id: connection_point_clone
                                            .gateway_id
                                            .clone(),
                                        connection_point_id: connection_point_clone
                                            .id
                                            .clone(),
                                        gateway_did: connection_point_did_clone,
                                        mediator_did: mediator_did_clone,
                                        name: connection_point_clone
                                            .name
                                            .clone(),
                                        cp_type: connection_point_clone
                                            .cp_type
                                            .clone(),
                                        abort_handle: handle_clone,
                                        metrics: metrics_clone,
                                        client,
                                    };

                                    let old_listener = {
                                        let mut listeners = listeners_clone.write().await;
                                        let mut idx = gateway_index_clone
                                            .write()
                                            .await;
                                        index_gateway_listener(&listeners, &mut idx, &listener_info);
                                        listeners.insert(cp_id_clone.clone(), listener_info)
                                    };
                                    if let Some(old_listener) = old_listener {
                                        old_listener
                                            .client
                                            .atm()
                                            .graceful_shutdown()
                                            .await;
                                        old_listener
                                            .abort_handle
                                            .abort();
                                    }
                                    info!(
                                        "WebSocket listener registered after delayed connection for connection point '{}'",
                                        connection_point_clone.name
                                    );
                                    Self::spawn_peer_issuer_reconciliation(
                                        &self_ref_clone,
                                        connection_point_clone
                                            .gateway_id
                                            .clone(),
                                    );
                                }
                                Ok(None) => {
                                    warn!(
                                        "Connection point '{}' was deleted while establishing connection, not registering listener",
                                        cp_id_clone
                                    );
                                    handle_clone.abort();
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to verify connection point '{}' exists: {}, not registering listener",
                                        cp_id_clone, e
                                    );
                                    handle_clone.abort();
                                }
                            }
                        }
                        None => {
                            warn!(
                                "WebSocket listener task ended before delayed registration for connection point '{}'",
                                cp_id_clone
                            );
                        }
                    }

                    let removed_start = starting_listeners_clone
                        .lock()
                        .await
                        .remove(&cp_id_clone);
                    if removed_start {
                        starting_listeners_notify_clone.notify_waiters();
                    }
                });

                // Return OK - listener will be registered when connection succeeds
                info!(
                    "WebSocket listener task started for connection point '{}' (waiting for connection)",
                    connection_point.name
                );
                return Ok(());
            }
        };

        // Store listener info
        let listener_info = ListenerInfo {
            id: cp_id.clone(),
            instance_id: listener_instance_id.clone(),
            gateway_id: connection_point
                .gateway_id
                .clone(),
            connection_point_id: connection_point.id.clone(),
            gateway_did: connection_point_did.clone(), // Store connection point DID
            mediator_did: mediator_did.clone(),
            name: connection_point.name.clone(),
            cp_type: connection_point
                .cp_type
                .clone(),
            abort_handle: handle.abort_handle(),
            metrics: Arc::clone(&metrics),
            client,
        };

        let old_listener = {
            let mut listeners = self.listeners.write().await;
            let mut idx = self
                .gateway_index
                .write()
                .await;
            index_gateway_listener(&listeners, &mut idx, &listener_info);
            listeners.insert(cp_id.clone(), listener_info)
        };
        if let Some(old_listener) = old_listener {
            old_listener
                .client
                .atm()
                .graceful_shutdown()
                .await;
            old_listener
                .abort_handle
                .abort();
        }
        self.finish_listener_start(&cp_id)
            .await;
        Self::spawn_peer_issuer_reconciliation(
            &self.self_ref,
            connection_point
                .gateway_id
                .clone(),
        );

        info!("WebSocket listener started successfully for connection point '{}'", connection_point.name);
        Ok(())
    }

    /// Stop a WebSocket listener for a connection point
    pub async fn stop_listener(
        &self,
        connection_point_id: &str,
    ) -> Result<(), String> {
        let listener = {
            let mut listeners = self.listeners.write().await;
            let listener = listeners.remove(connection_point_id);
            if let Some(listener) = &listener {
                let mut idx = self
                    .gateway_index
                    .write()
                    .await;
                if idx.get(&listener.gateway_id) == Some(&listener.id) {
                    recompute_gateway_index_for(&listeners, &mut idx, &listener.gateway_id);
                }
            }
            listener
        };

        if let Some(listener) = listener {
            info!("Stopping WebSocket listener for connection point '{}'", listener.name);
            listener
                .client
                .atm()
                .graceful_shutdown()
                .await;
            listener.abort_handle.abort();
            Ok(())
        } else {
            Err(format!("No listener found for connection point {}", connection_point_id))
        }
    }

    /// Update the name of a listener (when connection point is renamed)
    pub async fn update_listener_name(
        &self,
        connection_point_id: &str,
        new_name: String,
    ) -> Result<(), String> {
        let mut listeners = self.listeners.write().await;

        if let Some(listener) = listeners.get_mut(connection_point_id) {
            let old_name = listener.name.clone();
            listener.name = new_name.clone();
            info!("Updated listener name from '{}' to '{}'", old_name, new_name);
            Ok(())
        } else {
            Err(format!("No listener found for connection point {}", connection_point_id))
        }
    }

    /// Replace the DIDComm client stored for an active listener.
    ///
    /// Called by the listener supervision loop after it reconnects to the
    /// mediator so that outbound sends and x402 use the live socket instead of
    /// the dead client captured when the listener was first registered.
    pub async fn update_listener_client(
        &self,
        connection_point_id: &str,
        client: DIDCommClient,
    ) {
        let mut listeners = self.listeners.write().await;
        if let Some(listener) = listeners.get_mut(connection_point_id) {
            listener.client = client;
            debug!("Refreshed DIDComm client for connection point '{}' after reconnect", connection_point_id);
        }
    }

    /// Resolve the (mediator_did, mediator_url) for a connection point, mirroring
    /// the resolution used when listeners are first started.
    async fn resolve_mediator_for_cp(
        &self,
        cp: &super::types::GatewayConnectionPoint,
    ) -> Result<(String, String), String> {
        use crate::mediators::filesystem::MediatorStore;

        if cp
            .mediator_id
            .starts_with("did:")
        {
            let url = crate::gateways::connection_points::extract_mediator_url(&cp.mediator_id)
                .map_err(|e| format!("Failed to extract mediator URL from DID '{}': {}", cp.mediator_id, e))?;
            Ok((cp.mediator_id.clone(), url))
        } else {
            let store = self
                .mediator_store
                .as_ref()
                .ok_or_else(|| format!("mediator store unavailable for mediator ID '{}'", cp.mediator_id))?;
            match store
                .get(&cp.mediator_id)
                .await
            {
                Ok(Some(mediator)) => {
                    let url = crate::gateways::connection_points::extract_mediator_url(&mediator.did)
                        .map_err(|e| format!("Failed to extract mediator URL from DID '{}': {}", mediator.did, e))?;
                    Ok((mediator.did.clone(), url))
                }
                Ok(None) => Err(format!("mediator '{}' not found", cp.mediator_id)),
                Err(e) => Err(format!("failed to load mediator '{}': {}", cp.mediator_id, e)),
            }
        }
    }

    /// Force a connection point's listener to reconnect to the mediator and
    /// return it once it is live again. Used by request handlers for instant
    /// recovery when a pre-flight check shows the connection is stale (e.g. the
    /// mediator flushed the account). Reuses the tested stop + start path and
    /// its completion signal, so the returned client is already
    /// re-authenticated with its ACL re-applied before the caller retries.
    ///
    /// If a concurrent caller has already restored the listener, the existing
    /// live listener is returned without a second restart.
    pub async fn reconnect_listener(
        &self,
        connection_point_id: &str,
        timeout: std::time::Duration,
    ) -> Result<ListenerInfo, String> {
        if let Some(current) = self
            .get_listener(connection_point_id)
            .await
            && current
                .client
                .preflight_check(std::time::Duration::from_secs(3))
                .await
                .is_ok()
        {
            return Ok(current);
        }

        self.restart_listener(connection_point_id, timeout)
            .await
    }

    /// Restart a Connection Point's listener for a caller that knows the
    /// mediator session of the listener instance it used is unusable (e.g. the
    /// mediator reported our account missing), and return it once it is live.
    ///
    /// When the current listener is no longer `instance_id`, another caller
    /// has already replaced it; that listener is returned without a restart,
    /// so concurrent callers do not tear down each other's fresh session.
    /// When there is no current listener, the Connection Point was stopped
    /// (removed, or being restarted by another caller) since the caller read
    /// it, so it is not started again.
    pub async fn restart_listener_if_current(
        &self,
        connection_point_id: &str,
        instance_id: &str,
        timeout: std::time::Duration,
    ) -> Result<ListenerInfo, String> {
        let Some(current) = self
            .get_listener(connection_point_id)
            .await
        else {
            return Err(format!("Connection point '{connection_point_id}' has no running listener; not restarting it"));
        };
        if current.instance_id != instance_id {
            return Ok(current);
        }

        self.restart_listener(connection_point_id, timeout)
            .await
    }

    async fn restart_listener(
        &self,
        connection_point_id: &str,
        timeout: std::time::Duration,
    ) -> Result<ListenerInfo, String> {
        let cp = self
            .cp_store
            .get(connection_point_id)
            .await
            .map_err(|e| format!("Failed to load connection point '{}': {}", connection_point_id, e))?
            .ok_or_else(|| format!("Connection point '{}' not found", connection_point_id))?;
        let (mediator_did, mediator_url) = self
            .resolve_mediator_for_cp(&cp)
            .await?;

        let _ = self
            .stop_listener(connection_point_id)
            .await;
        let completion = self.request_start_listener(cp, mediator_did, mediator_url)?;

        match tokio::time::timeout(timeout, completion).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => return Err(format!("listener restart failed: {}", e)),
            Ok(Err(_)) => return Err("listener restart completion channel dropped".to_string()),
            Err(_) => return Err(format!("listener restart timed out after {:?}", timeout)),
        }

        self.get_listener(connection_point_id)
            .await
            .ok_or_else(|| format!("listener '{}' missing after restart", connection_point_id))
    }

    /// Get information about active listeners
    pub async fn get_active_listeners(&self) -> Vec<ListenerInfo> {
        let listeners = self.listeners.read().await;
        listeners
            .values()
            .cloned()
            .collect()
    }

    /// Get listener info for a specific gateway or connection point ID
    pub async fn get_listener(
        &self,
        id: &str,
    ) -> Option<ListenerInfo> {
        let listeners = self.listeners.read().await;
        // Try as connection point ID first.
        if let Some(listener) = listeners.get(id) {
            return Some(listener.clone());
        }
        // Otherwise resolve the gateway_id → connection_point_id mapping
        // (O(1) via the secondary index) instead of linear-scanning all
        // listeners.
        let idx = self
            .gateway_index
            .read()
            .await;
        if let Some(cp_id) = idx.get(id)
            && let Some(listener) = listeners.get(cp_id)
        {
            return Some(listener.clone());
        }
        None
    }

    #[cfg(test)]
    pub(crate) async fn register_test_listener(
        &self,
        listener: ListenerInfo,
    ) {
        let mut listeners = self.listeners.write().await;
        let mut gateway_index = self
            .gateway_index
            .write()
            .await;
        index_gateway_listener(&listeners, &mut gateway_index, &listener);
        listeners.insert(listener.id.clone(), listener);
    }

    /// Get ATM instance for a specific connection point
    #[allow(dead_code)]
    pub async fn get_atm_for_connection_point(
        &self,
        connection_point_id: &str,
    ) -> Option<(Arc<ATM>, Arc<affinidi_messaging_sdk::profiles::ATMProfile>)> {
        let listeners = self.listeners.read().await;
        listeners
            .get(connection_point_id)
            .map(|info| (Arc::clone(info.client.atm()), Arc::clone(info.client.profile())))
    }

    /// Get the remote gateway DID for a gateway ID
    pub async fn get_gateway_did(
        &self,
        gateway_id: &str,
    ) -> Option<String> {
        if let Some(ref store) = self.gateway_store {
            store
                .get(gateway_id)
                .await
                .ok()
                .flatten()
                .map(|gw| gw.did)
        } else {
            None
        }
    }

    /// The DID of an active Remote gateway, and the tenant owning its record.
    pub(crate) async fn get_active_stream_peer(
        &self,
        gateway_id: &str,
    ) -> Option<(String, Option<String>)> {
        let peer = self
            .gateway_store
            .as_ref()?
            .get(gateway_id)
            .await
            .ok()??;
        peer.is_active_remote_peer()
            .then_some((peer.did, peer.tenant_id))
    }

    pub(crate) fn fabric_stream_max_envelope_bytes(&self) -> usize {
        stream_envelope_limit(self.bootstrap_config.as_ref())
    }

    /// Get ATM instance for a mediator (uses first connection point with that mediator)
    #[allow(dead_code)]
    pub async fn get_atm_for_mediator(
        &self,
        mediator_id: &str,
    ) -> Option<(Arc<ATM>, Arc<affinidi_messaging_sdk::profiles::ATMProfile>, String)> {
        let listeners = self.listeners.read().await;
        for info in listeners.values() {
            if info.mediator_did == mediator_id {
                return Some((Arc::clone(info.client.atm()), Arc::clone(info.client.profile()), info.id.clone()));
            }
        }
        None
    }

    /// Get the DID cache
    pub fn get_did_cache(&self) -> Arc<crate::gateways::did_cache::DIDCache> {
        Arc::clone(&self.did_cache)
    }

    /// The Gateway record whose `did` is the given Connection Point DID.
    pub async fn find_gateway_by_did(
        &self,
        did: &str,
    ) -> Option<crate::gateways::types::Gateway> {
        let store = self.gateway_store.as_ref()?;
        match store.get_by_did(did).await {
            Ok(gateway) => gateway,
            Err(e) => {
                warn!("Failed to look up gateway by DID {}: {}", did, e);
                None
            }
        }
    }

    /// Return the peer's verified issuer DID for a Remote gateway, running the
    /// `gateway-issuer-request` exchange over the pairing's Connection Point
    /// when the record does not hold it yet, and persisting the result.
    pub async fn ensure_peer_issuer_did(
        &self,
        gateway_id: &str,
    ) -> Result<String, crate::gateways::issuer_exchange::PeerIssuerError> {
        use crate::gateways::issuer_attestation::{ExpectedAttestation, verify_issuer_attestation};
        use crate::gateways::issuer_exchange::{
            ISSUER_REQUEST_TIMEOUT, PeerIssuerError, attestation_from_issuer_response, build_issuer_request,
        };
        use crate::proxy::fabric_response_waiter::{
            register_forward_response_waiter, remove_forward_response_waiter, wait_for_forward_response,
        };

        let store = self
            .gateway_store
            .as_ref()
            .ok_or_else(|| PeerIssuerError::Store("gateway store not available".to_string()))?;
        let mut gateway = store
            .get(gateway_id)
            .await
            .map_err(|e| PeerIssuerError::Store(e.to_string()))?
            .ok_or_else(|| PeerIssuerError::GatewayNotFound(gateway_id.to_string()))?;
        if let Some(issuer_did) = &gateway.issuer_did {
            return Ok(issuer_did.clone());
        }

        let listener = self
            .get_listener(gateway_id)
            .await
            .ok_or_else(|| PeerIssuerError::NoListener(gateway_id.to_string()))?;
        let request = build_issuer_request(&listener.gateway_did, &gateway.did);
        info!(
            gateway_id,
            peer_did = %gateway.did,
            request_id = %request.message.id,
            "📤 Requesting issuer attestation from peer gateway"
        );

        if let Err(e) = self
            .did_cache
            .resolve_and_cache_for_atm(
                &gateway.did,
                listener
                    .client
                    .atm()
                    .get_tdk(),
            )
            .await
        {
            warn!("Failed to pre-resolve peer DID {} before issuer request: {}", gateway.did, e);
        }

        let response_rx =
            register_forward_response_waiter(&request.message.id, &gateway.did).map_err(PeerIssuerError::Send)?;
        if let Err(e) = listener
            .client
            .pack_and_send_message(&request.message, &gateway.did, &listener.gateway_did)
            .await
        {
            remove_forward_response_waiter(&request.message.id);
            return Err(PeerIssuerError::Send(e));
        }

        let response = wait_for_forward_response(&request.message.id, response_rx, ISSUER_REQUEST_TIMEOUT)
            .await
            .ok_or(PeerIssuerError::Timeout)?;
        let attestation = attestation_from_issuer_response(&response, &gateway.did)?;
        let issuer_did = verify_issuer_attestation(
            attestation,
            ExpectedAttestation {
                sub: &gateway.did,
                aud: &listener.gateway_did,
                nonce: &request.nonce,
            },
            &self.did_cache,
        )
        .await?;

        gateway.issuer_did = Some(issuer_did.clone());
        gateway.issuer_did_source = Some(crate::gateways::types::IssuerDidSource::Exchange);
        gateway.updated_at = chrono::Utc::now();
        store
            .update(&gateway)
            .await
            .map_err(|e| PeerIssuerError::Store(e.to_string()))?;
        info!(gateway_id, issuer_did = %issuer_did, "✓ Peer issuer DID verified and stored");
        Ok(issuer_did)
    }

    /// Once a listener is registered, fetch the peer issuer DID in the
    /// background for active remote gateways that do not have one yet. Failures
    /// are logged; the first fabric request from the peer retries the exchange.
    fn spawn_peer_issuer_reconciliation(
        manager: &Option<std::sync::Weak<Self>>,
        gateway_id: String,
    ) {
        let Some(manager) = manager
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return;
        };
        tokio::spawn(async move {
            let needs_exchange = match manager.gateway_store.as_ref() {
                Some(store) => match store.get(&gateway_id).await {
                    Ok(Some(gateway)) => crate::gateways::issuer_exchange::needs_issuer_reconciliation(&gateway),
                    _ => false,
                },
                None => false,
            };
            if !needs_exchange {
                return;
            }
            match manager
                .ensure_peer_issuer_did(&gateway_id)
                .await
            {
                Ok(issuer_did) => info!(gateway_id, issuer_did, "✓ Peer issuer DID reconciled at listener start"),
                Err(e) => warn!(
                    gateway_id,
                    "Peer issuer DID not reconciled at listener start ({}); will retry on the first fabric request", e
                ),
            }
        });
    }

    /// Send settlement completion notification to a target gateway via DIDComm
    /// Used by settlement sync worker to notify originating gateways of settlement completion
    pub async fn send_settlement_complete(
        &self,
        target_gateway_id: &str,
        correlation_id: &str,
        tx_hash: &str,
    ) -> Result<(), String> {
        use crate::messages::MessageType;

        // Get target gateway DID from gateway store
        let target_gateway = match &self.gateway_store {
            Some(store) => store
                .get(target_gateway_id)
                .await
                .map_err(|e| format!("Failed to get gateway {}: {}", target_gateway_id, e))?
                .ok_or_else(|| format!("Gateway {} not found", target_gateway_id))?,
            None => {
                return Err("Gateway store not available".to_string());
            }
        };

        // Get an active DIDComm client from any listener
        let listeners = self.listeners.read().await;
        let (client, our_did) = listeners
            .values()
            .next()
            .map(|listener| (listener.client.clone(), listener.gateway_did.clone()))
            .ok_or_else(|| "No active connection points for sending message".to_string())?;
        drop(listeners); // Release lock

        info!(
            "Sending settlement-complete: correlation_id={} tx_hash={} → gateway={}",
            correlation_id, tx_hash, target_gateway.did
        );

        let message_body = serde_json::json!({
            "correlation_id": correlation_id,
            "tx_hash": tx_hash,
            "status": "completed",
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        crate::comm::didcomm::gateway::send_notification_message(
            &client,
            &our_did,
            &target_gateway.did,
            &MessageType::X402SettlementComplete.to_string(),
            message_body,
        )
        .await?;

        info!(
            "✅ Settlement completion notification sent: correlation_id={} → gateway={}",
            correlation_id, target_gateway.did
        );

        Ok(())
    }

    /// Stop all listeners (for shutdown)
    #[allow(dead_code)]
    pub async fn stop_all_listeners(&self) {
        let listeners: Vec<ListenerInfo> = {
            let mut listeners = self.listeners.write().await;
            listeners
                .drain()
                .map(|(_id, listener)| listener)
                .collect()
        };

        for listener in listeners {
            info!("Stopping WebSocket listener for connection point '{}'", listener.name);
            listener
                .client
                .atm()
                .graceful_shutdown()
                .await;
            listener.abort_handle.abort();
        }
        self.gateway_index
            .write()
            .await
            .clear();
    }
}

/// Persist the runtime health of a connection point onto its record.
///
/// The listener is the sole writer of `runtime_status`; it load-modify-saves so
/// a concurrent operator edit of other fields is not clobbered. Missing store
/// or missing record are silently ignored (the connection point may have been
/// deleted mid-flight).
async fn persist_cp_runtime_status<CS: super::ConnectionPointStore>(
    cp_store: &Option<Arc<CS>>,
    connection_point_id: &str,
    runtime: &crate::comm::connection_health::ConnectionRuntimeStatus,
) {
    let Some(store) = cp_store else {
        return;
    };
    match store
        .get(connection_point_id)
        .await
    {
        Ok(Some(mut cp)) => {
            cp.runtime_status = Some(runtime.clone());
            match store
                .update_if_exists(&cp)
                .await
            {
                Ok(true) => {}
                Ok(false) => debug!(
                    "Connection point '{}' record no longer exists; its runtime status was not persisted",
                    connection_point_id
                ),
                Err(e) => {
                    warn!("Failed to persist runtime status for connection point '{}': {}", connection_point_id, e)
                }
            }
        }
        Ok(None) => {}
        Err(e) => warn!("Failed to load connection point '{}' for runtime status persist: {}", connection_point_id, e),
    }
}

/// The stored record to announce in place of the listener's start-time
/// snapshot, or `None` when it was deleted while the listener connected.
async fn current_announced_record<CS: super::ConnectionPointStore>(
    cp_store: &Option<Arc<CS>>,
    snapshot: &GatewayConnectionPoint,
) -> Option<GatewayConnectionPoint> {
    let Some(store) = cp_store else {
        return Some(snapshot.clone());
    };
    match store.get(&snapshot.id).await {
        Ok(Some(current)) => current
            .is_announced()
            .then_some(current),
        Ok(None) => None,
        Err(e) => {
            warn!("Failed to reload connection point '{}' for its connected event: {}", snapshot.id, e);
            Some(snapshot.clone())
        }
    }
}

/// Run a WebSocket listener for a connection point
/// This is the main task that maintains the WebSocket connection and processes messages
/// Uses the connection point's unique DID (not the gateway DID) to avoid duplicate connections
#[instrument(name = "connection_point.ws_listener", skip_all, fields(cp.name = %connection_point.name, cp.did = %connection_point_did, mediator = %mediator_did))]
async fn run_websocket_listener<CS: super::ConnectionPointStore + 'static>(
    connection_point: &GatewayConnectionPoint,
    connection_point_did: &str, // Connection point's unique DID
    mediator_did: &str,
    mediator_url: &str,
    mediator_did_document: Option<serde_json::Value>,
    secrets: Vec<Secret>,
    message_store: Arc<MessageStore>,
    metrics: Arc<RwLock<ConnectionPointMetrics>>,
    client_sender: tokio::sync::mpsc::Sender<DIDCommClient>,
    gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    pending_connection_store: Option<Arc<crate::gateways::PendingConnectionStore>>,
    notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    bootstrap_config: Option<Arc<crate::config::BootstrapConfig>>,
    cp_store: Option<Arc<CS>>,
    manager_weak: Option<std::sync::Weak<ConnectionPointListenerManager>>,
) -> Result<(), String> {
    info!(
        "Initializing WebSocket listener for '{}' (ConnectionPoint DID: {}, Mediator: {})",
        connection_point.name, connection_point_did, mediator_did
    );

    // Create webhook client (reused across reconnections)
    let webhook_client = WebhookClient::new();

    // Reconnect policy: exponential backoff to a cap, then a fixed cadence.
    let reconnect_policy = bootstrap_config
        .as_ref()
        .map(|c| c.reconnect_policy.to_policy())
        .unwrap_or_default();

    // Runtime health for this connection point, embedded on the CP record.
    // Seeded from the persisted value so a restart continues the
    // existing failure streak rather than resetting it.
    let mut runtime = connection_point
        .runtime_status
        .clone()
        .unwrap_or_default();

    // Tracks whether we have already logged the transition into `failed`, so we
    // WARN once on the way down (and periodically), DEBUG on every other
    // attempt, and INFO once on recovery.
    let mut previously_failed = matches!(runtime.status, ConnectionStatus::Failed);

    // Restart: honor the persisted next-retry time so a
    // restart resumes the existing backoff schedule instead of hammering the
    // mediator immediately.
    if let Some(next_retry_at) = runtime.next_retry_at {
        let now = Utc::now();
        if next_retry_at > now {
            let wait = (next_retry_at - now)
                .to_std()
                .unwrap_or_default()
                .min(std::time::Duration::from_secs(reconnect_policy.max_backoff_seconds));
            debug!(
                cp_id = %connection_point.id,
                "Resuming reconnect schedule for '{}'; waiting {}s before first attempt",
                connection_point.name,
                wait.as_secs()
            );
            tokio::time::sleep(wait).await;
        }
    }

    // Only the very first successful connect hands the freshly-created client
    // to the startup path via `client_sender` (a one-shot channel consumed by
    // `start_listener`). Every later reconnect refreshes the manager's stored
    // client instead so outbound sends and x402 keep using the live socket.
    let mut initial_client_sent = false;

    // Supervision loop: (re)connect -> refresh infra -> re-apply ACL -> pump
    // messages. When the message pump returns because the mediator dropped the
    // socket (restart, or an ACL/storage wipe that severs the connection) we
    // loop back and reconnect, which re-registers this connection point's ACL
    // on the mediator so previously-known connections can route again.
    use super::types::ConnectionPointType;
    loop {
        // Connect with policy-driven backoff, recording runtime health on each
        // failed attempt so the connection point surfaces as failed with a
        // reason and a next-retry time.
        let client = loop {
            match create_atm_instance(
                connection_point,
                connection_point_did,
                mediator_did,
                mediator_url,
                mediator_did_document.clone(),
                &secrets,
                bootstrap_config.as_ref(),
            )
            .await
            {
                Ok(client) => {
                    break client;
                }
                Err(e) => {
                    let now = Utc::now();
                    let code = crate::comm::connection_health::classify_error(&e);
                    runtime.record_failure(now, code, code.message(), e.as_str());
                    runtime.schedule_retry(now, &reconnect_policy);
                    let backoff = runtime
                        .current_backoff_seconds
                        .unwrap_or(reconnect_policy.initial_backoff_seconds);

                    {
                        let mut m = metrics.write().await;
                        m.status = ConnectionStatus::Reconnecting;
                        m.reconnect_attempts = runtime.consecutive_failures;
                        m.error_count = m
                            .error_count
                            .saturating_add(1);
                    }

                    persist_cp_runtime_status(&cp_store, &connection_point.id, &runtime).await;

                    // Log noise control: WARN once on the transition into failed
                    // and then only every RECONNECT_SUMMARY_EVERY attempts; DEBUG
                    // for the per-attempt detail in between.
                    let is_transition = !previously_failed;
                    previously_failed = true;
                    let is_summary = runtime
                        .consecutive_failures
                        .is_multiple_of(RECONNECT_SUMMARY_EVERY);
                    let next_retry_at = runtime
                        .next_retry_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default();

                    if is_transition || is_summary {
                        warn!(
                            gateway_id = %connection_point.gateway_id,
                            cp_id = %connection_point.id,
                            mediator_did = %mediator_did,
                            mediator_url = %mediator_url,
                            error_code = ?code,
                            backoff_seconds = backoff,
                            next_retry_at = %next_retry_at,
                            consecutive_failures = runtime.consecutive_failures,
                            authorization_error = is_authorization_error(&e),
                            "Connection point '{}' cannot connect: {} ({})",
                            connection_point.name, code.message(), e
                        );
                    } else {
                        debug!(
                            gateway_id = %connection_point.gateway_id,
                            cp_id = %connection_point.id,
                            mediator_did = %mediator_did,
                            error_code = ?code,
                            backoff_seconds = backoff,
                            "Connection point '{}' retry attempt {} failed: {}",
                            connection_point.name, runtime.consecutive_failures, e
                        );
                    }

                    tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                }
            }
        };

        // Hand the client to the startup path on the first connect, or refresh
        // the manager's stored client on reconnects so callers use the live
        // socket rather than the dead one from before the drop.
        if !initial_client_sent {
            let _ = client_sender
                .send(client.clone())
                .await;
            initial_client_sent = true;
            if connection_point.is_announced()
                && let Some(hook) = manager_weak
                    .as_ref()
                    .and_then(|weak| weak.upgrade())
                    .and_then(|manager| manager.event_hook().cloned())
                && let Some(current) = current_announced_record(&cp_store, connection_point).await
            {
                hook.emit(
                    crate::event_hook::EventKind::Connected,
                    crate::event_hook::ConnectionPointPayload::from_record(&current, Some(mediator_did)),
                );
            }
        } else if let Some(manager) = manager_weak
            .as_ref()
            .and_then(|weak| weak.upgrade())
        {
            manager
                .update_listener_client(&connection_point.id, client.clone())
                .await;
        }

        // Initialize/refresh x402 gateway facilitator service with ATM infrastructure
        if let Err(e) = crate::x402::set_atm_infrastructure(
            Arc::clone(client.atm()),
            Arc::clone(client.profile()),
            connection_point_did.to_string(),
        )
        .await
        {
            warn!("Failed to initialize x402 gateway facilitator service: {}", e);
            warn!("  Gateway-to-gateway DIDComm verification will not be available");
        } else {
            info!("✓ x402 gateway facilitator service ready for DIDComm verification");
        }

        info!("✓ WebSocket connection established for connection point '{}'", connection_point.name);
        info!("  Connection Point DID: {}", connection_point_did);
        info!("  Mediator: {}", mediator_did);

        // Re-apply this connection point's ACL on every successful (re)connect,
        // immediately after the socket authenticates and before the message
        // loop. This restores the ACL on a mediator that lost its store (e.g.
        // storage wipe) so previously-known connections can route again. Runs
        // for every connection point type, not just the OOB ones.
        match &connection_point.cp_type {
            ConnectionPointType::OobResponder => {
                if let Some(acceptor_did) = connection_point
                    .oob_message
                    .get("acceptor_secure_did")
                    .and_then(|v| v.as_str())
                {
                    info!("   Acceptor's secure DID (will be able to send to us): {}", acceptor_did);
                }
            }
            ConnectionPointType::OobAcceptor => {
                if let Some(inviter_did) = connection_point
                    .oob_message
                    .get("inviter_secure_did")
                    .and_then(|v| v.as_str())
                {
                    info!("   Inviter's secure DID (will be able to send to us): {}", inviter_did);
                }
            }
            _ => {}
        }
        if let Err(e) = set_acl_to_allow_everything_and_more(client.atm(), Arc::clone(client.profile())).await {
            warn!(
                "Could not (re)apply ACL for connection point '{}': {}. Continuing with existing mediator permissions.",
                connection_point.name, e
            );
        }

        // Update metrics: connection successful
        {
            let mut m = metrics.write().await;
            m.status = ConnectionStatus::Connected;
            m.reconnect_attempts = 0;
        }

        // INFO once on recovery (failed -> active), then persist healthy runtime
        // status onto the connection point record.
        if previously_failed {
            info!(
                gateway_id = %connection_point.gateway_id,
                cp_id = %connection_point.id,
                mediator_did = %mediator_did,
                recovered_after_failures = runtime.consecutive_failures,
                "Connection point '{}' reconnected after {} failed attempt(s)",
                connection_point.name, runtime.consecutive_failures
            );
        }
        previously_failed = false;
        runtime.mark_active(Utc::now());
        persist_cp_runtime_status(&cp_store, &connection_point.id, &runtime).await;

        // Pump messages until the connection drops or errors.
        match process_messages(
            connection_point,
            connection_point_did,
            &client,
            &message_store,
            &webhook_client,
            &metrics,
            &gateway_store,
            &pending_connection_store,
            &notification_store,
            &bootstrap_config,
            &cp_store,
            &manager_weak,
            mediator_did,
            mediator_url,
        )
        .await
        {
            Ok(()) => {
                info!("Message loop for connection point '{}' ended cleanly; stopping listener", connection_point.name);
                // Close the socket cleanly so it doesn't linger as a zombie.
                client
                    .atm()
                    .graceful_shutdown()
                    .await;
                return Ok(());
            }
            Err(e) => {
                let now = Utc::now();
                let code = crate::comm::connection_health::classify_error(&e);
                runtime.record_failure(now, code, code.message(), e.as_str());
                runtime.schedule_retry(now, &reconnect_policy);
                let backoff = runtime
                    .current_backoff_seconds
                    .unwrap_or(reconnect_policy.initial_backoff_seconds);

                {
                    let mut m = metrics.write().await;
                    m.status = ConnectionStatus::Reconnecting;
                    m.error_count = m
                        .error_count
                        .saturating_add(1);
                }

                persist_cp_runtime_status(&cp_store, &connection_point.id, &runtime).await;

                let is_transition = !previously_failed;
                previously_failed = true;
                if is_authorization_error(&e) {
                    warn!(
                        gateway_id = %connection_point.gateway_id,
                        cp_id = %connection_point.id,
                        error_code = ?code,
                        backoff_seconds = backoff,
                        "Mediator rejected traffic for connection point '{}': {}. It may have lost this DID's ACL; reconnecting and re-applying ACL.",
                        connection_point.name, e
                    );
                } else if is_transition {
                    warn!(
                        gateway_id = %connection_point.gateway_id,
                        cp_id = %connection_point.id,
                        mediator_did = %mediator_did,
                        error_code = ?code,
                        backoff_seconds = backoff,
                        "Connection lost for connection point '{}': {}. Reconnecting in {}s...",
                        connection_point.name, e, backoff
                    );
                } else {
                    debug!(
                        cp_id = %connection_point.id,
                        error_code = ?code,
                        backoff_seconds = backoff,
                        "Connection lost for connection point '{}': {}. Reconnecting.",
                        connection_point.name, e
                    );
                }

                // Gracefully close the old socket BEFORE reconnecting. Dropping
                // the client is not enough: the SDK keeps a background websocket
                // task (with its own auto-reconnect) alive, so a new connection
                // for the same DID makes the mediator terminate the pair in a
                // `w.websocket.duplicate-channel` loop. Shutting down first
                // guarantees only one socket exists for this DID at a time.
                client
                    .atm()
                    .graceful_shutdown()
                    .await;
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
            }
        }
    }
}

/// Best-effort classification of a mediator error string as an authorization /
/// ACL rejection (blocked, forbidden, unauthorized). Used only for clearer
/// operator logging when a mediator has lost this DID's ACL — it never changes
/// control flow.
pub(crate) fn is_authorization_error(error: &str) -> bool {
    let lower = error.to_lowercase();
    lower.contains("forbidden")
        || lower.contains("unauthorized")
        || lower.contains("unauthorised")
        || lower.contains("blocked")
        || lower.contains("not local")
        || lower.contains("isn't local")
        || lower.contains("local to the mediator")
        || lower.contains("401")
        || lower.contains("403")
}

fn stream_envelope_limit(bootstrap_config: Option<&Arc<crate::config::BootstrapConfig>>) -> usize {
    bootstrap_config.map_or_else(
        || crate::config::types::A2aConfig::default().stream_envelope_limit(),
        |config| {
            config
                .a2a
                .stream_envelope_limit()
        },
    )
}

/// Create DIDComm client and establish WebSocket connection
/// This should only be called ONCE per connection point to avoid duplicate connections
async fn create_atm_instance(
    connection_point: &GatewayConnectionPoint,
    connection_point_did: &str,
    mediator_did: &str,
    _mediator_url: &str,
    mediator_did_document: Option<serde_json::Value>,
    secrets: &[Secret],
    bootstrap_config: Option<&Arc<crate::config::BootstrapConfig>>,
) -> Result<DIDCommClient, String> {
    let cache_config = bootstrap_config.map(|cfg| crate::comm::didcomm::gateway::CacheConfig {
        inbound_cache_count: cfg
            .a2a
            .sdk_inbound_cache_count,
        inbound_cache_bytes: cfg
            .a2a
            .sdk_inbound_cache_bytes,
    });

    let mut client = DIDCommClient::new_with_cache_config(
        connection_point_did.to_string(),
        secrets.to_vec(),
        Some(mediator_did.to_string()),
        mediator_did_document,
        Some(connection_point.name.clone()),
        cache_config.as_ref(),
    )
    .await?;

    #[cfg(test)]
    if super::test_mediator::connects_offline(mediator_did) {
        return Ok(client);
    }

    client
        .enable_websocket()
        .await?;

    Ok(client)
}

/// Dispatch a single non-OOB message from a spawned task and respond if needed.
///
/// This is the body of the per-message work for messages that do NOT mutate
/// the listener manager (i.e. everything other than the connection-protocol
/// OOB messages, which must stay on the WS reader task because their handlers
/// can stop/replace this very listener).
async fn dispatch_simple_message(
    client: &DIDCommClient,
    connection_point_did: &str,
    connection_point_id: &str,
    connection_point_name: &str,
    received_msg: ReceivedMessage,
) {
    let dispatch_context =
        crate::messages::DispatchContext::new(&received_msg).with_connection_point(connection_point_id.to_string());

    match crate::messages::dispatch_message(&received_msg, dispatch_context).await {
        message_processor::ProcessingResult::RequiresResponse { response_type, response_body } => {
            info!("Message processing requires response: {} (cp '{}')", response_type, connection_point_name);
            if let Err(e) =
                send_response_message(client, connection_point_did, &received_msg, &response_type, response_body).await
            {
                error!("Failed to send response message: {}", e);
            } else {
                info!("✓ Response message sent successfully");
            }
        }
        message_processor::ProcessingResult::ProcessedNoResponse => {
            debug!("Message processed successfully with no response needed");
        }
        message_processor::ProcessingResult::Stored => {
            debug!("Message stored without processing (unknown type)");
        }
        message_processor::ProcessingResult::Failed { reason } => {
            warn!("Message processing failed: {}", reason);
        }
        // Connection-protocol OOB results should never arrive here because
        // the caller classifies on message type and routes them inline.
        // Surface as a warning if it ever does so we don't silently drop.
        other => {
            warn!(
                "Spawned dispatch produced unexpected OOB result on cp '{}': {:?}",
                connection_point_name,
                std::mem::discriminant(&other)
            );
        }
    }
}

/// Send a response message back to the sender
async fn send_response_message(
    client: &DIDCommClient,
    our_did: &str,
    original_message: &ReceivedMessage,
    response_type: &str,
    response_body: serde_json::Value,
) -> Result<(), String> {
    let recipient_did = original_message
        .from_did
        .as_ref()
        .ok_or_else(|| "Original message has no 'from' DID".to_string())?;

    crate::comm::didcomm::gateway::send_response_message(
        client,
        our_did,
        recipient_did,
        &original_message.didcomm_message_id,
        response_type,
        response_body,
    )
    .await
}

/// Only the mediator can report that this connection point's account is gone.
/// The sender DID is the authcrypt-verified sender, so another DID cannot pose
/// as the mediator and force a reconnect that ends every live stream. The SDK
/// binds `from` to the sender key by DID, ignoring a `#fragment`, so the DIDs
/// are compared the same way.
fn mediator_reported(
    from_did: Option<&str>,
    mediator_did: &str,
) -> bool {
    let base_did = |did: &str| {
        did.split_once('#')
            .map_or(did, |(base, _)| base)
            .to_string()
    };
    from_did.is_some_and(|from_did| base_did(from_did) == base_did(mediator_did))
}

/// The record of a message the mediator delivered. `from_did` is the
/// envelope's `from`, not a key ID from the unpack metadata.
fn received_message(
    connection_point: &GatewayConnectionPoint,
    connection_point_did: &str,
    message: &affinidi_messaging_didcomm::Message,
    metadata: &affinidi_messaging_sdk::messages::compat::UnpackMetadata,
) -> ReceivedMessage {
    let to_dids = message
        .to
        .clone()
        .unwrap_or_else(|| vec![connection_point_did.to_string()]);
    let message_metadata = MessageMetadata {
        encrypted: metadata.encrypted,
        authenticated: metadata.authenticated,
        from_key: metadata
            .encrypted_from_kid
            .clone(),
        extra: serde_json::to_value(metadata).unwrap_or(serde_json::json!({})),
    };
    ReceivedMessage::new(
        connection_point.id.clone(),
        connection_point
            .gateway_id
            .clone(),
        message.typ.clone(),
        message.id.clone(),
        message.thid.clone(),
        message.from.clone(),
        to_dids,
        message.created_time,
        message.expires_time,
        message.body.clone(),
        message_metadata,
    )
}

/// The mediator reports `account.not_found` when it no longer has this
/// connection point's account (e.g. its store was flushed). Unlike
/// `recipient.unknown` or `access_list.denied`, which are about the remote
/// peer, this is about us, and the stale socket cannot recover the account.
/// Returns the report's code when the reader must end so the supervision loop
/// re-authenticates, which recreates the account and re-applies its ACL. The
/// same report from any other sender is ignored.
fn mediator_account_loss<'a>(
    received_msg: &'a ReceivedMessage,
    mediator_did: &str,
) -> Option<&'a str> {
    if !matches!(MessageType::from_str(&received_msg.message_type), MessageType::ProblemReport) {
        return None;
    }
    let code = received_msg
        .message_body
        .get("code")
        .and_then(|code| code.as_str())?;
    if !code.contains("account.not_found") {
        return None;
    }
    if !mediator_reported(
        received_msg
            .from_did
            .as_deref(),
        mediator_did,
    ) {
        warn!(
            from = ?received_msg.from_did,
            "Ignoring an account.not_found problem report that did not come from the mediator"
        );
        return None;
    }
    Some(code)
}

/// The sender's gateway record, when it is a registered, active gateway. A
/// capability query creates an offer in a table every peer shares, so only
/// such a gateway may send one, and only such a gateway is answered when its
/// `Open` is refused. The listener's store is read in memory, so the reader
/// never loads the gateway directory for it.
async fn active_peer_gateway(
    gateway_store: Option<&crate::gateways::FileSystemGatewayStore>,
    from_did: Option<&str>,
) -> Option<crate::gateways::types::Gateway> {
    use crate::gateways::GatewayStore;
    gateway_store?
        .get_active_by_did(from_did?)
        .await
        .ok()
        .flatten()
}

/// Whether the reader stores and dispatches a capability query: its sender is
/// within its query rate and an active peer. An admitted query carries the
/// peer's tenant, which its offer is bound to.
async fn admit_capability_query(
    query_rate: &PeerRateLimiter,
    gateway_store: Option<&crate::gateways::FileSystemGatewayStore>,
    query: &mut ReceivedMessage,
) -> bool {
    let from_did = query.from_did.as_deref();
    if !admits_from_peer(query_rate, from_did) {
        debug!(from = ?from_did, "Dropping a Fabric capability query past its sender's rate");
        return false;
    }
    let Some(peer) = active_peer_gateway(gateway_store, from_did).await else {
        debug!(from = ?from_did, "Dropping a Fabric capability query from a sender that is not an active peer");
        return false;
    };
    query
        .context
        .insert(crate::proxy::fabric_stream::PEER_TENANT_CONTEXT.to_string(), serde_json::json!(peer.tenant_id));
    true
}

/// A refused `Open` from an active peer is answered with an `Error` frame, so
/// its caller fails at once instead of waiting for the response deadline. Any
/// other sender gets nothing back.
async fn answer_refused_open(
    client: &DIDCommClient,
    message: &ReceivedMessage,
    code: crate::proxy::fabric_stream::wire::StreamErrorCode,
    gateway_store: Option<&crate::gateways::FileSystemGatewayStore>,
    bootstrap_config: &Option<Arc<crate::config::BootstrapConfig>>,
) {
    if active_peer_gateway(gateway_store, message.from_did.as_deref())
        .await
        .is_none()
    {
        return;
    }
    if let Ok(runtime) = crate::proxy::fabric_stream::global() {
        runtime
            .answer_refused_open(client, message, code, stream_envelope_limit(bootstrap_config.as_ref()))
            .await;
    }
}

/// Refused `Open`s whose `Error` answers may be in flight at once per listener.
/// Past this, a refusal goes unanswered and its sender waits out its deadline.
const MAX_PENDING_OPEN_REFUSALS: usize = 16;

/// `Open`s one listener may be admitting at once. Admission (the peer lookup
/// and route resolution) runs off the reader loop; past this, an `Open` is
/// refused with `capacity_reached` before any lookup.
const MAX_PENDING_OPEN_ADMISSIONS: usize = 16;

/// How long admitting one `Open` may take before it is refused.
const OPEN_ADMISSION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// `Open`s one peer may have admitted per second per listener, and the burst
/// allowed on top. A peer past this rate is refused with `capacity_reached`
/// before any lookup.
const PEER_OPENS_PER_SECOND: u32 = 50;
const PEER_OPEN_BURST: u32 = 100;

/// Capability queries one sender may have looked up per second per listener,
/// and the burst on top. An honest peer queries only when it (re)negotiates,
/// so a sender past this is dropped before the peer lookup.
const PEER_QUERIES_PER_SECOND: u32 = 10;
const PEER_QUERY_BURST: u32 = 20;

/// Peers tracked by a per-peer rate limiter before stale entries are pruned.
const RATE_LIMITED_PEERS_BEFORE_PRUNE: usize = 1024;

type PeerRateLimiter = governor::DefaultKeyedRateLimiter<String>;

fn peer_rate_limiter(
    per_second: u32,
    burst: u32,
) -> PeerRateLimiter {
    governor::RateLimiter::keyed(
        governor::Quota::per_second(std::num::NonZeroU32::new(per_second).expect("positive rate"))
            .allow_burst(std::num::NonZeroU32::new(burst).expect("positive burst")),
    )
}

fn open_rate_limiter() -> PeerRateLimiter {
    peer_rate_limiter(PEER_OPENS_PER_SECOND, PEER_OPEN_BURST)
}

fn query_rate_limiter() -> PeerRateLimiter {
    peer_rate_limiter(PEER_QUERIES_PER_SECOND, PEER_QUERY_BURST)
}

/// Whether `peer` is within its rate on `limiter` now.
fn admits_from_peer(
    limiter: &PeerRateLimiter,
    peer: Option<&str>,
) -> bool {
    if limiter.len() > RATE_LIMITED_PEERS_BEFORE_PRUNE {
        limiter.retain_recent();
    }
    limiter
        .check_key(
            &peer
                .unwrap_or_default()
                .to_string(),
        )
        .is_ok()
}

/// Answers a refused `Open` off the reader loop: the answer costs a peer
/// lookup, a pack and a send, and pickup must not wait on it.
fn spawn_refused_open_answer(
    stream_tasks: &mut tokio::task::JoinSet<()>,
    pending: &Arc<tokio::sync::Semaphore>,
    client: &DIDCommClient,
    message: &ReceivedMessage,
    code: crate::proxy::fabric_stream::wire::StreamErrorCode,
    gateway_store: &Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    bootstrap_config: &Option<Arc<crate::config::BootstrapConfig>>,
) {
    let Ok(permit) = Arc::clone(pending).try_acquire_owned() else {
        warn!(from = ?message.from_did, "Too many refused Fabric Opens awaiting an answer; leaving this one unanswered");
        return;
    };
    let client = client.clone();
    let message = message.clone();
    let gateway_store = gateway_store.clone();
    let bootstrap_config = bootstrap_config.clone();
    stream_tasks.spawn(async move {
        let _permit = permit;
        answer_refused_open(&client, &message, code, gateway_store.as_deref(), &bootstrap_config).await;
    });
}

/// Starts admitting an `Open` off the reader loop. The frames that arrive for
/// its stream are held until `admission` releases them, or until it ends
/// without doing so (aborted with the listener, or panicking), and at most
/// `admissions` `Open`s are admitted at once. Returns at once; a refusal here
/// is the caller's to answer.
fn start_open_admission<Admission, Task>(
    stream_tasks: &mut tokio::task::JoinSet<()>,
    admissions: &Arc<tokio::sync::Semaphore>,
    registry: &Arc<crate::proxy::fabric_stream::registry::ReceiveRegistry>,
    message: &ReceivedMessage,
    admission: Admission,
) -> Result<(), crate::proxy::fabric_stream::OpenRefusal>
where
    Admission: FnOnce(crate::proxy::fabric_stream::registry::HeldStream, tokio::sync::OwnedSemaphorePermit) -> Task,
    Task: std::future::Future<Output = ()> + Send + 'static,
{
    let Ok(permit) = Arc::clone(admissions).try_acquire_owned() else {
        return Err(crate::proxy::fabric_stream::OpenRefusal::new(
            crate::proxy::fabric_stream::wire::StreamErrorCode::CapacityReached,
            "Too many Fabric Opens are being admitted",
        ));
    };
    let stream_id = message
        .message_body
        .get("stream_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
        .ok_or("Fabric Open frame has no stream id")?;
    let peer_did = message
        .from_did
        .as_deref()
        .ok_or("Fabric sender is missing")?;
    let held = registry.hold(stream_id, peer_did)?;
    stream_tasks.spawn(admission(held, permit));
    Ok(())
}

/// What admitting one `Open` reads: the sender's gateway record and the
/// Connection Point's current one.
struct OpenGate<CS> {
    runtime: Arc<crate::proxy::fabric_stream::StreamRuntime>,
    message: ReceivedMessage,
    connection_point: Arc<GatewayConnectionPoint>,
    cp_store: Option<Arc<CS>>,
    gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
}

impl<CS: super::ConnectionPointStore + 'static> OpenGate<CS> {
    /// Admits the `Open` within `OPEN_ADMISSION_TIMEOUT` and ends the hold on
    /// its stream's frames: delivered when it is admitted, dropped otherwise.
    /// `Ok(None)` is an admitted stream that broke the hold by sending more
    /// frames than it may before admission.
    async fn admit_held(
        &self,
        held: crate::proxy::fabric_stream::registry::HeldStream,
    ) -> Result<Option<crate::proxy::fabric_stream::IncomingStream>, crate::proxy::fabric_stream::OpenRefusal> {
        let admitted = tokio::time::timeout(OPEN_ADMISSION_TIMEOUT, self.admit())
            .await
            .unwrap_or_else(|_| Err("Fabric Open admission timed out".into()));
        match admitted {
            Ok(incoming) => match held.release(true) {
                Ok(()) => Ok(Some(incoming)),
                Err(error) => {
                    warn!(from = ?self.message.from_did, %error, "Ending an admitted Fabric stream");
                    Ok(None)
                }
            },
            Err(refusal) => {
                if let Err(error) = held.release(false) {
                    warn!(%error, "Could not drop the frames held for a refused Fabric Open");
                }
                Err(refusal)
            }
        }
    }

    async fn admit(
        &self
    ) -> Result<crate::proxy::fabric_stream::IncomingStream, crate::proxy::fabric_stream::OpenRefusal> {
        let revocations = self
            .runtime
            .registry
            .revocations();
        let store = self
            .gateway_store
            .as_ref()
            .ok_or("Fabric gateway store is unavailable")?;
        let peer_did = self
            .message
            .from_did
            .as_deref()
            .ok_or("Fabric sender is missing")?;
        let peer = store
            .get_by_did(peer_did)
            .await
            .map_err(|error| error.to_string())?
            .ok_or("Fabric sender is not a configured peer")?;
        let connection_point = self
            .current_connection_point()
            .await?;
        let incoming = self
            .runtime
            .prepare_incoming(&self.message, &connection_point, &peer)
            .await?;
        // A revocation that ran after the records were read could not end
        // this stream, which was not registered yet.
        if self
            .runtime
            .registry
            .revocations()
            != revocations
        {
            return Err("Fabric access changed while the Open was admitted".into());
        }
        Ok(incoming)
    }

    /// The Connection Point as stored now, so a disabled one or a narrowed
    /// exposure applies to this `Open`, not the record the listener started
    /// with.
    async fn current_connection_point(
        &self
    ) -> Result<GatewayConnectionPoint, crate::proxy::fabric_stream::OpenRefusal> {
        match &self.cp_store {
            Some(store) => store
                .get(&self.connection_point.id)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "Fabric Connection Point no longer exists".into()),
            None => Ok((*self.connection_point).clone()),
        }
    }
}

/// What admitting one `Open` off the reader loop needs.
struct OpenAdmission<CS> {
    gate: OpenGate<CS>,
    client: DIDCommClient,
    bootstrap_config: Option<Arc<crate::config::BootstrapConfig>>,
    refusals: Arc<tokio::sync::Semaphore>,
}

impl<CS: super::ConnectionPointStore + 'static> OpenAdmission<CS> {
    /// Admits the `Open`, releases the frames held for its stream and runs the
    /// stream. A refused `Open` is answered, so its sender fails at once.
    async fn admit_and_run(
        self,
        held: crate::proxy::fabric_stream::registry::HeldStream,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        let admitted = self
            .gate
            .admit_held(held)
            .await;
        drop(permit);
        match admitted {
            Ok(Some(incoming)) => {
                let sink = Arc::new(crate::proxy::fabric_stream::transport::DidCommFrameSink {
                    client: self.client,
                    binding: incoming.binding.clone(),
                    capabilities: incoming.capabilities.clone(),
                    max_envelope_bytes: stream_envelope_limit(self.bootstrap_config.as_ref()),
                });
                incoming.run(sink).await;
            }
            Ok(None) => {}
            Err(refusal) => {
                let message = &self.gate.message;
                warn!(
                    from = ?message.from_did,
                    error = %refusal,
                    code = ?refusal.code,
                    "Rejecting Fabric Open"
                );
                let Ok(_answering) = self
                    .refusals
                    .try_acquire_owned()
                else {
                    warn!(from = ?message.from_did, "Too many refused Fabric Opens awaiting an answer; leaving this one unanswered");
                    return;
                };
                answer_refused_open(
                    &self.client,
                    message,
                    refusal.code,
                    self.gate
                        .gateway_store
                        .as_deref(),
                    &self.bootstrap_config,
                )
                .await;
            }
        }
    }
}

/// Connection-protocol OOB messages run inline because their handlers stop or
/// replace this listener, and because single use of an invitation relies on two
/// connection-setups on one listener never being redeemed concurrently. Messages that only complete a waiter held by an
/// in-flight dispatch run inline, because waiting for a slot could wait on the
/// very dispatch the reply would free.
fn dispatches_inline(message_type: &str) -> bool {
    matches!(
        message_type,
        "https://affinidi.com/atm/client-actions/connection-setup"
            | "https://affinidi.com/atm/client-actions/connection-accepted"
            | "https://affinidi.com/atm/client-actions/connection-rejected"
    ) || matches!(
        MessageType::from_str(message_type),
        MessageType::ForwardResponse
            | MessageType::GatewayIssuerResponse
            | MessageType::ForwardStreamFrame
            | MessageType::ForwardStreamQuery
            | MessageType::ForwardStreamDisclose
    )
}

enum DispatchSlot {
    Permit(tokio::sync::OwnedSemaphorePermit),
    Overloaded(serde_json::Value),
}

/// A `ForwardRequest` that finds every slot busy is answered with a retryable 503, so the reader never blocks
/// behind the replies in-flight requests are waiting for; the caller first refuses or drops it as the dispatched
/// task would. Other messages have no reply that could carry that error, so they wait for a slot while outgoing
/// stream tasks keep being spawned.
async fn dispatch_slot(
    semaphore: &Arc<tokio::sync::Semaphore>,
    message_type: &str,
    stream_listener: &mut crate::proxy::fabric_stream::ListenerGeneration,
    stream_tasks: &mut tokio::task::JoinSet<()>,
) -> Result<DispatchSlot, String> {
    if let Ok(permit) = Arc::clone(semaphore).try_acquire_owned() {
        return Ok(DispatchSlot::Permit(permit));
    }
    if matches!(MessageType::from_str(message_type), MessageType::ForwardRequest) {
        return Ok(DispatchSlot::Overloaded(serde_json::json!({
            "status": 503,
            "headers": { "retry-after": "1", "content-type": "application/json" },
            "body": "{\"error\":\"Gateway dispatch capacity unavailable\"}",
        })));
    }
    stream_listener
        .serve_outgoing_until(stream_tasks, Arc::clone(semaphore).acquire_owned())
        .await?
        .map(DispatchSlot::Permit)
        .map_err(|_| "Fabric dispatch capacity was closed".to_string())
}

async fn delete_message_after_processing(
    client: &DIDCommClient,
    message_sha256_hash: &str,
    connection_point_name: &str,
) {
    if let Err(e) = client
        .atm()
        .delete_message_background(client.profile(), message_sha256_hash)
        .await
    {
        warn!(
            "Failed to delete processed message '{}' for connection point '{}': {:?}",
            message_sha256_hash, connection_point_name, e
        );
    }
}

/// Process messages from the WebSocket connection in an infinite loop
async fn process_messages<CS: super::ConnectionPointStore + 'static>(
    connection_point: &GatewayConnectionPoint,
    connection_point_did: &str,
    client: &DIDCommClient,
    message_store: &Arc<MessageStore>,
    webhook_client: &WebhookClient,
    metrics: &Arc<RwLock<ConnectionPointMetrics>>,
    gateway_store: &Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    pending_connection_store: &Option<Arc<crate::gateways::PendingConnectionStore>>,
    _notification_store: &Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    bootstrap_config: &Option<Arc<crate::config::BootstrapConfig>>,
    cp_store: &Option<Arc<CS>>,
    manager_weak: &Option<std::sync::Weak<ConnectionPointListenerManager>>,
    mediator_did: &str,
    mediator_url: &str,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut stream_listener = crate::proxy::fabric_stream::global()?
        .listener(connection_point.id.clone(), connection_point_did.to_string())?;

    // ----------------------------------------------------------------------
    // Pre-compute message-context values that are constant for the lifetime
    // of this listener. Reading the x402 config from disk on EVERY inbound
    // message is wasteful and significantly inflates per-message latency
    // under fabric load.
    // ----------------------------------------------------------------------
    let (channel_storage_ctx, x402_headers_ctx, x402_config_ctx, secrets_storage_ctx) =
        if let Some(config) = bootstrap_config {
            let headers_value = match config.load_x402_headers() {
                Ok(h) => serde_json::json!({
                    "payment_required": h.payment_required,
                    "payment_signature": h.payment_signature,
                    "payment_response": h.payment_response,
                }),
                Err(e) => {
                    warn!("Failed to load x402 headers for message context: {}, using defaults", e);
                    serde_json::json!({
                        "payment_required": "PAYMENT-REQUIRED",
                        "payment_signature": "PAYMENT-SIGNATURE",
                        "payment_response": "PAYMENT-RESPONSE",
                    })
                }
            };
            let x402_cfg_value = match crate::x402::get_x402_config().await {
                Some(cfg) => Some(serde_json::to_value(&*cfg).unwrap_or(serde_json::json!({}))),
                None => {
                    debug!("x402 config not cached, skipping message context injection");
                    None
                }
            };
            (
                Some(serde_json::json!(
                    config
                        .storage_paths
                        .agent_surfaces
                        .clone()
                )),
                Some(headers_value),
                x402_cfg_value,
                Some(serde_json::json!(
                    config
                        .storage_paths
                        .secrets
                        .clone()
                )),
            )
        } else {
            (None, None, None, None)
        };

    // ----------------------------------------------------------------------
    // Concurrent-dispatch infrastructure. Without this the WS reader task
    // blocks on the heaviest dispatch (e.g. a forward-request that proxies
    // an HTTP backend via mTLS) before reading the next inbound message,
    // which combined with the SDK's inbound-cache backpressure produces the
    // cascading slowdown observed under fabric-to-fabric load.
    // ----------------------------------------------------------------------
    let max_inflight = bootstrap_config
        .as_ref()
        .map(|c| c.a2a.max_inflight_dispatches)
        .unwrap_or(256);
    let dispatch_semaphore = Arc::new(tokio::sync::Semaphore::new(max_inflight));
    let mut dispatch_set: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let mut stream_tasks: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    let pending_open_refusals = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_OPEN_REFUSALS));
    let pending_open_admissions = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_OPEN_ADMISSIONS));
    let open_rate = open_rate_limiter();
    let query_rate = query_rate_limiter();
    let in_flight = Arc::new(AtomicU64::new(0));

    // Wrap the client so spawned dispatch tasks can cheaply clone it.
    let connection_point_did_arc: Arc<str> = Arc::from(connection_point_did);
    let connection_point_arc: Arc<GatewayConnectionPoint> = Arc::new(connection_point.clone());

    // Main message receiving loop
    let auto_deleted_received_messages = false;
    let mut next_message =
        Box::pin(client.live_stream_next(std::time::Duration::from_secs(300), auto_deleted_received_messages));
    loop {
        // Wait for the next message from the WebSocket.
        //
        // auto_delete=true: the SDK deletes each message from the mediator as
        // soon as it is delivered to us. Without this the mediator's DB grows
        // unbounded because nothing else in this loop deletes the message.
        //
        // TODO: retry mechanism.
        let received = stream_listener
            .serve_outgoing_until(&mut stream_tasks, &mut next_message)
            .await?;
        next_message =
            Box::pin(client.live_stream_next(std::time::Duration::from_secs(300), auto_deleted_received_messages));
        match received {
            Ok(Some((message, metadata))) => {
                debug!("Message metadata: from={:?}, encrypted={}", metadata.encrypted_from_kid, metadata.encrypted);
                debug!("Message.from: {:?}, Message.to: {:?}", message.from, message.to);
                let message_sha256_hash = metadata.sha256_hash.clone();
                let mut received_msg = received_message(connection_point, connection_point_did, &message, &metadata);
                received_msg.pthid = message.pthid.clone();
                stream_listener.stamp(&mut received_msg);

                // Attach pre-computed per-listener context. These values
                // were resolved once at process_messages startup so we never
                // re-read x402.json from disk per message.
                if let Some(v) = &channel_storage_ctx {
                    received_msg
                        .context
                        .insert("agent_surface_storage_path".to_string(), v.clone());
                }
                if let Some(v) = &x402_headers_ctx {
                    received_msg
                        .context
                        .insert("x402_headers".to_string(), v.clone());
                }
                if let Some(v) = &x402_config_ctx {
                    received_msg
                        .context
                        .insert("x402_config".to_string(), v.clone());
                }
                if let Some(v) = &secrets_storage_ctx {
                    received_msg
                        .context
                        .insert("secrets_storage_path".to_string(), v.clone());
                }
                received_msg.context.insert(
                    message_processor::CONNECTION_POINT_DID_CONTEXT_KEY.to_string(),
                    serde_json::Value::String(connection_point_did.to_string()),
                );

                if matches!(MessageType::from_str(&received_msg.message_type), MessageType::ForwardStreamFrame)
                    && received_msg
                        .message_body
                        .pointer("/payload/kind")
                        .and_then(serde_json::Value::as_str)
                        == Some("open")
                {
                    let started = if !admits_from_peer(
                        &open_rate,
                        received_msg
                            .from_did
                            .as_deref(),
                    ) {
                        Err(crate::proxy::fabric_stream::OpenRefusal::new(
                            crate::proxy::fabric_stream::wire::StreamErrorCode::CapacityReached,
                            "Fabric Open rate exceeded for this peer",
                        ))
                    } else {
                        match crate::proxy::fabric_stream::global() {
                            Ok(runtime) => {
                                let admission = OpenAdmission {
                                    gate: OpenGate {
                                        runtime: Arc::clone(runtime),
                                        message: received_msg.clone(),
                                        connection_point: Arc::clone(&connection_point_arc),
                                        cp_store: cp_store.clone(),
                                        gateway_store: gateway_store.clone(),
                                    },
                                    client: client.clone(),
                                    bootstrap_config: bootstrap_config.clone(),
                                    refusals: Arc::clone(&pending_open_refusals),
                                };
                                start_open_admission(
                                    &mut stream_tasks,
                                    &pending_open_admissions,
                                    &runtime.registry,
                                    &received_msg,
                                    move |held, permit| admission.admit_and_run(held, permit),
                                )
                            }
                            Err(error) => Err(error.into()),
                        }
                    };
                    if let Err(refusal) = started {
                        warn!(
                            from = ?received_msg.from_did,
                            error = %refusal,
                            code = ?refusal.code,
                            "Rejecting Fabric Open"
                        );
                        spawn_refused_open_answer(
                            &mut stream_tasks,
                            &pending_open_refusals,
                            client,
                            &received_msg,
                            refusal.code,
                            gateway_store,
                            bootstrap_config,
                        );
                    }
                    delete_message_after_processing(client, &message_sha256_hash, &connection_point.name).await;
                    while stream_tasks
                        .try_join_next()
                        .is_some()
                    {}
                    continue;
                }

                if matches!(MessageType::from_str(&received_msg.message_type), MessageType::ForwardStreamQuery)
                    && !admit_capability_query(&query_rate, gateway_store.as_deref(), &mut received_msg).await
                {
                    delete_message_after_processing(client, &message_sha256_hash, &connection_point.name).await;
                    continue;
                }

                // Store the message
                match message_store
                    .store(&received_msg)
                    .await
                {
                    Ok(_) => {
                        //info!("✓ Stored message {} for connection point '{}'", received_msg.id, connection_point.name);

                        // Update metrics: increment message count and update last activity
                        {
                            let mut m = metrics.write().await;
                            m.message_count += 1;
                            m.last_activity = Some(Utc::now());
                        }

                        if let Some(code) = mediator_account_loss(&received_msg, mediator_did) {
                            warn!(
                                "Connection point '{}' account is missing on the mediator ('{}'); reconnecting to re-authenticate and re-register.",
                                connection_point.name, code
                            );
                            return Err(format!(
                                "mediator account not found ('{}') — reconnecting to re-register",
                                code
                            ));
                        }

                        // Sender authentication is enforced natively by the SDK's
                        // UnpackPolicy (authcrypt-only): anoncrypt/plaintext
                        // envelopes are purged at pickup and never reach here, so
                        // any message at this point has a cryptographically
                        // verified `from`.

                        // Dispatch the message. Everything not dispatched
                        // inline is spawned onto a bounded JoinSet so a slow
                        // HTTP forward cannot stall the WS reader and
                        // back-pressure the SDK inbound cache.
                        if dispatches_inline(&received_msg.message_type) {
                            let dispatch_context = crate::messages::DispatchContext::new(&received_msg)
                                .with_connection_point(connection_point.id.clone());

                            match crate::messages::dispatch_message(&received_msg, dispatch_context).await {
                                message_processor::ProcessingResult::RequiresResponse {
                                    response_type,
                                    response_body,
                                } => {
                                    info!("Message processing requires response: {}", response_type);

                                    // Send response message back through mediator
                                    if let Err(e) = send_response_message(
                                        client,
                                        connection_point_did,
                                        &received_msg,
                                        &response_type,
                                        response_body,
                                    )
                                    .await
                                    {
                                        error!("Failed to send response message: {}", e);
                                    } else {
                                        info!("✓ Response message sent successfully");
                                    }
                                }
                                message_processor::ProcessingResult::OOBConnectionAccepted(accepted) => {
                                    let message_processor::OobConnectionAccepted {
                                        inviter_temporary_did,
                                        inviter_secure_did,
                                        issuer_attestation,
                                        nonce,
                                    } = *accepted;
                                    info!("🎉 OOB connection-accepted received! Finalizing gateway connection...");

                                    // This is the ACCEPTOR side receiving confirmation from INVITER
                                    // Finalize the gateway connection
                                    if let (Some(gw_store), Some(pend_store), Some(config), Some(cps), Some(mgr_weak)) = (
                                        gateway_store,
                                        pending_connection_store,
                                        bootstrap_config,
                                        cp_store,
                                        manager_weak,
                                    ) {
                                        // Need to convert Weak to Arc for the call
                                        if let Some(mgr) = mgr_weak.upgrade() {
                                            match finalize_oob_connection_as_acceptor(
                                                &inviter_temporary_did,
                                                &inviter_secure_did,
                                                issuer_attestation.as_deref(),
                                                nonce.as_deref(),
                                                gw_store,
                                                pend_store,
                                                config,
                                                cps,
                                                &mgr,
                                                Some(connection_point),
                                                mediator_did,
                                                mediator_url,
                                            )
                                            .await
                                            {
                                                Ok(gateway) => {
                                                    info!("✓ Gateway {} created successfully!", gateway.id);
                                                    info!("  Gateway DID: {}", gateway.did);

                                                    // Clean up temporary connection point
                                                    info!(
                                                        "🧹 Cleaning up temporary connection point: {}",
                                                        connection_point.name
                                                    );
                                                    if let Err(e) = mgr
                                                        .stop_listener(&connection_point.id)
                                                        .await
                                                    {
                                                        warn!("Failed to stop temporary listener: {}", e);
                                                    }
                                                    if let Err(e) = cps
                                                        .delete(&connection_point.id)
                                                        .await
                                                    {
                                                        warn!("Failed to delete temporary connection point: {}", e);
                                                    } else {
                                                        info!("✓ Temporary connection point cleaned up");
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("❌ Failed to finalize OOB connection: {}", e);
                                                }
                                            }
                                        } else {
                                            warn!(
                                                "Cannot finalize OOB connection: listener manager no longer available"
                                            );
                                        }
                                    } else {
                                        warn!("Cannot finalize OOB connection: missing required stores");
                                    }
                                }
                                message_processor::ProcessingResult::OOBConnectionSetup(setup) => {
                                    let message_processor::OobConnectionSetup {
                                        acceptor_temporary_did,
                                        acceptor_secure_did,
                                        invitation_id,
                                        secret,
                                        issuer_attestation,
                                        nonce,
                                    } = *setup;
                                    info!("📥 OOB connection-setup received! Processing as INVITER...");

                                    // This is the INVITER side receiving connection-setup from ACCEPTOR
                                    if let (Some(gw_store), Some(pend_store), Some(config), Some(cp_st)) =
                                        (gateway_store, pending_connection_store, bootstrap_config, cp_store)
                                    {
                                        match handle_oob_connection_setup_as_inviter(
                                            &acceptor_temporary_did,
                                            &acceptor_secure_did,
                                            &invitation_id,
                                            &secret,
                                            issuer_attestation.as_deref(),
                                            nonce.as_deref(),
                                            connection_point_did,
                                            client,
                                            gw_store,
                                            pend_store,
                                            _notification_store,
                                            config,
                                            cp_st,
                                            &connection_point.mediator_id,
                                            manager_weak,
                                            mediator_did,
                                            mediator_url,
                                        )
                                        .await
                                        {
                                            Ok(_) => {
                                                info!("✓ Connection-accepted sent successfully!");

                                                // Trigger integration for successful OOB connection attempt
                                                // This only runs when someone successfully connects with the correct secret
                                                info!(
                                                    "🔔 Triggering integration for successful OOB connection attempt"
                                                );
                                                if let Err(e) = webhook_client
                                                    .trigger_integration(connection_point, &received_msg)
                                                    .await
                                                {
                                                    error!(
                                                        "Notifier/webhook delivery failed for connection point '{}': {}",
                                                        connection_point.name, e
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                error!("❌ Failed to process connection-setup as inviter: {}", e);
                                                // Do NOT trigger integration on failed connection attempts (wrong secret, etc.)
                                            }
                                        }
                                    } else {
                                        warn!("Cannot process OOB connection-setup: missing required stores");
                                    }
                                }
                                message_processor::ProcessingResult::OOBConnectionRejected { reason } => {
                                    error!("❌ OOB connection-rejected received! Reason: {}", reason);

                                    // This is the ACCEPTOR side receiving rejection from INVITER
                                    // Clean up the pending connection state
                                    if let Some(_pend_store) = pending_connection_store {
                                        // Find and delete pending connections for this DID
                                        // Note: We don't have easy access to the pending connection ID here,
                                        // so we'll log the failure. In production, you'd want to track this better.
                                        error!("Connection rejected - pending connection cleanup needed");
                                        error!("Rejection reason: {}", reason);
                                    } else {
                                        warn!("Cannot cleanup rejected connection: missing pending store");
                                    }
                                }
                                message_processor::ProcessingResult::ProcessedNoResponse => {
                                    debug!("Message processed successfully with no response needed");
                                }
                                message_processor::ProcessingResult::StreamingResponse { .. } => {
                                    warn!("Rejecting streaming response outside the Fabric stream dispatcher");
                                }
                                message_processor::ProcessingResult::Stored => {
                                    debug!("Message stored without processing (unknown type)");
                                }
                                message_processor::ProcessingResult::Failed { reason } => {
                                    warn!("Message processing failed: {}", reason);
                                }
                            }

                            delete_message_after_processing(client, &message_sha256_hash, &connection_point.name).await;
                        } else {
                            // Spawn the dispatch onto a bounded JoinSet so
                            // heavy proxy work cannot stall the WS reader.
                            let permit = match dispatch_slot(
                                &dispatch_semaphore,
                                &received_msg.message_type,
                                &mut stream_listener,
                                &mut stream_tasks,
                            )
                            .await?
                            {
                                DispatchSlot::Permit(permit) => permit,
                                DispatchSlot::Overloaded(overload) => {
                                    // Shed only a request the task would admit. A duplicate is dropped
                                    // without a reply, and an unauthorized or refused envelope gets the
                                    // task's own answer, so saturation never displaces a real response
                                    // or reveals itself to a sender that is not admitted.
                                    let reply = match message_processor::forward_request_refusal_before_dispatch(
                                        &received_msg,
                                        gateway_store.as_deref(),
                                    )
                                    .await
                                    {
                                        None => {
                                            warn!(
                                                "Dispatch capacity unavailable for connection point '{}'",
                                                connection_point.name
                                            );
                                            Some((MessageType::ForwardResponse.to_string(), overload))
                                        }
                                        Some(message_processor::ProcessingResult::RequiresResponse {
                                            response_type,
                                            response_body,
                                        }) => Some((response_type, response_body)),
                                        Some(_) => None,
                                    };
                                    if let Some((response_type, response_body)) = reply
                                        && let Err(error) = send_response_message(
                                            client,
                                            connection_point_did,
                                            &received_msg,
                                            &response_type,
                                            response_body,
                                        )
                                        .await
                                    {
                                        warn!(error = %error, "Failed to send dispatch overload response");
                                    }
                                    delete_message_after_processing(
                                        client,
                                        &message_sha256_hash,
                                        &connection_point.name,
                                    )
                                    .await;
                                    continue;
                                }
                            };

                            let new_inflight = in_flight.fetch_add(1, Ordering::Relaxed) + 1;
                            {
                                let mut m = metrics.write().await;
                                m.in_flight_dispatches = new_inflight;
                                if new_inflight > m.max_in_flight_dispatches {
                                    m.max_in_flight_dispatches = new_inflight;
                                }
                            }

                            let client_c = client.clone();
                            let cp_did_c = Arc::clone(&connection_point_did_arc);
                            let cp_id_c = connection_point_arc
                                .id
                                .clone();
                            let cp_name_c = connection_point_arc
                                .name
                                .clone();
                            let message_sha256_hash_c = message_sha256_hash.clone();
                            let metrics_c = Arc::clone(metrics);
                            let in_flight_c = Arc::clone(&in_flight);
                            let received_msg_c = received_msg.clone();

                            dispatch_set.spawn(async move {
                                let _permit = permit; // released on drop
                                dispatch_simple_message(&client_c, &cp_did_c, &cp_id_c, &cp_name_c, received_msg_c)
                                    .await;
                                delete_message_after_processing(&client_c, &message_sha256_hash_c, &cp_name_c).await;

                                let remaining = in_flight_c
                                    .fetch_sub(1, Ordering::Relaxed)
                                    .saturating_sub(1);
                                metrics_c
                                    .write()
                                    .await
                                    .in_flight_dispatches = remaining;
                            });

                            // Reap any completed dispatch tasks so the
                            // JoinSet does not grow unboundedly.
                            while dispatch_set
                                .try_join_next()
                                .is_some()
                            {}
                        }

                        // Note: integrations are ONLY triggered on successful OOB connection setup
                        // (see OOBConnectionSetup handler above - around line 905)
                        // This prevents spam from health checks, pings, and other DIDComm messages
                    }
                    Err(e) => {
                        error!("Failed to store message for connection point '{}': {:?}", connection_point.name, e);
                    }
                }

                debug!("Message body: {}", serde_json::to_string_pretty(&message.body).unwrap_or_default());
            }
            Ok(None) => {
                debug!("No message received within timeout for connection point '{}'", connection_point.name);
                // Continue waiting for messages
                continue;
            }
            Err(e) => {
                // Return error to trigger reconnection
                return Err(format!("Error receiving message: {:?}", e));
            }
        }
    }
}
/// The permanent secure DID may be homed on a different mediator than the
/// temporary handshake DID (per-gateway mediator selection). Prefer the
/// mediator recorded alongside the secure DID when the pending-connection
/// cache must be recovered from the temporary connection point's metadata,
/// falling back to the temp CP's own (inviter) mediator for connections
/// created before this field existed.
fn resolve_recovered_secure_mediator_did(
    oob_message: &serde_json::Value,
    fallback_mediator_id: &str,
) -> String {
    oob_message
        .get("secure_mediator_did")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| fallback_mediator_id.to_string())
}

/// Checks the mediator a cache-miss recovery would home the permanent
/// connection point on. In shared-mediator mode it is the temporary connection
/// point's own mediator, which the handshake already used, so it is accepted
/// without a store lookup; the acceptor need not have it registered. A
/// different mediator must be the acceptor mediator record recorded when the
/// invitation was accepted, still Active and with the recovered DID. Recovery
/// fails closed without that record id or without a store.
async fn validate_recovered_mediator(
    mediator_store: Option<&crate::mediators::FileSystemMediatorStore>,
    recovered_did: &str,
    recovered_record_id: Option<&str>,
    temp_cp_mediator_did: &str,
    connection_point_id: &str,
) -> Result<(), String> {
    if recovered_did == temp_cp_mediator_did {
        return Ok(());
    }
    let refuse = || {
        format!(
            "Recovered secure_mediator_did '{}' does not resolve to the selected, Active mediator; refusing to \
             finalize connection {}",
            recovered_did, connection_point_id
        )
    };
    let record_id = recovered_record_id.ok_or_else(refuse)?;
    let mediator_store = mediator_store.ok_or_else(|| {
        format!(
            "Mediator store unavailable; cannot validate recovered secure_mediator_did '{}' for connection {}",
            recovered_did, connection_point_id
        )
    })?;
    let mediator = get_mediator(mediator_store, record_id)
        .await
        .map_err(|e| {
            format!("Failed to validate recovered secure_mediator_did '{}' against MediatorStore: {}", recovered_did, e)
        })?;
    match mediator {
        Some(mediator) if selected_mediator_is_valid(&mediator, recovered_did) => Ok(()),
        _ => Err(refuse()),
    }
}

/// True when the recorded acceptor mediator still carries `mediator_did` and
/// is `Active`.
fn selected_mediator_is_valid(
    mediator: &crate::mediators::types::Mediator,
    mediator_did: &str,
) -> bool {
    mediator.did == mediator_did && mediator.status == crate::mediators::types::MediatorStatus::Active
}

/// The DID document of the acceptor mediator selected when the invitation was
/// accepted, or `None` for a shared-mediator connection, which selected none.
/// A selected record that is missing, carries another DID or is not `Active`
/// fails finalize, as it fails recovery.
async fn selected_mediator_document(
    mediator_store: Option<&crate::mediators::FileSystemMediatorStore>,
    mediator_record_id: Option<&str>,
    mediator_did: &str,
) -> Result<Option<serde_json::Value>, String> {
    let Some(record_id) = mediator_record_id else {
        return Ok(None);
    };
    let mediator_store = mediator_store
        .ok_or_else(|| format!("Mediator store unavailable; cannot read the selected mediator '{}'", record_id))?;
    match get_mediator(mediator_store, record_id).await? {
        Some(mediator) if selected_mediator_is_valid(&mediator, mediator_did) => Ok(mediator.did_document),
        _ => Err(format!(
            "Selected mediator '{}' is no longer an Active mediator with DID '{}'; refusing to finalize",
            record_id, mediator_did
        )),
    }
}

async fn get_mediator(
    mediator_store: &crate::mediators::FileSystemMediatorStore,
    record_id: &str,
) -> Result<Option<crate::mediators::types::Mediator>, String> {
    use crate::mediators::filesystem::MediatorStore;
    mediator_store
        .get(record_id)
        .await
        .map_err(|e| format!("Failed to read mediator '{}': {}", record_id, e))
}

/// The endpoint the acceptor's permanent connection point advertises.
///
/// The mediator's stored DID document wins. Without one, a connection on the
/// handshake mediator (shared mode) uses the handshake mediator's URL, taken
/// from the OOB invitation, since the acceptor usually has no record of the
/// inviter's mediator. Otherwise the URL is derived from the mediator DID.
fn permanent_mediator_url(
    mediator_did: &str,
    mediator_doc: Option<&serde_json::Value>,
    handshake_mediator_did: &str,
    handshake_mediator_url: &str,
) -> Result<String, String> {
    if mediator_doc.is_none() && mediator_did == handshake_mediator_did && !handshake_mediator_url.is_empty() {
        return Ok(handshake_mediator_url.to_string());
    }
    super::handlers::resolve_mediator_endpoint(mediator_did, mediator_doc)
        .map_err(|e| format!("Failed to resolve mediator URL: {}", e))
}

/// The mediator DID document preloaded for a listener: the record named by the
/// connection point's `mediator_id` when it carries the listener's mediator
/// DID, otherwise the first record with that DID.
async fn listener_mediator_document(
    store: &crate::mediators::FileSystemMediatorStore,
    cp_mediator_id: &str,
    mediator_did: &str,
    listener_name: &str,
) -> Option<serde_json::Value> {
    use crate::mediators::filesystem::MediatorStore;

    match store
        .get(cp_mediator_id)
        .await
    {
        Ok(Some(mediator)) if mediator.did == mediator_did => mediator.did_document,
        Ok(Some(_)) | Ok(None) => match store.list_all().await {
            Ok(mediators) => mediators
                .into_iter()
                .find(|mediator| mediator.did == mediator_did)
                .and_then(|mediator| mediator.did_document),
            Err(e) => {
                warn!("Failed to list mediators while preloading DID document for listener '{}': {}", listener_name, e);
                None
            }
        },
        Err(e) => {
            warn!(
                "Failed to load mediator '{}' while preloading DID document for listener '{}': {}",
                cp_mediator_id, listener_name, e
            );
            None
        }
    }
}

/// The `mediator_id` stored on the acceptor's permanent connection point: the
/// acceptor mediator's record id when one was selected, so restarts, deletion
/// checks and tenant ownership use that exact record; otherwise the inviter's
/// mediator DID, for which the acceptor has no record.
fn permanent_mediator_reference(
    mediator_record_id: Option<&str>,
    mediator_did: &str,
) -> String {
    mediator_record_id
        .unwrap_or(mediator_did)
        .to_string()
}

/// Finalize OOB connection as ACCEPTOR after receiving connection-accepted
async fn finalize_oob_connection_as_acceptor<S: GatewayStore, CS: super::ConnectionPointStore>(
    inviter_temporary_did: &str,
    inviter_secure_did: &str,
    issuer_attestation: Option<&str>,
    nonce: Option<&str>,
    gateway_store: &Arc<S>,
    pending_store: &Arc<crate::gateways::PendingConnectionStore>,
    bootstrap_config: &Arc<crate::config::BootstrapConfig>,
    cp_store: &Arc<CS>,
    listener_manager: &Arc<ConnectionPointListenerManager>,
    current_connection_point: Option<&super::types::GatewayConnectionPoint>,
    handshake_mediator_did: &str,
    handshake_mediator_url: &str,
) -> Result<crate::gateways::types::Gateway, String> {
    info!("🔧 Finalizing OOB connection as ACCEPTOR");
    info!("  Inviter temporary DID: {}", inviter_temporary_did);
    info!("  Inviter secure DID: {}", inviter_secure_did);

    // Step 1: Retrieve pending connection state. In real-process G2G flows the
    // connection-accepted message can arrive on the temporary listener while the
    // pending OOB cache is briefly unavailable. The temporary connection point
    // and pending gateway record contain enough persisted state to complete the
    // handshake, so reconstruct from them instead of dropping the message.
    let pending_conn = if let Some(pending_conn) = pending_store
        .get_by_temporary_did(inviter_temporary_did)
        .await
    {
        pending_conn
    } else {
        let temp_connection_point = match current_connection_point {
            Some(connection_point) => connection_point.clone(),
            None => {
                let connection_points = cp_store
                    .list_all()
                    .await
                    .map_err(|e| {
                        format!("Failed to list connection points while recovering pending OOB state: {}", e)
                    })?;
                connection_points
                    .into_iter()
                    .find(|cp| cp.cp_type == super::types::ConnectionPointType::System)
                    .ok_or_else(|| {
                        format!("No pending connection found for inviter temporary DID: {}", inviter_temporary_did)
                    })?
            }
        };

        if let Some(pending_conn) = pending_store
            .get_by_temporary_cp_id(&temp_connection_point.id)
            .await
        {
            warn!(
                "Pending OOB state missing by DID for inviter temporary DID {}; recovered by temporary connection point {}",
                inviter_temporary_did, temp_connection_point.id
            );
            pending_conn
        } else {
            let pending_gateway_id = temp_connection_point
                .oob_message
                .get("pending_gateway_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    format!(
                        "No pending connection found for inviter temporary DID: {}; temporary connection point {} has no pending_gateway_id",
                        inviter_temporary_did, temp_connection_point.id
                    )
                })?;
            let pending_gateway_id = pending_gateway_id.to_string();
            let pending_gateway = match gateway_store
                .get(&pending_gateway_id)
                .await
                .map_err(|e| format!("Failed to get pending gateway {}: {}", pending_gateway_id, e))?
            {
                Some(gateway) => gateway,
                None if temp_connection_point.gateway_id != pending_gateway_id => {
                    warn!(
                        "Pending gateway {} from temporary connection point {} metadata not found; trying owner gateway {}",
                        pending_gateway_id, temp_connection_point.id, temp_connection_point.gateway_id
                    );
                    gateway_store
                        .get(&temp_connection_point.gateway_id)
                        .await
                        .map_err(|e| {
                            format!(
                                "Failed to get fallback pending gateway {}: {}",
                                temp_connection_point.gateway_id, e
                            )
                        })?
                        .ok_or_else(|| {
                            format!(
                                "Pending gateway {} not found; fallback owner gateway {} also not found",
                                pending_gateway_id, temp_connection_point.gateway_id
                            )
                        })?
                }
                None => {
                    warn!(
                        "Pending gateway {} not found while recovering OOB state; synthesizing pending connection from temporary connection point {}",
                        pending_gateway_id, temp_connection_point.id
                    );
                    crate::gateways::types::Gateway {
                        id: pending_gateway_id.clone(),
                        tenant_id: None,
                        name: format!(
                            "Gateway {}",
                            &inviter_temporary_did[inviter_temporary_did
                                .len()
                                .saturating_sub(12)..]
                        ),
                        description: format!(
                            "Recovered connection request from {}",
                            &inviter_temporary_did[inviter_temporary_did
                                .len()
                                .saturating_sub(12)..]
                        ),
                        did: inviter_temporary_did.to_string(),
                        issuer_did: None,
                        issuer_did_source: None,
                        trusted_issuer_dids: Vec::new(),
                        gateway_type: crate::gateways::types::GatewayType::Remote,
                        status: crate::gateways::types::GatewayStatus::Pending,
                        creation_type: crate::gateways::types::GatewayCreationType::System,
                        created_at: temp_connection_point.created_at,
                        updated_at: chrono::Utc::now(),
                        exposed_channels: Vec::new(),
                        exposure_mode: Some(crate::gateways::types::ExposureMode::None),
                        opa_policy_config: None,
                    }
                }
            };

            warn!(
                "Pending OOB state missing for inviter temporary DID {}; recovering from temporary connection point {}",
                inviter_temporary_did, temp_connection_point.id
            );
            let recovered_secure_cp_id = temp_connection_point
                .oob_message
                .get("secure_cp_id")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let recovered_secure_did = temp_connection_point
                .oob_message
                .get("secure_did")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let recovered_secure_mediator_did = resolve_recovered_secure_mediator_did(
                &temp_connection_point.oob_message,
                &temp_connection_point.mediator_id,
            );
            let recovered_mediator_record_id = temp_connection_point
                .oob_message
                .get("secure_mediator_id")
                .and_then(|v| v.as_str())
                .map(str::to_string);

            validate_recovered_mediator(
                listener_manager
                    .mediator_store
                    .as_deref(),
                &recovered_secure_mediator_did,
                recovered_mediator_record_id.as_deref(),
                &temp_connection_point.mediator_id,
                &temp_connection_point.id,
            )
            .await?;

            crate::gateways::PendingOOBConnection {
                id: pending_gateway.id.clone(),
                invitation_id: pending_gateway.id.clone(),
                our_temporary_did: temp_connection_point
                    .connection_point_did
                    .clone(),
                our_secure_did: recovered_secure_did,
                their_temporary_did: inviter_temporary_did.to_string(),
                their_secure_did: None,
                their_issuer_did: None,
                mediator_did: recovered_secure_mediator_did,
                connection_point_id: String::new(),
                role: crate::gateways::ConnectionRole::Acceptor,
                state: crate::gateways::ConnectionState::WaitingForResponse,
                created_at: temp_connection_point.created_at,
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                secure_cp_id: recovered_secure_cp_id,
                temporary_cp_id: Some(
                    temp_connection_point
                        .id
                        .clone(),
                ),
                mediator_record_id: recovered_mediator_record_id,
            }
        }
    };

    info!("✓ Found pending connection (invitation ID: {})", pending_conn.invitation_id);

    // Defense-in-depth: verify we are the acceptor and that the sender DID
    // matches their_temporary_did (i.e. the remote party), not our own DID.
    // get_by_temporary_did matches both sides of the connection; without this
    // check a message whose `from` equals our_temporary_did would also resolve
    // and could be used to activate a gateway with an attacker-supplied DID.
    if pending_conn.role != crate::gateways::ConnectionRole::Acceptor {
        return Err(format!(
            "Pending connection {} has unexpected role {:?}; expected Acceptor",
            pending_conn.id, pending_conn.role
        ));
    }
    if pending_conn.their_temporary_did != inviter_temporary_did {
        return Err(format!(
            "Sender DID mismatch: message claims from='{}' but pending connection {} \
             expects their_temporary_did='{}'",
            inviter_temporary_did, pending_conn.id, pending_conn.their_temporary_did
        ));
    }

    // The attestation binds the inviter's gateway DID to the Connection Point DID
    // it will send from; reject the handshake when it is missing or invalid.
    let inviter_issuer_did = crate::gateways::issuer_attestation::verify_issuer_attestation(
        issuer_attestation,
        crate::gateways::issuer_attestation::ExpectedAttestation {
            sub: inviter_secure_did,
            aud: &pending_conn.our_temporary_did,
            nonce: nonce.unwrap_or_default(),
        },
        &listener_manager.get_did_cache(),
    )
    .await
    .map_err(|e| format!("Inviter issuer attestation rejected: {e}"))?;
    info!("✓ Inviter issuer DID verified: {}", inviter_issuer_did);

    // Step 2: Update pending connection with inviter's secure DID
    let mut updated_conn = pending_conn.clone();
    updated_conn.their_secure_did = Some(inviter_secure_did.to_string());
    updated_conn.their_issuer_did = Some(inviter_issuer_did.clone());
    updated_conn.state = crate::gateways::ConnectionState::ReadyToFinalize;

    pending_store
        .update(updated_conn)
        .await;
    info!("✓ Updated pending connection state");

    // Step 3: Update existing pending gateway with inviter's SECURE DID and set to Active
    info!("  Looking for existing pending gateway with temporary DID: {}", inviter_temporary_did);

    let mut gateway = gateway_store
        .get_by_did(inviter_temporary_did)
        .await
        .map_err(|e| format!("Failed to get pending gateway: {}", e))?
        .or_else(|| {
            Some(crate::gateways::types::Gateway {
                id: pending_conn.id.clone(),
                tenant_id: None,
                name: format!(
                    "Gateway {}",
                    &inviter_temporary_did[inviter_temporary_did
                        .len()
                        .saturating_sub(12)..]
                ),
                description: format!(
                    "Recovered connection request from {}",
                    &inviter_temporary_did[inviter_temporary_did
                        .len()
                        .saturating_sub(12)..]
                ),
                did: inviter_temporary_did.to_string(),
                issuer_did: None,
                issuer_did_source: None,
                trusted_issuer_dids: Vec::new(),
                gateway_type: crate::gateways::types::GatewayType::Remote,
                status: crate::gateways::types::GatewayStatus::Pending,
                creation_type: crate::gateways::types::GatewayCreationType::System,
                created_at: pending_conn.created_at,
                updated_at: chrono::Utc::now(),
                exposed_channels: Vec::new(),
                exposure_mode: Some(crate::gateways::types::ExposureMode::None),
                opa_policy_config: None,
            })
        })
        .ok_or_else(|| format!("No pending gateway found for temporary DID: {}", inviter_temporary_did))?;

    info!("✓ Found pending gateway: {}", gateway.id);
    info!("  Keeping user-provided name: {}", gateway.name);
    info!("  Keeping user-provided description: {}", gateway.description);

    // Update the gateway with secure DID and set to Active
    // and use the user-provided name and description
    gateway.did = inviter_secure_did.to_string();
    gateway.issuer_did = Some(inviter_issuer_did);
    gateway.issuer_did_source = Some(crate::gateways::types::IssuerDidSource::Handshake);
    gateway.status = crate::gateways::types::GatewayStatus::Active;
    gateway.updated_at = chrono::Utc::now();

    gateway_store
        .update(&gateway)
        .await
        .map_err(|e| format!("Failed to update gateway: {}", e))?;

    info!("✓ Gateway {} updated to Active with secure DID", gateway.id);

    // Step 4: Create gateway listener endpoint (NOT an OOB connection point!)
    // This is our DID for receiving messages FROM this remote gateway
    // IMPORTANT: Use the SAME DID that we sent in the connection-setup message!
    info!("🎧 Creating gateway listener endpoint...");

    // The pending connection records the permanent connection point's mediator:
    // the acceptor mediator when one was selected, otherwise the inviter's,
    // which is also the handshake mediator.
    let connection_mediator_did = pending_conn
        .mediator_did
        .clone();
    info!("   Using mediator from connection: {}", connection_mediator_did);

    let connection_mediator_doc = selected_mediator_document(
        listener_manager
            .mediator_store
            .as_deref(),
        pending_conn
            .mediator_record_id
            .as_deref(),
        &connection_mediator_did,
    )
    .await?;
    let connection_mediator_url = permanent_mediator_url(
        &connection_mediator_did,
        connection_mediator_doc.as_ref(),
        handshake_mediator_did,
        handshake_mediator_url,
    )?;

    // Extract the UUID from our_secure_did (format: did:web:domain:connection-points:{UUID})
    let cp_id = pending_conn
        .secure_cp_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Use the existing DID that was already created and sent in connection-setup message
    let cp_did = if pending_conn
        .our_secure_did
        .is_empty()
    {
        crate::gateways::connection_points::handlers::generate_connection_point_identity(
            &cp_id,
            &listener_manager
                .network_config
                .as_ref()
                .map(|network_config| {
                    network_config
                        .did
                        .domain
                        .clone()
                })
                .unwrap_or_else(|| "localhost".to_string()),
            std::path::Path::new(
                &bootstrap_config
                    .storage_paths
                    .connection_points,
            ),
            &connection_mediator_url,
            &super::types::ConnectionPointDidMethod::Peer,
            #[cfg(feature = "didwebvh")]
            None,
            #[cfg(feature = "didwebvh")]
            None,
        )
        .await
        .map_err(|e| format!("Failed to recover gateway listener DID: {}", e))?
        .0
    } else {
        pending_conn
            .our_secure_did
            .clone()
    };

    info!("   Using existing gateway listener DID: {}", cp_did);
    info!("   Connection point ID: {}", cp_id);

    let mut connection_point = super::types::GatewayConnectionPoint::new(
        gateway.id.clone(),
        permanent_mediator_reference(
            pending_conn
                .mediator_record_id
                .as_deref(),
            &connection_mediator_did,
        ),
        cp_did.clone(),
        format!("Listener for {}", gateway.name),
        "Gateway listener endpoint (acceptor side)".to_string(),
        String::new(),
        String::new(),
        serde_json::json!({
            "inviter_secure_did": inviter_secure_did
        }),
        None,
        super::types::ConnectionPointType::OobAcceptor, // System-created for OOB acceptor side
        String::new(),                                  // No secret for auto-created connection points
    );

    connection_point.id = cp_id.clone();
    connection_point.last_used_at = Some(chrono::Utc::now());

    cp_store
        .create(&connection_point)
        .await
        .map_err(|e| format!("Failed to store gateway listener: {}", e))?;

    info!("   ✓ Gateway listener endpoint {} created", connection_point.id);

    // Step 4.5: Start listener for this gateway using the connection's mediator.
    // Mediator-side ACLs (if any) are managed by the mediator itself and are
    // not a precondition set by this gateway before starting the listener.
    info!("🎧 Starting gateway listener...");

    match listener_manager.request_start_listener(
        connection_point.clone(),
        connection_mediator_did.clone(),
        connection_mediator_url,
    ) {
        Ok(completion_rx) => {
            info!("   ✓ Gateway listener startup requested");

            // Wait for the listener to actually start (event-driven, no polling)
            info!("   ⏳ Waiting for listener to start...");
            match completion_rx.await {
                Ok(Ok(())) => {
                    info!("   ✓ Listener started successfully");
                }
                Ok(Err(e)) => {
                    warn!("   ⚠️  Listener failed to start: {}", e);
                }
                Err(_) => {
                    warn!("   ⚠️  Listener start notification channel closed");
                }
            }
        }
        Err(e) => {
            warn!("⚠️  Failed to request gateway listener startup: {}", e);
            warn!("  Listener will start on next server restart");
        }
    }

    // Step 5: Cleanup temporary connection point
    // Extract the temporary connection point ID from the temporary DID
    // Format: did:web:domain:connection-points:{UUID}
    let temp_cp_id = pending_conn
        .temporary_cp_id
        .clone()
        .unwrap_or_else(|| {
            pending_conn
                .our_temporary_did
                .split(':')
                .next_back()
                .unwrap_or_default()
                .to_string()
        });

    info!("🧹 Cleaning up temporary connection point: {}", temp_cp_id);

    // Step 5.1: Stop the temporary listener if it's running
    if let Err(e) = listener_manager
        .stop_listener(&temp_cp_id)
        .await
    {
        warn!("   Failed to stop temporary listener: {}", e);
    } else {
        info!("   ✓ Stopped temporary listener");
    }

    // Step 5.2: Delete the temporary connection point from the store
    if let Err(e) = cp_store
        .delete(&temp_cp_id)
        .await
    {
        warn!("   Failed to delete temporary connection point: {}", e);
    } else {
        info!("   ✓ Deleted temporary connection point metadata");
    }

    // Step 5.3: Remove the storage directory
    let temp_storage_path = std::path::PathBuf::from(
        &bootstrap_config
            .storage_paths
            .connection_points,
    )
    .join(temp_cp_id);

    if temp_storage_path.exists() {
        match std::fs::remove_dir_all(&temp_storage_path) {
            Ok(_) => info!("   ✓ Cleaned up temporary DID storage: {:?}", temp_storage_path),
            Err(e) => {
                warn!("   Failed to cleanup temporary DID storage: {}", e)
            }
        }
    }

    // Step 5: Don't remove pending connection yet - caller needs mediator info
    // pending_store.remove(&pending_conn.id).await;
    // info!("✓ Removed pending connection state");

    info!("🎉 OOB connection finalized successfully!");
    info!("  Gateway ID: {}", gateway.id);
    info!("  Gateway DID: {}", gateway.did);

    Ok(gateway)
}
/// Handle OOB connection-setup as INVITER (receiving connection request from acceptor)
async fn handle_oob_connection_setup_as_inviter<CS: super::ConnectionPointStore + 'static>(
    acceptor_temporary_did: &str,
    acceptor_secure_did: &str,
    _invitation_id: &str,
    provided_secret: &str,
    issuer_attestation: Option<&str>,
    nonce: Option<&str>,
    our_temporary_did: &str,
    client: &DIDCommClient,
    gateway_store: &Arc<crate::gateways::FileSystemGatewayStore>,
    _pending_store: &Arc<crate::gateways::PendingConnectionStore>,
    notification_store: &Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    bootstrap_config: &Arc<crate::config::BootstrapConfig>,
    cp_store: &Arc<CS>,
    _mediator_id: &str,
    manager_weak: &Option<std::sync::Weak<ConnectionPointListenerManager>>,
    _mediator_did: &str,
    mediator_url: &str,
) -> Result<(), String> {
    use crate::gateways::filesystem::GatewayStore;
    use crate::gateways::types::{Gateway, GatewayType};

    info!("🔧 Processing connection-setup as INVITER");
    info!("  Acceptor temporary DID: {}", acceptor_temporary_did);
    info!("  Acceptor secure DID: {}", acceptor_secure_did);
    info!("  Our temporary DID: {}", our_temporary_did);

    // Step 0: Validate the secret
    info!("🔐 Step 0: Validating connection secret...");

    let connection_point = match super::message_processor::redeem_invitation(
        cp_store.as_ref(),
        our_temporary_did,
        provided_secret,
    )
    .await
    {
        Ok(connection_point) => connection_point,
        Err(super::message_processor::InvitationRefusal::Unavailable(reason)) => {
            error!("❌ Invitation for {} not redeemed: {}", our_temporary_did, reason);
            return Err(reason);
        }
        Err(super::message_processor::InvitationRefusal::InvalidSecret) => {
            error!("❌ Secret validation failed for invitation {}", our_temporary_did);

            // Send connection-rejected message back to acceptor
            info!("📤 Sending connection-rejected message to acceptor...");

            match crate::comm::didcomm::gateway::send_connection_rejected(
                client,
                our_temporary_did,
                acceptor_temporary_did,
                "Invalid connection secret",
            )
            .await
            {
                Ok(_) => {
                    info!("✓ Connection-rejected message sent successfully");
                }
                Err(e) => {
                    error!("❌ Failed to send connection-rejected message: {}", e);
                }
            }

            return Err("Invalid connection secret".to_string());
        }
    };
    info!("  Redeemed invitation: {} (ID: {})", connection_point.name, connection_point.id);

    info!("✓ Secret validated successfully");
    let outcome: Result<(), String> = async {
        // The attestation binds the acceptor's gateway DID to the Connection Point
        // DID it will send from; reject the handshake when it is missing or invalid.
        let did_cache = manager_weak
            .as_ref()
            .and_then(|w| w.upgrade())
            .map(|m| m.get_did_cache())
            .ok_or_else(|| "Listener manager not available".to_string())?;
        let acceptor_issuer_did = match crate::gateways::issuer_attestation::verify_issuer_attestation(
            issuer_attestation,
            crate::gateways::issuer_attestation::ExpectedAttestation {
                sub: acceptor_secure_did,
                aud: our_temporary_did,
                nonce: nonce.unwrap_or_default(),
            },
            &did_cache,
        )
        .await
        {
            Ok(issuer_did) => issuer_did,
            Err(e) => {
                error!("❌ Issuer attestation rejected for acceptor {}: {}", acceptor_temporary_did, e);
                if let Err(send_err) = crate::comm::didcomm::gateway::send_connection_rejected(
                    client,
                    our_temporary_did,
                    acceptor_temporary_did,
                    "Invalid issuer attestation",
                )
                .await
                {
                    error!("❌ Failed to send connection-rejected message: {}", send_err);
                }
                return Err(format!("Invalid issuer attestation: {e}"));
            }
        };
        info!("✓ Acceptor issuer DID verified: {}", acceptor_issuer_did);
        info!("");

        // Step 1: Check if gateway already exists for this acceptor
        info!("🔍 Checking for existing gateway with acceptor's secure DID...");
        if let Ok(Some(existing_gateway)) = gateway_store
            .get_by_did(acceptor_secure_did)
            .await
        {
            info!("⚠️  Gateway already exists for acceptor DID {}", acceptor_secure_did);
            info!("  Gateway ID: {}", existing_gateway.id);
            info!("  Gateway Status: {:?}", existing_gateway.status);

            // If already awaiting approval or active, don't create duplicate
            if matches!(
                existing_gateway.status,
                crate::gateways::types::GatewayStatus::AwaitingApproval | crate::gateways::types::GatewayStatus::Active
            ) {
                info!("  Gateway already exists - not creating duplicate");
                return Ok(());
            }
        }
        info!("✓ No existing gateway found - proceeding with connection request");
        info!("");

        // Refuse the inbound connection if the appliance gateway limit is reached.
        crate::config::enforce_add("connections.gateways")
            .await
            .map_err(|e| format!("Inbound gateway connection refused (appliance limit): {}", e.message()))?;

        // Step 2: Create our secure DID for the permanent connection
        info!("🔑 Creating our secure DID for permanent connection...");

        // Get network_config from manager
        let network_config = manager_weak
            .as_ref()
            .and_then(|w| w.upgrade())
            .and_then(|m| m.network_config.clone())
            .ok_or_else(|| "Network config not available in listener manager".to_string())?;

        let secure_cp_id = uuid::Uuid::new_v4().to_string();
        let (our_secure_did, _secure_secrets, _secure_doc) =
            crate::gateways::connection_points::handlers::generate_connection_point_identity(
                &secure_cp_id,
                &network_config.did.domain,
                std::path::Path::new(
                    &bootstrap_config
                        .storage_paths
                        .connection_points,
                ),
                mediator_url,
                &connection_point.did_method,
                #[cfg(feature = "didwebvh")]
                None,
                #[cfg(feature = "didwebvh")]
                None,
            )
            .await
            .map_err(|e| format!("Failed to generate secure DID: {}", e))?;

        info!("✓ Our secure DID created: {}", our_secure_did);

        // Step 3: Create the gateway record with AwaitingApproval status
        // Store the acceptor's information so admin can review and approve
        let gateway_name = format!(
            "Gateway {}",
            &acceptor_secure_did[acceptor_secure_did
                .len()
                .saturating_sub(12)..]
        );
        let mut gateway = Gateway::new_with_creation_type(
            gateway_name,
            format!(
                "Connection request from {}",
                &acceptor_temporary_did[acceptor_temporary_did
                    .len()
                    .saturating_sub(12)..]
            ),
            acceptor_secure_did.to_string(),
            GatewayType::Remote,
            crate::gateways::types::GatewayCreationType::System,
        );

        // Set status to AwaitingApproval - requires human approval
        gateway.status = crate::gateways::types::GatewayStatus::AwaitingApproval;
        gateway.issuer_did = Some(acceptor_issuer_did.clone());
        gateway.issuer_did_source = Some(crate::gateways::types::IssuerDidSource::Handshake);

        gateway_store
            .create(&gateway)
            .await
            .map_err(|e| format!("Failed to store gateway: {}", e))?;

        info!("✓ Gateway {} created with AwaitingApproval status", gateway.id);
        info!("  Administrator needs to approve this connection request");
        info!("");

        // Step 4: Store the connection context for later approval
        // We need to save the acceptor and inviter DIDs and our secure DID for when admin approves
        info!("💾 Storing connection context for approval...");

        // Create a pending connection record with all the info needed for approval
        use crate::gateways::pending_connections::{PendingConnection, PendingConnectionState};

        let pending_connection = PendingConnection {
            gateway_id: gateway.id.clone(),
            invitation_id: connection_point.id.clone(),
            our_temporary_did: our_temporary_did.to_string(),
            our_secure_did: our_secure_did.clone(),
            their_temporary_did: acceptor_temporary_did.to_string(),
            their_secure_did: Some(acceptor_secure_did.to_string()),
            their_issuer_did: Some(acceptor_issuer_did),
            state: PendingConnectionState::AwaitingApproval,
            created_at: chrono::Utc::now(),
        };

        if let Err(e) = _pending_store
            .store_approval(&pending_connection)
            .await
        {
            if let Err(delete_err) = gateway_store
                .delete(&gateway.id)
                .await
            {
                error!("❌ Failed to remove gateway {} after a failed setup: {}", gateway.id, delete_err);
            }
            return Err(format!("Failed to store pending connection: {}", e));
        }

        info!("✓ Connection context saved - gateway can be approved later");
        info!("");

        // Step 5: Send notification to administrator
        info!("📬 Creating notification for administrators...");

        if let Some(notif_store) = notification_store {
            use crate::integrations::filesystem::NotificationStore;
            use crate::integrations::types::{Notification, NotificationStatus, NotificationType};

            // For now, create a notification for "system" user (all admins)
            // In a real system, you'd want to query all administrator users
            let notification_id = uuid::Uuid::new_v4().to_string();
            let notification = Notification {
                id: notification_id,
                user_id: "system".to_string(), // System-wide notification for admins
                notification_type: NotificationType::System,
                title: "New Gateway Connection Request".to_string(),
                message: format!(
                    "A new gateway connection request requires approval.\n\n\
                    Gateway: {}\n\
                    DID: {}\n\
                    Connection Point: {}\n\n\
                    Please review and approve or reject this connection in the Gateways section.",
                    gateway.name,
                    &acceptor_secure_did[..acceptor_secure_did
                        .len()
                        .min(50)],
                    connection_point.name
                ),
                metadata: serde_json::json!({
                    "gateway_id": gateway.id,
                    "gateway_did": acceptor_secure_did,
                    "connection_point_id": connection_point.id,
                    "connection_point_name": connection_point.name,
                    "action_required": "approval"
                }),
                status: NotificationStatus::New,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            match notif_store
                .create(&notification)
                .await
            {
                Ok(_) => {
                    info!("✓ System notification created for administrators");
                    info!("  Notification ID: {}", notification.id);
                    info!("  Gateway: {}", gateway.name);
                }
                Err(e) => {
                    error!("❌ Failed to create notification: {}", e);
                }
            }
        } else {
            info!("  (Notification store not configured - skipping notification)");
        }

        info!("");
        info!("✅ Connection request received and stored - awaiting administrator approval");

        Ok(())
    }
    .await;
    if outcome.is_err() {
        super::message_processor::release_invitation(cp_store.as_ref(), &connection_point.id).await;
    }
    outcome
}

/// Spawn a temporary listener for OOB acceptor to receive connection-accepted message
/// This listener will automatically cleanup after receiving the message or timing out
#[allow(dead_code)]
pub async fn spawn_oob_acceptor_listener<S: GatewayStore + 'static, CS: super::ConnectionPointStore + 'static>(
    temp_did: String,
    pending_gateway_id: String,
    client: DIDCommClient,
    gateway_store: Arc<S>,
    pending_store: Arc<crate::gateways::PendingConnectionStore>,
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    cp_store: Arc<CS>,
    listener_manager: Arc<ConnectionPointListenerManager>,
    mediator_did: String,
    mediator_url: String,
) {
    crate::observability::spawn_traced_task(&format!("oob_listener.{}", pending_gateway_id), async move {
        info!("🎧 Starting temporary listener for OOB acceptor (pending gateway: {})", pending_gateway_id);
        info!("   Listening on temporary DID: {}", temp_did);
        info!("   Will auto-cleanup after receiving connection-accepted or 5 minute timeout");

        // Set a 5-minute timeout for the entire listener
        let pending_gateway_id_clone = pending_gateway_id.clone();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            listen_for_connection_accepted(
                temp_did,
                pending_gateway_id,
                client,
                gateway_store,
                pending_store,
                bootstrap_config,
                cp_store,
                listener_manager,
                mediator_did,
                mediator_url,
            ),
        )
        .await;

        match result {
            Ok(Ok(())) => {
                info!("✅ OOB acceptor listener completed successfully");
            }
            Ok(Err(e)) => {
                error!("❌ OOB acceptor listener failed: {}", e);
            }
            Err(_) => {
                warn!("⏱️  OOB acceptor listener timed out after 5 minutes");
                warn!("   Pending gateway {} may remain in Pending state", pending_gateway_id_clone);
            }
        }
    });
}

/// Listen for connection-accepted message on temporary DID
#[allow(dead_code)]
async fn listen_for_connection_accepted<S: GatewayStore, CS: super::ConnectionPointStore>(
    _temp_did: String,
    _pending_gateway_id: String,
    client: DIDCommClient,
    gateway_store: Arc<S>,
    pending_store: Arc<crate::gateways::PendingConnectionStore>,
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    cp_store: Arc<CS>,
    listener_manager: Arc<ConnectionPointListenerManager>,
    mediator_did: String,
    mediator_url: String,
) -> Result<(), String> {
    info!("📥 Polling for messages on temporary DID...");

    // Poll for messages every 2 seconds
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut poll_count = 0;

    loop {
        interval.tick().await;
        poll_count += 1;

        if poll_count % 10 == 0 {
            info!("   Still listening... ({} polls)", poll_count);
        }

        // Fetch messages
        let response = match client
            .atm()
            .fetch_messages(client.profile(), &Default::default())
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!("   Failed to fetch messages: {:?}", e);
                continue;
            }
        };

        let messages = response.success;

        if messages.is_empty() {
            continue;
        }

        info!("📬 Received {} message(s)", messages.len());

        // Process each message
        for msg_envelope in messages {
            info!("   Processing message ID: {}", msg_envelope.msg_id);

            // Unpack the message
            let msg_str = msg_envelope
                .msg
                .as_ref()
                .ok_or_else(|| "Message content is missing".to_string())?;

            let (message, _metadata): (affinidi_messaging_didcomm::Message, _) = match client
                .atm()
                .unpack(msg_str)
                .await
            {
                Ok(result) => result,
                Err(e) => {
                    error!("   Failed to unpack message: {:?}", e);
                    continue;
                }
            };

            info!("   Message type: {}", message.typ);

            // Check if it's connection-accepted
            if message.typ == MessageType::ConnectionAccepted.to_string() {
                info!("🎉 Received connection-accepted message!");

                // Extract inviter's secure DID from the message body
                let inviter_secure_did = message
                    .body
                    .get("channel_did")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "Missing channel_did in connection-accepted message".to_string())?;

                info!("   Inviter's secure DID: {}", inviter_secure_did);

                // Call finalize function with the temporary DID (since that's what we stored the gateway under)
                let inviter_temp_did = message
                    .from
                    .as_ref()
                    .ok_or_else(|| "Missing 'from' field in connection-accepted message".to_string())?;

                let issuer_attestation = message
                    .body
                    .get("issuer_attestation")
                    .and_then(|v| v.as_str());

                let gateway = finalize_oob_connection_as_acceptor(
                    inviter_temp_did,
                    inviter_secure_did,
                    issuer_attestation,
                    message.thid.as_deref(),
                    &gateway_store,
                    &pending_store,
                    &bootstrap_config,
                    &cp_store,
                    &listener_manager,
                    None,
                    &mediator_did,
                    &mediator_url,
                )
                .await
                .map_err(|e| {
                    error!("❌ Failed to finalize OOB connection: {}", e);
                    e
                })?;

                info!("✅ Gateway finalized: {} ({})", gateway.id, gateway.did);

                // Now remove the pending connection (we're done with it)
                if let Some(pending_conn) = pending_store
                    .get_by_temporary_did(inviter_temp_did)
                    .await
                {
                    pending_store
                        .remove(&pending_conn.id)
                        .await;
                    info!("   ✓ Removed pending connection state");
                } else {
                    warn!("   Could not find pending connection to remove (may have been removed already)");
                }

                // Delete the message from mediator
                let delete_req = affinidi_messaging_sdk::messages::DeleteMessageRequest {
                    message_ids: vec![msg_envelope.msg_id.clone()],
                };
                if let Err(e) = client
                    .atm()
                    .delete_messages_direct(client.profile(), &delete_req)
                    .await
                {
                    warn!("   Failed to delete message from mediator: {:?}", e);
                }

                info!("✅ OOB connection fully established with permanent listener, stopping temporary listener");
                return Ok(());
            } else if message.typ == MessageType::ConnectionRejected.to_string() {
                error!("❌ Received connection-rejected message!");

                // Extract rejection reason
                let reason = message
                    .body
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown reason");

                error!("   Rejection reason: {}", reason);

                // Update the pending gateway to failed status
                let inviter_temp_did = message
                    .from
                    .as_ref()
                    .ok_or_else(|| "Missing 'from' field in connection-rejected message".to_string())?;

                // Find the pending gateway by the inviter's temporary DID
                if let Ok(Some(mut gateway)) = gateway_store
                    .get_by_did(inviter_temp_did)
                    .await
                {
                    info!("   Updating gateway {} to Failed status", gateway.id);
                    gateway.status = crate::gateways::types::GatewayStatus::Failed;
                    gateway.description = format!("Connection rejected: {}", reason);

                    if let Err(e) = gateway_store
                        .update(&gateway)
                        .await
                    {
                        error!("   Failed to update gateway status: {}", e);
                    } else {
                        info!("   ✓ Gateway status updated to Failed");
                    }
                } else {
                    warn!("   Could not find pending gateway to update");
                }

                // Remove the pending connection
                if let Some(pending_conn) = pending_store
                    .get_by_temporary_did(inviter_temp_did)
                    .await
                {
                    pending_store
                        .remove(&pending_conn.id)
                        .await;
                    info!("   ✓ Removed pending connection state");
                }

                // Delete the message from mediator
                let delete_req = affinidi_messaging_sdk::messages::DeleteMessageRequest {
                    message_ids: vec![msg_envelope.msg_id.clone()],
                };
                if let Err(e) = client
                    .atm()
                    .delete_messages_direct(client.profile(), &delete_req)
                    .await
                {
                    warn!("   Failed to delete message from mediator: {:?}", e);
                }

                error!("❌ OOB connection rejected, stopping temporary listener");
                return Err(format!("Connection rejected: {}", reason));
            } else {
                info!("   Skipping non-connection-accepted message type: {}", message.typ);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn a_peer_past_its_open_rate_is_refused_without_slowing_other_peers() {
        let limiter = super::open_rate_limiter();
        let admitted = (0..super::PEER_OPEN_BURST * 2)
            .filter(|_| super::admits_from_peer(&limiter, Some("did:example:noisy")))
            .count();

        assert!(
            (super::PEER_OPEN_BURST as usize..super::PEER_OPEN_BURST as usize + 5).contains(&admitted),
            "admitted {admitted}"
        );
        assert!(!super::admits_from_peer(&limiter, Some("did:example:noisy")));
        assert!(super::admits_from_peer(&limiter, Some("did:example:quiet")));
    }

    #[test]
    fn capability_queries_have_a_tighter_per_peer_rate_than_opens() {
        let limiter = super::query_rate_limiter();
        let admitted = (0..super::PEER_QUERY_BURST * 2)
            .filter(|_| super::admits_from_peer(&limiter, Some("did:example:prober")))
            .count();

        assert!(
            (super::PEER_QUERY_BURST as usize..super::PEER_QUERY_BURST as usize + 3).contains(&admitted),
            "admitted {admitted}"
        );
        const { assert!(super::PEER_QUERY_BURST < super::PEER_OPEN_BURST) };
        assert!(super::admits_from_peer(&limiter, Some("did:example:peer")));
    }

    fn open_from(stream_id: Option<uuid::Uuid>) -> crate::gateways::connection_points::messages::ReceivedMessage {
        crate::gateways::connection_points::messages::ReceivedMessage::new(
            "cp".into(),
            "gateway".into(),
            MessageType::ForwardStreamFrame.to_string(),
            uuid::Uuid::new_v4().to_string(),
            None,
            Some("did:example:peer".into()),
            vec!["did:example:local".into()],
            None,
            None,
            serde_json::json!({ "stream_id": stream_id, "payload": { "kind": "open" } }),
            crate::gateways::connection_points::messages::MessageMetadata {
                authenticated: true,
                encrypted: true,
                from_key: None,
                extra: serde_json::Value::Null,
            },
        )
    }

    #[tokio::test]
    async fn open_admission_runs_off_the_reader_loop_and_is_bounded() {
        use crate::proxy::fabric_stream::wire::StreamErrorCode;

        let runtime = StreamRuntime::test_runtime();
        let admissions = Arc::new(Semaphore::new(1));
        let mut tasks = JoinSet::new();
        let finish = Arc::new(tokio::sync::Notify::new());
        let (first, second) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());

        let waiting = Arc::clone(&finish);
        super::start_open_admission(
            &mut tasks,
            &admissions,
            &runtime.registry,
            &open_from(Some(first)),
            move |held, permit| async move {
                waiting.notified().await;
                drop((held, permit));
            },
        )
        .expect("the reader loop goes on while the Open is admitted");
        assert!(
            runtime
                .registry
                .was_opened(&first),
            "frames for the Open are held while it is admitted"
        );

        let refusal = super::start_open_admission(
            &mut tasks,
            &admissions,
            &runtime.registry,
            &open_from(Some(second)),
            |_, _| async {},
        )
        .expect_err("no admission slot is free");
        assert_eq!(refusal.code, StreamErrorCode::CapacityReached);
        assert!(
            !runtime
                .registry
                .was_opened(&second),
            "a refused Open holds nothing"
        );

        finish.notify_one();
        tasks
            .join_next()
            .await
            .unwrap()
            .unwrap();
        super::start_open_admission(
            &mut tasks,
            &admissions,
            &runtime.registry,
            &open_from(Some(second)),
            |_, _| async {},
        )
        .expect("the slot is free again once admission ends");
    }

    #[tokio::test]
    async fn a_repeated_or_malformed_open_is_refused_without_taking_a_slot() {
        let runtime = StreamRuntime::test_runtime();
        let admissions = Arc::new(Semaphore::new(2));
        let mut tasks = JoinSet::new();
        let stream_id = uuid::Uuid::new_v4();
        let finish = Arc::new(tokio::sync::Notify::new());
        let waiting = Arc::clone(&finish);
        super::start_open_admission(
            &mut tasks,
            &admissions,
            &runtime.registry,
            &open_from(Some(stream_id)),
            move |held, permit| async move {
                waiting.notified().await;
                drop((held, permit));
            },
        )
        .unwrap();

        for message in [open_from(Some(stream_id)), open_from(None)] {
            assert!(
                super::start_open_admission(&mut tasks, &admissions, &runtime.registry, &message, |_, _| async {})
                    .is_err()
            );
            assert_eq!(admissions.available_permits(), 1, "a refused Open gives its slot back");
        }
        finish.notify_one();
    }

    #[tokio::test]
    async fn an_admission_that_ends_without_releasing_drops_its_held_frames() {
        let runtime = StreamRuntime::test_runtime();
        let admissions = Arc::new(Semaphore::new(2));
        let mut tasks = JoinSet::new();
        let (aborted, panicked) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());

        super::start_open_admission(
            &mut tasks,
            &admissions,
            &runtime.registry,
            &open_from(Some(panicked)),
            |held, _permit| async move {
                let _held = held;
                panic!("admission failed");
            },
        )
        .unwrap();
        assert!(
            tasks
                .join_next()
                .await
                .unwrap()
                .is_err_and(|error| error.is_panic())
        );
        assert!(
            !runtime
                .registry
                .was_opened(&panicked),
            "a panicking admission holds nothing"
        );

        super::start_open_admission(
            &mut tasks,
            &admissions,
            &runtime.registry,
            &open_from(Some(aborted)),
            |held, _permit| async move {
                let _held = held;
                std::future::pending::<()>().await;
            },
        )
        .unwrap();
        tokio::task::yield_now().await;
        assert!(
            runtime
                .registry
                .was_opened(&aborted)
        );
        tasks.shutdown().await;
        assert!(
            !runtime
                .registry
                .was_opened(&aborted),
            "an admission aborted with its listener holds nothing"
        );
        assert_eq!(admissions.available_permits(), 2);
    }

    /// A Connection Point store that answers `get` with `record` after
    /// `delay`, running `on_get` first. Admission reads nothing else.
    struct StubConnectionPoints {
        record: Option<crate::gateways::connection_points::types::GatewayConnectionPoint>,
        delay: std::time::Duration,
        on_get: Box<dyn Fn() + Send + Sync>,
    }

    #[async_trait::async_trait]
    impl crate::gateways::connection_points::ConnectionPointStore for StubConnectionPoints {
        async fn create(
            &self,
            _: &crate::gateways::connection_points::types::GatewayConnectionPoint,
        ) -> anyhow::Result<()> {
            unreachable!("admission only reads its Connection Point")
        }

        async fn get(
            &self,
            _: &str,
        ) -> anyhow::Result<Option<crate::gateways::connection_points::types::GatewayConnectionPoint>> {
            (self.on_get)();
            tokio::time::sleep(self.delay).await;
            Ok(self.record.clone())
        }

        async fn list_all(
            &self
        ) -> anyhow::Result<Vec<crate::gateways::connection_points::types::GatewayConnectionPoint>> {
            unreachable!("admission only reads its Connection Point")
        }

        async fn list_by_gateway(
            &self,
            _: &str,
        ) -> anyhow::Result<Vec<crate::gateways::connection_points::types::GatewayConnectionPoint>> {
            unreachable!("admission only reads its Connection Point")
        }

        async fn update(
            &self,
            _: &crate::gateways::connection_points::types::GatewayConnectionPoint,
        ) -> anyhow::Result<()> {
            unreachable!("admission only reads its Connection Point")
        }

        async fn update_if_exists(
            &self,
            _: &crate::gateways::connection_points::types::GatewayConnectionPoint,
        ) -> anyhow::Result<bool> {
            unreachable!("admission only reads its Connection Point")
        }

        async fn delete(
            &self,
            _: &str,
        ) -> anyhow::Result<()> {
            unreachable!("admission only reads its Connection Point")
        }
    }

    /// Admits an Open the peer's sender built, holding its stream's frames
    /// meanwhile, with the Connection Point `connection_points` reads.
    async fn admit_open(
        fixture: &crate::proxy::fabric_stream::test_fixture::OpenFixture,
        gateways: &Arc<crate::gateways::FileSystemGatewayStore>,
        connection_points: StubConnectionPoints,
    ) -> (
        uuid::Uuid,
        Result<Option<crate::proxy::fabric_stream::IncomingStream>, crate::proxy::fabric_stream::OpenRefusal>,
    ) {
        let nonce = uuid::Uuid::new_v4();
        fixture
            .runtime
            .process(&fixture.capability_query(nonce), &MessageType::ForwardStreamQuery);
        let open = fixture.open(nonce);
        let stream_id = uuid::Uuid::parse_str(
            open.message_body["stream_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let held = fixture
            .runtime
            .registry
            .hold(stream_id, &fixture.peer.did)
            .unwrap();
        let gate = super::OpenGate {
            runtime: Arc::clone(&fixture.runtime),
            message: open,
            connection_point: Arc::new(fixture.connection.clone()),
            cp_store: Some(Arc::new(connection_points)),
            gateway_store: Some(Arc::clone(gateways)),
        };
        (stream_id, gate.admit_held(held).await)
    }

    #[tokio::test]
    async fn open_admission_reads_the_current_records_and_refuses_an_open_access_changed_under() {
        use crate::gateways::GatewayStore;
        use crate::proxy::fabric_stream::test_fixture::{OpenFixture, in_isolated_child};
        use std::time::Duration;

        if !in_isolated_child("Open admission").await {
            return;
        }
        let fixture = OpenFixture::new().await;
        let directory = tempfile::tempdir().unwrap();
        let gateways = Arc::new(
            crate::gateways::FileSystemGatewayStore::new(
                directory
                    .path()
                    .join("gateways"),
                None,
            )
            .await
            .unwrap(),
        );
        gateways
            .create(&fixture.peer)
            .await
            .unwrap();
        let current = |record| StubConnectionPoints {
            record,
            delay: Duration::ZERO,
            on_get: Box::new(|| {}),
        };
        let registry = &fixture.runtime.registry;

        let (admitted, outcome) = admit_open(&fixture, &gateways, current(Some(fixture.connection.clone()))).await;
        let incoming = outcome
            .expect("the records admit the Open")
            .expect("the hold was kept");
        assert!(registry.is_running(&admitted));
        drop(incoming);

        let mut disabled = fixture.connection.clone();
        disabled.enabled = false;
        let mut narrowed = fixture.connection.clone();
        narrowed.exposed_channels = vec!["another-surface".into()];
        for (record, case) in [
            (Some(disabled), "a Connection Point disabled since its listener started"),
            (Some(narrowed), "a Connection Point that stopped exposing the surface"),
            (None, "a removed Connection Point"),
        ] {
            let (stream_id, outcome) = admit_open(&fixture, &gateways, current(record)).await;
            assert!(outcome.is_err(), "{case}");
            assert!(!registry.is_running(&stream_id), "{case}");
            assert!(!registry.was_opened(&stream_id), "{case}: the held frames are dropped");
        }

        let revoking = Arc::clone(&fixture.runtime);
        let (stream_id, outcome) = admit_open(
            &fixture,
            &gateways,
            StubConnectionPoints {
                record: Some(fixture.connection.clone()),
                delay: Duration::ZERO,
                on_get: Box::new(move || {
                    revoking
                        .registry
                        .revoke(|_, _| false)
                }),
            },
        )
        .await;
        let Err(refusal) = outcome else {
            panic!("an Open admitted while a revocation ran is refused");
        };
        assert_eq!(refusal.to_string(), "Fabric access changed while the Open was admitted");
        assert!(!registry.is_running(&stream_id), "nothing stays registered");

        let (stream_id, outcome) = admit_open(
            &fixture,
            &gateways,
            StubConnectionPoints {
                record: Some(fixture.connection.clone()),
                delay: super::OPEN_ADMISSION_TIMEOUT + Duration::from_secs(1),
                on_get: Box::new(|| {}),
            },
        )
        .await;
        let Err(refusal) = outcome else {
            panic!("an admission past its deadline is refused");
        };
        assert_eq!(refusal.to_string(), "Fabric Open admission timed out");
        assert!(!registry.was_opened(&stream_id), "the held frames are dropped");
    }

    use futures::FutureExt;
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    use super::{
        DispatchSlot, dispatch_slot, dispatches_inline, is_authorization_error, listener_index_priority,
        preferred_gateway_listener_id,
    };
    use crate::gateways::connection_points::types::ConnectionPointType;
    use crate::messages::MessageType;
    use crate::proxy::fabric_stream::{ListenerGeneration, StreamRuntime, registry::StreamBinding};

    fn stream_listener() -> (Arc<StreamRuntime>, ListenerGeneration) {
        let runtime = StreamRuntime::test_runtime();
        let listener = runtime
            .listener("cp".into(), "did:example:local".into())
            .unwrap();
        (runtime, listener)
    }

    fn saturated() -> (Arc<Semaphore>, tokio::sync::OwnedSemaphorePermit) {
        let semaphore = Arc::new(Semaphore::new(1));
        let held = Arc::clone(&semaphore)
            .try_acquire_owned()
            .unwrap();
        (semaphore, held)
    }

    #[tokio::test]
    async fn saturated_dispatch_answers_forward_requests_with_a_retryable_503() {
        let (_runtime, mut listener) = stream_listener();
        let mut tasks = JoinSet::new();
        let (semaphore, _held) = saturated();

        let slot = dispatch_slot(&semaphore, MessageType::ForwardRequest.as_str(), &mut listener, &mut tasks)
            .now_or_never()
            .expect("a saturated ForwardRequest must not wait for a slot")
            .unwrap();

        let DispatchSlot::Overloaded(response) = slot else {
            panic!("a saturated ForwardRequest must not be dispatched");
        };
        assert_eq!(response["status"], 503);
        assert_eq!(response["headers"]["retry-after"], "1");
        assert_eq!(response["headers"]["content-type"], "application/json");
        let body: serde_json::Value = serde_json::from_str(
            response["body"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"], "Gateway dispatch capacity unavailable");
        assert_eq!(semaphore.available_permits(), 0);
    }

    #[tokio::test]
    async fn free_dispatch_slot_is_granted_immediately() {
        let (_runtime, mut listener) = stream_listener();
        let mut tasks = JoinSet::new();
        let semaphore = Arc::new(Semaphore::new(2));
        let mut permits = Vec::new();

        for message_type in [MessageType::ForwardRequest, MessageType::X402VerifyResponse] {
            let slot = dispatch_slot(&semaphore, message_type.as_str(), &mut listener, &mut tasks)
                .now_or_never()
                .expect("a free slot must be granted without waiting")
                .unwrap();
            let DispatchSlot::Permit(permit) = slot else {
                panic!("{message_type} was refused a free slot");
            };
            permits.push(permit);
        }

        assert_eq!(semaphore.available_permits(), 0);
        drop(permits);
        assert_eq!(semaphore.available_permits(), 2);
    }

    #[tokio::test]
    async fn saturated_dispatch_queues_other_messages_while_serving_outgoing_streams() {
        let (runtime, mut listener) = stream_listener();
        let (instance, recipient) = runtime
            .listener_context("cp")
            .unwrap();
        let binding = StreamBinding {
            peer_did: "did:example:peer".into(),
            recipient_did: recipient,
            connection_point_id: "cp".into(),
            listener_instance_id: instance,
            surface_id: "surface".into(),
        };
        let mut tasks = JoinSet::new();
        let (semaphore, held) = saturated();
        let (ran_tx, ran_rx) = tokio::sync::oneshot::channel();
        runtime
            .enqueue_outgoing(&binding, async move {
                let _ = ran_tx.send(());
            })
            .unwrap();

        let waiting = dispatch_slot(&semaphore, MessageType::X402VerifyResponse.as_str(), &mut listener, &mut tasks);
        let release_after_outgoing_task_runs = async move {
            ran_rx
                .await
                .expect("the outgoing task must run while the message waits");
            drop(held);
        };
        let (slot, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(waiting, release_after_outgoing_task_runs)
        })
        .await
        .expect("the waiting message must get the freed slot");

        let Ok(DispatchSlot::Permit(_permit)) = slot else {
            panic!("a queued message must be dispatched, not shed");
        };
        assert_eq!(semaphore.available_permits(), 0);
    }

    #[tokio::test]
    async fn saturated_dispatch_stops_waiting_when_the_listener_generation_is_replaced() {
        let (runtime, mut listener) = stream_listener();
        let mut tasks = JoinSet::new();
        let (semaphore, _held) = saturated();
        let _replacement = runtime
            .listener("cp".into(), "did:example:local".into())
            .unwrap();

        let slot = tokio::time::timeout(
            Duration::from_secs(5),
            dispatch_slot(&semaphore, MessageType::X402VerifyResponse.as_str(), &mut listener, &mut tasks),
        )
        .await
        .expect("a replaced listener must stop waiting for a slot");

        let Err(error) = slot else {
            panic!("a replaced listener must not dispatch");
        };
        assert_eq!(error, "Fabric listener generation was replaced");
        assert_eq!(semaphore.available_permits(), 0);
    }

    #[test]
    fn only_the_mediator_can_force_an_account_reconnect() {
        assert!(super::mediator_reported(Some("did:peer:mediator"), "did:peer:mediator"));
        assert!(super::mediator_reported(Some("did:peer:mediator#key-1"), "did:peer:mediator"));
        assert!(super::mediator_reported(Some("did:peer:mediator"), "did:peer:mediator#key-1"));
        for sender in [Some("did:peer:peer"), Some("did:peer:peer#did:peer:mediator"), Some("did:peer:mediatorx"), None]
        {
            assert!(!super::mediator_reported(sender, "did:peer:mediator"), "{sender:?}");
        }
    }

    const MEDIATOR_DID: &str = "did:web:mediator.example.com";
    const CONNECTION_POINT_DID: &str = "did:web:gateway.example.com:cp";

    /// A problem report as the mediator's WebSocket handler packages it: its
    /// own DID as `from`, the session DID as `to`, the failed message as
    /// `pthid`, and a `ProblemReport` body.
    fn mediator_problem_report(
        sender: &str,
        descriptor: &str,
    ) -> super::ReceivedMessage {
        use affinidi_messaging_sdk::messages::problem_report::{
            ProblemReport, ProblemReportScope, ProblemReportSorter,
        };

        let report = ProblemReport::new(
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            descriptor.to_string(),
            "account {1} not found".to_string(),
            vec![CONNECTION_POINT_DID.to_string()],
            None,
        );
        let envelope = affinidi_messaging_didcomm::Message::build(
            uuid::Uuid::new_v4().to_string(),
            "https://didcomm.org/report-problem/2.0/problem-report".to_string(),
            serde_json::json!(report),
        )
        .from(sender.to_string())
        .to(CONNECTION_POINT_DID.to_string())
        .created_time(1_760_000_000)
        .pthid(uuid::Uuid::new_v4().to_string())
        .finalize();
        let connection_point = super::GatewayConnectionPoint::new(
            "gw-1".to_string(),
            MEDIATOR_DID.to_string(),
            CONNECTION_POINT_DID.to_string(),
            "cp".to_string(),
            String::new(),
            "oob-1".to_string(),
            "https://oob.example.com".to_string(),
            serde_json::json!({}),
            None,
            ConnectionPointType::OobAcceptor,
            String::new(),
        );

        super::received_message(
            &connection_point,
            CONNECTION_POINT_DID,
            &envelope,
            &affinidi_messaging_sdk::messages::compat::UnpackMetadata::default(),
        )
    }

    #[test]
    fn a_mediator_account_not_found_report_ends_the_reader() {
        let received = mediator_problem_report(MEDIATOR_DID, "account.not_found");

        assert_eq!(received.from_did.as_deref(), Some(MEDIATOR_DID));
        assert_eq!(received.to_dids, vec![CONNECTION_POINT_DID.to_string()]);
        assert_eq!(super::mediator_account_loss(&received, MEDIATOR_DID), Some("e.p.account.not_found"));
        assert_eq!(
            super::mediator_account_loss(&received, &format!("{MEDIATOR_DID}#key-1")),
            Some("e.p.account.not_found")
        );
    }

    #[test]
    fn an_account_not_found_report_from_another_sender_keeps_the_socket() {
        for sender in ["did:web:peer.example.com", "did:web:mediator.example.com.attacker"] {
            let received = mediator_problem_report(sender, "account.not_found");

            assert_eq!(received.from_did.as_deref(), Some(sender));
            assert_eq!(super::mediator_account_loss(&received, MEDIATOR_DID), None, "{sender}");
        }
    }

    #[test]
    fn other_mediator_reports_keep_the_socket() {
        let denied = mediator_problem_report(MEDIATOR_DID, "authorization.account.denied");
        assert_eq!(super::mediator_account_loss(&denied, MEDIATOR_DID), None);

        let mut not_a_report = mediator_problem_report(MEDIATOR_DID, "account.not_found");
        not_a_report.message_type = MessageType::MessagePickupStatus
            .as_str()
            .to_string();
        assert_eq!(super::mediator_account_loss(&not_a_report, MEDIATOR_DID), None);
    }

    #[tokio::test]
    async fn only_an_active_peer_may_query_stream_capabilities() {
        use crate::gateways::filesystem::GatewayStore;
        use crate::gateways::types::{Gateway, GatewayStatus, GatewayType};
        let directory = tempfile::tempdir().unwrap();
        let store = crate::gateways::FileSystemGatewayStore::new(directory.path().to_path_buf(), None)
            .await
            .unwrap();
        for (did, status) in
            [("did:web:active.example", GatewayStatus::Active), ("did:web:disabled.example", GatewayStatus::Disabled)]
        {
            let mut gateway = Gateway::new("Peer".into(), String::new(), did.into(), GatewayType::Remote);
            gateway.status = status;
            store
                .create(&gateway)
                .await
                .unwrap();
        }
        let active = super::active_peer_gateway(Some(&store), Some("did:web:active.example")).await;
        assert_eq!(active.map(|gateway| gateway.did), Some("did:web:active.example".to_string()));
        for sender in [Some("did:web:disabled.example"), Some("did:web:stranger.example"), None] {
            assert!(
                super::active_peer_gateway(Some(&store), sender)
                    .await
                    .is_none(),
                "{sender:?}"
            );
        }
        assert!(
            super::active_peer_gateway(None, Some("did:web:active.example"))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_reader_admits_a_capability_query_only_from_an_active_peer() {
        use crate::gateways::GatewayStore;
        use crate::gateways::types::GatewayStatus;
        use crate::proxy::fabric_stream::test_fixture::{OpenFixture, in_isolated_child};

        if !in_isolated_child("capability query admission").await {
            return;
        }
        let fixture = OpenFixture::new().await;
        let directory = tempfile::tempdir().unwrap();
        let gateways = crate::gateways::FileSystemGatewayStore::new(directory.path().to_path_buf(), None)
            .await
            .unwrap();
        let query_rate = super::query_rate_limiter();
        let tenant_context = crate::proxy::fabric_stream::PEER_TENANT_CONTEXT;

        let nonce = uuid::Uuid::new_v4();
        let mut from_stranger = fixture.capability_query(nonce);
        assert!(!super::admit_capability_query(&query_rate, Some(&gateways), &mut from_stranger).await);
        assert!(
            !from_stranger
                .context
                .contains_key(tenant_context)
        );
        assert!(!fixture.offered(&from_stranger, nonce, std::time::Instant::now()), "no offer for a stranger");

        let mut disabled = fixture.peer.clone();
        disabled.status = GatewayStatus::Disabled;
        gateways
            .create(&disabled)
            .await
            .unwrap();
        let nonce = uuid::Uuid::new_v4();
        let mut from_disabled = fixture.capability_query(nonce);
        assert!(!super::admit_capability_query(&query_rate, Some(&gateways), &mut from_disabled).await);
        assert!(
            !from_disabled
                .context
                .contains_key(tenant_context)
        );
        assert!(!fixture.offered(&from_disabled, nonce, std::time::Instant::now()), "no offer for a disabled peer");

        let mut active = fixture.peer.clone();
        active.status = GatewayStatus::Active;
        active.tenant_id = Some("tenant-a".into());
        gateways
            .update(&active)
            .await
            .unwrap();
        let nonce = uuid::Uuid::new_v4();
        let mut from_peer = fixture.capability_query(nonce);
        assert!(super::admit_capability_query(&query_rate, Some(&gateways), &mut from_peer).await);
        assert_eq!(from_peer.context[tenant_context], serde_json::json!("tenant-a"));
        assert!(matches!(
            fixture
                .runtime
                .process(&from_peer, &MessageType::ForwardStreamQuery),
            super::message_processor::ProcessingResult::RequiresResponse { .. }
        ));
        assert!(fixture.offered(&from_peer, nonce, std::time::Instant::now()), "the active peer is offered streams");
    }

    #[test]
    fn waiter_completing_replies_dispatch_inline_and_requests_are_queued() {
        for inline in [
            MessageType::ForwardResponse,
            MessageType::GatewayIssuerResponse,
            MessageType::ForwardStreamFrame,
            MessageType::ForwardStreamQuery,
            MessageType::ForwardStreamDisclose,
        ] {
            assert!(dispatches_inline(&inline.to_string()), "{inline}");
        }
        assert!(dispatches_inline("https://affinidi.com/atm/client-actions/connection-setup"));
        for queued in [MessageType::ForwardRequest, MessageType::GatewayIssuerRequest] {
            assert!(!dispatches_inline(&queued.to_string()), "{queued}");
        }
    }

    #[test]
    fn recovered_secure_mediator_prefers_recorded_field() {
        let oob_message = serde_json::json!({
            "secure_did": "did:web:acceptor.example.com:connection-points:abc",
            "secure_mediator_did": "did:web:m2.example.com:.well-known",
        });
        assert_eq!(
            super::resolve_recovered_secure_mediator_did(&oob_message, "did:web:m1.example.com:.well-known"),
            "did:web:m2.example.com:.well-known"
        );
    }

    #[test]
    fn recovered_secure_mediator_falls_back_when_field_absent() {
        // Connections created before per-gateway mediator selection existed have
        // no "secure_mediator_did" in their temp CP metadata; the recovery path
        // must fall back to the temp CP's own (inviter) mediator, not error out.
        let oob_message = serde_json::json!({
            "secure_did": "did:web:acceptor.example.com:connection-points:abc",
        });
        assert_eq!(
            super::resolve_recovered_secure_mediator_did(&oob_message, "did:web:m1.example.com:.well-known"),
            "did:web:m1.example.com:.well-known"
        );
    }

    fn mediator(
        did: &str,
        status: crate::mediators::types::MediatorStatus,
    ) -> crate::mediators::types::Mediator {
        let now = chrono::Utc::now();
        crate::mediators::types::Mediator {
            id: format!("mediator-{did}"),
            tenant_id: None,
            name: "test-mediator".to_string(),
            description: String::new(),
            did: did.to_string(),
            did_document: None,
            status,
            our_did: None,
            our_secrets: None,
            provided: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn a_recorded_mediator_is_valid_only_while_active_with_the_same_did() {
        let own = "did:web:m2.example.com:.well-known";
        let active = mediator(own, crate::mediators::types::MediatorStatus::Active);
        let disabled = mediator(own, crate::mediators::types::MediatorStatus::Disabled);

        assert!(super::selected_mediator_is_valid(&active, own));
        assert!(!super::selected_mediator_is_valid(&active, "did:web:attacker.example.com:.well-known"));
        assert!(!super::selected_mediator_is_valid(&disabled, own));
    }

    async fn mediator_store_with(
        root: &std::path::Path,
        mediators: &[crate::mediators::types::Mediator],
    ) -> crate::mediators::FileSystemMediatorStore {
        use crate::mediators::store::MediatorStore;
        let store = crate::mediators::FileSystemMediatorStore::new(root.join("mediators"))
            .await
            .unwrap();
        for mediator in mediators {
            store
                .create(mediator)
                .await
                .unwrap();
        }
        store
    }

    #[tokio::test]
    async fn shared_mode_recovery_needs_no_registered_inviter_mediator() {
        let root = tempfile::tempdir().unwrap();
        let empty_store = mediator_store_with(root.path(), &[]).await;
        let inviter_mediator = "did:web:m1.example.com:.well-known";

        assert!(
            super::validate_recovered_mediator(Some(&empty_store), inviter_mediator, None, inviter_mediator, "cp-1")
                .await
                .is_ok()
        );
        assert!(
            super::validate_recovered_mediator(None, inviter_mediator, None, inviter_mediator, "cp-1")
                .await
                .is_ok()
        );
    }

    #[test]
    fn a_shared_mediator_without_a_record_keeps_the_invitation_url() {
        let inviter_mediator = "did:web:127.0.0.1%3A7037";

        assert_eq!(
            super::permanent_mediator_url(
                inviter_mediator,
                None,
                inviter_mediator,
                "http://127.0.0.1:7037/mediator/v1"
            )
            .unwrap(),
            "http://127.0.0.1:7037/mediator/v1"
        );
    }

    #[test]
    fn a_stored_mediator_document_wins_over_the_invitation_url() {
        let inviter_mediator = "did:web:m1.example.com";
        let doc = serde_json::json!({ "service": [
            { "type": "DIDCommMessaging", "serviceEndpoint": [{ "uri": "http://m1.internal:7037" }] }
        ]});

        assert_eq!(
            super::permanent_mediator_url(inviter_mediator, Some(&doc), inviter_mediator, "https://m1.example.com")
                .unwrap(),
            "http://m1.internal:7037"
        );
    }

    #[test]
    fn an_acceptor_mediator_without_a_record_is_derived_from_its_did() {
        assert_eq!(
            super::permanent_mediator_url(
                "did:web:m2.example.com",
                None,
                "did:web:m1.example.com",
                "https://m1.example.com"
            )
            .unwrap(),
            "https://m2.example.com"
        );
    }

    #[tokio::test]
    async fn recovery_onto_a_different_mediator_requires_the_recorded_active_mediator() {
        let root = tempfile::tempdir().unwrap();
        let inviter_mediator = "did:web:m1.example.com:.well-known";
        let own_mediator = "did:web:m2.example.com:.well-known";
        let own = mediator(own_mediator, crate::mediators::types::MediatorStatus::Active);
        let store = mediator_store_with(root.path(), std::slice::from_ref(&own)).await;

        assert!(
            super::validate_recovered_mediator(Some(&store), own_mediator, Some(&own.id), inviter_mediator, "cp-1")
                .await
                .is_ok()
        );
        assert!(
            super::validate_recovered_mediator(None, own_mediator, Some(&own.id), inviter_mediator, "cp-1")
                .await
                .is_err()
        );
        assert!(
            super::validate_recovered_mediator(
                Some(&store),
                own_mediator,
                Some("unknown-id"),
                inviter_mediator,
                "cp-1"
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn finalize_refuses_a_selected_mediator_that_is_gone_changed_or_disabled() {
        let root = tempfile::tempdir().unwrap();
        let own_did = "did:web:m2.example.com:.well-known";
        let mut own = mediator(own_did, crate::mediators::types::MediatorStatus::Active);
        own.did_document = Some(serde_json::json!({ "id": own_did }));
        let mut disabled = mediator("did:web:m3.example.com", crate::mediators::types::MediatorStatus::Disabled);
        disabled.id = "mediator-disabled".to_string();
        let store = mediator_store_with(root.path(), &[own.clone(), disabled.clone()]).await;

        assert_eq!(
            super::selected_mediator_document(Some(&store), Some(&own.id), own_did)
                .await
                .unwrap(),
            Some(serde_json::json!({ "id": own_did }))
        );
        assert!(
            super::selected_mediator_document(Some(&store), Some("deleted-id"), own_did)
                .await
                .is_err()
        );
        assert!(
            super::selected_mediator_document(Some(&store), Some(&own.id), "did:web:other.example.com")
                .await
                .is_err()
        );
        assert!(
            super::selected_mediator_document(Some(&store), Some(&disabled.id), &disabled.did)
                .await
                .is_err()
        );
        assert!(
            super::selected_mediator_document(None, Some(&own.id), own_did)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_shared_mediator_connection_reads_no_mediator_record() {
        assert_eq!(
            super::selected_mediator_document(None, None, "did:web:m1.example.com")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn a_listener_uses_the_recorded_mediator_when_tenants_share_a_did() {
        let root = tempfile::tempdir().unwrap();
        let shared_did = "did:web:m2.example.com:.well-known";
        let mut other_tenants = mediator(shared_did, crate::mediators::types::MediatorStatus::Active);
        other_tenants.id = "mediator-tenant-b".to_string();
        other_tenants.tenant_id = Some("tenant-b".to_string());
        other_tenants.did_document = Some(serde_json::json!({ "id": shared_did, "owner": "tenant-b" }));
        let mut own = mediator(shared_did, crate::mediators::types::MediatorStatus::Active);
        own.id = "mediator-tenant-a".to_string();
        own.tenant_id = Some("tenant-a".to_string());
        own.did_document = Some(serde_json::json!({ "id": shared_did, "owner": "tenant-a" }));
        let store = mediator_store_with(root.path(), &[other_tenants, own]).await;

        let document = super::listener_mediator_document(&store, "mediator-tenant-a", shared_did, "listener").await;

        assert_eq!(document.unwrap()["owner"], "tenant-a");
    }

    #[test]
    fn the_permanent_connection_point_names_the_selected_mediator_record() {
        assert_eq!(
            super::permanent_mediator_reference(Some("mediator-tenant-a"), "did:web:m2.example.com"),
            "mediator-tenant-a"
        );
        assert_eq!(super::permanent_mediator_reference(None, "did:web:m1.example.com"), "did:web:m1.example.com");
    }

    #[tokio::test]
    async fn recovery_never_matches_a_mediator_by_did_alone() {
        let root = tempfile::tempdir().unwrap();
        let inviter_mediator = "did:web:m1.example.com:.well-known";
        let own_mediator = "did:web:m2.example.com:.well-known";
        let mut other_tenants = mediator(own_mediator, crate::mediators::types::MediatorStatus::Active);
        other_tenants.tenant_id = Some("tenant-b".to_string());
        let store = mediator_store_with(root.path(), &[other_tenants]).await;

        assert!(
            super::validate_recovered_mediator(Some(&store), own_mediator, None, inviter_mediator, "cp-1")
                .await
                .is_err()
        );
    }

    #[test]
    fn authorization_error_matches_acl_rejections() {
        assert!(is_authorization_error("HTTP 403 Forbidden"));
        assert!(is_authorization_error("401 Unauthorized"));
        assert!(is_authorization_error("DID isn't local to the mediator"));
        assert!(is_authorization_error("connection BLOCKED by mediator"));
        assert!(is_authorization_error("request was unauthorised"));
    }

    #[test]
    fn authorization_error_ignores_transport_failures() {
        assert!(!is_authorization_error("connection refused"));
        assert!(!is_authorization_error("dns resolution failed"));
        assert!(!is_authorization_error("websocket closed unexpectedly"));
        assert!(!is_authorization_error("timeout waiting for response"));
    }

    #[test]
    fn gateway_listener_index_prefers_established_oob_connection_points() {
        assert!(
            listener_index_priority(&ConnectionPointType::OobAcceptor)
                > listener_index_priority(&ConnectionPointType::System)
        );
        assert!(
            listener_index_priority(&ConnectionPointType::OobResponder)
                > listener_index_priority(&ConnectionPointType::User)
        );
        assert_eq!(
            listener_index_priority(&ConnectionPointType::OobInviter),
            listener_index_priority(&ConnectionPointType::OobAcceptor)
        );
    }

    #[test]
    fn gateway_listener_index_promotes_remaining_lower_priority_listener() {
        let listeners = [
            ("user-cp", "gateway-1", ConnectionPointType::User),
            ("other-gateway-cp", "gateway-2", ConnectionPointType::OobAcceptor),
        ];

        let preferred = preferred_gateway_listener_id(
            listeners
                .iter()
                .map(|(id, gateway_id, cp_type)| (*id, *gateway_id, cp_type)),
            "gateway-1",
        );

        assert_eq!(preferred.as_deref(), Some("user-cp"));
    }

    #[test]
    fn gateway_listener_index_picks_highest_priority_remaining_listener() {
        let listeners = [
            ("user-cp", "gateway-1", ConnectionPointType::User),
            ("oob-cp", "gateway-1", ConnectionPointType::OobAcceptor),
            ("system-cp", "gateway-1", ConnectionPointType::System),
        ];

        let preferred = preferred_gateway_listener_id(
            listeners
                .iter()
                .map(|(id, gateway_id, cp_type)| (*id, *gateway_id, cp_type)),
            "gateway-1",
        );

        assert_eq!(preferred.as_deref(), Some("oob-cp"));
    }

    #[test]
    fn gateway_listener_index_returns_none_when_gateway_has_no_listeners() {
        let listeners = HashMap::<String, (String, ConnectionPointType)>::new();

        let preferred = preferred_gateway_listener_id(
            listeners
                .iter()
                .map(|(id, (gateway_id, cp_type))| (id.as_str(), gateway_id.as_str(), cp_type)),
            "gateway-1",
        );

        assert!(preferred.is_none());
    }
}

#[cfg(test)]
mod restart_listener_tests {
    use std::time::Duration;

    use crate::gateways::test_helpers::{test_listener, test_listener_manager};

    #[tokio::test]
    async fn a_listener_another_caller_already_replaced_is_returned_without_a_restart() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir) = test_listener_manager(root.path()).await;
        manager
            .register_test_listener(test_listener("replacement").await)
            .await;

        let current = manager
            .restart_listener_if_current("cp-1", "probed", Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(current.instance_id, "replacement");
    }

    #[tokio::test]
    async fn the_listener_the_caller_probed_is_restarted() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir) = test_listener_manager(root.path()).await;
        manager
            .register_test_listener(test_listener("probed").await)
            .await;

        let result = manager
            .restart_listener_if_current("cp-1", "probed", Duration::from_secs(1))
            .await;

        assert_eq!(result.err().as_deref(), Some("Connection point 'cp-1' not found"));
    }

    #[tokio::test]
    async fn a_connection_point_whose_listener_was_stopped_is_not_restarted() {
        let root = tempfile::tempdir().unwrap();
        let (manager, _issuer_dir) = test_listener_manager(root.path()).await;

        let result = manager
            .restart_listener_if_current("cp-1", "probed", Duration::from_secs(1))
            .await;

        assert_eq!(result.err().as_deref(), Some("Connection point 'cp-1' has no running listener; not restarting it"));
    }
}

#[cfg(test)]
mod connected_event_tests {
    use std::sync::Arc;

    use super::{current_announced_record, persist_cp_runtime_status};
    use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};
    use crate::gateways::connection_points::{ConnectionPointStore, FileSystemConnectionPointStore};

    fn announced_cp() -> GatewayConnectionPoint {
        let mut cp = GatewayConnectionPoint::new(
            "gw-1".to_string(),
            "did:example:mediator".to_string(),
            "did:example:cp".to_string(),
            "CP".to_string(),
            "desc".to_string(),
            "oob-1".to_string(),
            "https://oob.example".to_string(),
            serde_json::json!({}),
            None,
            ConnectionPointType::User,
            "secret".to_string(),
        );
        cp.mediator_did = Some("did:example:mediator".to_string());
        cp
    }

    async fn store_with(
        cp: &GatewayConnectionPoint
    ) -> (tempfile::TempDir, Option<Arc<FileSystemConnectionPointStore>>) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().join("cps"))
            .await
            .unwrap();
        store
            .create(cp)
            .await
            .unwrap();
        (dir, Some(Arc::new(store)))
    }

    #[tokio::test]
    async fn a_record_deleted_while_connecting_is_not_announced() {
        let cp = announced_cp();
        let (_dir, store) = store_with(&cp).await;
        store
            .as_ref()
            .unwrap()
            .delete(&cp.id)
            .await
            .unwrap();

        assert!(
            current_announced_record(&store, &cp)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_announced_record_is_the_current_one() {
        let cp = announced_cp();
        let (_dir, store) = store_with(&cp).await;
        let mut renamed = cp.clone();
        renamed.name = "renamed".to_string();
        store
            .as_ref()
            .unwrap()
            .update(&renamed)
            .await
            .unwrap();

        let current = current_announced_record(&store, &cp)
            .await
            .unwrap();

        assert_eq!(current.name, "renamed");
    }

    #[tokio::test]
    async fn persisting_runtime_status_does_not_recreate_a_deleted_record() {
        let cp = announced_cp();
        let (_dir, store) = store_with(&cp).await;
        let runtime = crate::comm::connection_health::ConnectionRuntimeStatus::default();
        persist_cp_runtime_status(&store, &cp.id, &runtime).await;
        let live = store.as_ref().unwrap();
        assert!(
            live.get(&cp.id)
                .await
                .unwrap()
                .unwrap()
                .runtime_status
                .is_some()
        );
        live.delete(&cp.id)
            .await
            .unwrap();

        persist_cp_runtime_status(&store, &cp.id, &runtime).await;

        assert!(
            live.get(&cp.id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
