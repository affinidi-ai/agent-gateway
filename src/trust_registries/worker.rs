//! Trust Registry Background Worker
//!
//! Thin compatibility shim over the per-connection stream readers owned by the
//! [`TrustRegistryListenerManager`]. Each active connection has a single reader
//! ([`super::reader`]) that both demultiplexes query responses and drives
//! setup/approval status transitions, so this type only wires the store +
//! dashboard broadcaster into the manager and ensures readers exist. Retained so
//! existing orchestrator and handler call sites keep working.

use std::sync::Arc;

use tracing::error;

use super::TrustRegistryStore;
use super::communication::TrustRegistryListenerManager;
use super::types::{TrustRegistry, TrustRegistryConnectionStatus};
use crate::server::websocket::WsState;

pub struct TrustRegistryWorker {
    listener_manager: Arc<TrustRegistryListenerManager>,
}

impl TrustRegistryWorker {
    pub fn new(listener_manager: Arc<TrustRegistryListenerManager>) -> Self {
        Self { listener_manager }
    }

    /// Attach the store + dashboard broadcaster to the manager and ensure a
    /// reader exists for every registry that already has a live connection.
    pub async fn start_all<S: TrustRegistryStore + 'static>(
        &self,
        store: Arc<S>,
        ws_state: WsState,
    ) {
        self.listener_manager
            .set_store(store.clone() as Arc<dyn TrustRegistryStore>)
            .await;
        self.listener_manager
            .set_ws_state(ws_state)
            .await;

        let registries = match store.list_all().await {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to list trust registries for worker startup: {}", e);
                return;
            }
        };

        for tr in registries {
            if matches!(
                tr.connection_status,
                TrustRegistryConnectionStatus::AwaitingApproval
                    | TrustRegistryConnectionStatus::Connecting
                    | TrustRegistryConnectionStatus::Connected
            ) {
                self.listener_manager
                    .spawn_reader(&tr.id)
                    .await;
            }
        }
    }

    /// Ensure the reader for a single registry is running, wiring the store +
    /// broadcaster in case they were not already set.
    pub async fn start_listener<S: TrustRegistryStore + 'static>(
        &self,
        tr: &TrustRegistry,
        store: Arc<S>,
        ws_state: WsState,
    ) {
        self.listener_manager
            .set_store(store as Arc<dyn TrustRegistryStore>)
            .await;
        self.listener_manager
            .set_ws_state(ws_state)
            .await;
        self.listener_manager
            .spawn_reader(&tr.id)
            .await;
    }

    /// Stop the reader for a specific trust registry.
    pub async fn stop_listener(
        &self,
        trust_registry_id: &str,
    ) {
        self.listener_manager
            .stop_reader(trust_registry_id)
            .await;
    }
}
