//! Pending OOB connection state management

use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, error};

/// State for a pending OOB connection
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingOOBConnection {
    /// Unique ID for this pending connection
    pub id: String,

    /// Our temporary/ephemeral DID used for the handshake
    pub our_temporary_did: String,

    /// Our secure/permanent DID for the established connection
    pub our_secure_did: String,

    /// Their temporary/ephemeral DID (from the invitation or connection-setup)
    pub their_temporary_did: String,

    /// Their secure DID (set when we receive it)
    pub their_secure_did: Option<String>,

    /// Their gateway DID, verified from the issuer attestation in the handshake
    #[serde(default)]
    pub their_issuer_did: Option<String>,

    /// The mediator DID we're using
    pub mediator_did: String,

    /// Which connection point we're using
    pub connection_point_id: String,

    /// Invitation message ID (for thread tracking)
    pub invitation_id: String,

    /// Role in the connection flow
    pub role: ConnectionRole,

    /// Current state of the connection
    pub state: ConnectionState,

    /// When this pending connection was created
    pub created_at: DateTime<Utc>,

    /// When this pending connection expires
    pub expires_at: DateTime<Utc>,

    #[serde(default)]
    pub secure_cp_id: Option<String>,

    #[serde(default)]
    pub temporary_cp_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConnectionRole {
    /// We created the OOB invitation (inviter/responder)
    Inviter,
    /// We're accepting an OOB invitation (acceptor/initiator)
    Acceptor,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConnectionState {
    /// Waiting for connection-setup (inviter) or connection-accepted (acceptor)
    WaitingForResponse,
    /// Connection established, ready to create gateway
    ReadyToFinalize,
    /// Connection failed
    Failed(String),
}

/// Simpler pending connection for approval workflow
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingConnection {
    /// Gateway ID this connection belongs to
    pub gateway_id: String,

    /// Invitation/connection point ID
    pub invitation_id: String,

    /// Our temporary DID
    pub our_temporary_did: String,

    /// Our secure DID for the connection
    pub our_secure_did: String,

    /// Their temporary DID
    pub their_temporary_did: String,

    /// Their secure DID (from connection-setup)
    pub their_secure_did: Option<String>,

    /// Their gateway DID, verified from the issuer attestation in connection-setup
    #[serde(default)]
    pub their_issuer_did: Option<String>,

    /// Current state
    pub state: PendingConnectionState,

    /// When created
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PendingConnectionState {
    /// Waiting for administrator approval
    AwaitingApproval,
    /// Waiting for response from remote
    WaitingForResponse,
    /// Ready to finalize
    ReadyToFinalize,
    /// Failed
    Failed(String),
}

impl StorableEntity for PendingOOBConnection {
    fn id(&self) -> &str {
        &self.id
    }
}

impl StorableEntity for PendingConnection {
    fn id(&self) -> &str {
        &self.gateway_id
    }
}

/// Store for pending OOB connections with filesystem persistence
pub struct PendingConnectionStore {
    connections: Box<dyn StorageBackend<PendingOOBConnection>>,
    approval_connections: Box<dyn StorageBackend<PendingConnection>>,
}

impl PendingConnectionStore {
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let connections = cached_storage(storage_dir.join("oob"), "pending_oob_connection").await?;
        let approval_connections = cached_storage(storage_dir.join("approval"), "pending_approval_connection").await?;

        Ok(Self {
            connections,
            approval_connections,
        })
    }

    /// Store a pending connection for approval
    pub async fn store_approval(
        &self,
        connection: &PendingConnection,
    ) -> Result<(), String> {
        self.approval_connections
            .save(connection)
            .await
            .map_err(|e| format!("Failed to store approval connection: {}", e))
    }

    /// Get pending connection for approval by gateway ID
    pub async fn get_approval_by_gateway_id(
        &self,
        gateway_id: &str,
    ) -> Option<PendingConnection> {
        self.approval_connections
            .get(gateway_id)
            .await
            .ok()
            .flatten()
    }

    /// Remove pending approval connection
    pub async fn remove_approval(
        &self,
        gateway_id: &str,
    ) -> Option<PendingConnection> {
        let existing = self
            .approval_connections
            .get(gateway_id)
            .await
            .ok()
            .flatten();
        if existing.is_some()
            && let Err(e) = self
                .approval_connections
                .delete(gateway_id)
                .await
        {
            debug!("Failed to remove pending approval connection: {}", e);
        }
        existing
    }

    /// Store a pending connection
    pub async fn store(
        &self,
        connection: PendingOOBConnection,
    ) {
        if let Err(e) = self
            .connections
            .save(&connection)
            .await
        {
            error!("Failed to store OOB connection: {}", e);
        }
    }

    /// Get a pending connection by ID
    #[allow(dead_code)]
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<PendingOOBConnection> {
        self.connections
            .get(id)
            .await
            .ok()
            .flatten()
    }

    /// Get a pending connection by temporary DID
    pub async fn get_by_temporary_did(
        &self,
        did: &str,
    ) -> Option<PendingOOBConnection> {
        let cache = self
            .connections
            .hash_map()
            .await
            .unwrap_or_default();
        cache
            .values()
            .find(|conn| conn.our_temporary_did == did || conn.their_temporary_did == did)
            .cloned()
    }

    /// Get a pending connection by invitation ID
    #[allow(dead_code)]
    pub async fn get_by_invitation_id(
        &self,
        invitation_id: &str,
    ) -> Option<PendingOOBConnection> {
        let cache = self
            .connections
            .hash_map()
            .await
            .unwrap_or_default();
        cache
            .values()
            .find(|conn| conn.invitation_id == invitation_id)
            .cloned()
    }

    pub async fn get_by_temporary_cp_id(
        &self,
        temporary_cp_id: &str,
    ) -> Option<PendingOOBConnection> {
        let cache = self
            .connections
            .hash_map()
            .await
            .unwrap_or_default();
        cache
            .values()
            .find(|conn| {
                conn.temporary_cp_id
                    .as_deref()
                    == Some(temporary_cp_id)
            })
            .cloned()
    }

    /// Update a pending connection
    pub async fn update(
        &self,
        connection: PendingOOBConnection,
    ) {
        if let Err(e) = self
            .connections
            .save(&connection)
            .await
        {
            error!("Failed to update OOB connection: {}", e);
        }
    }

    /// Remove a pending connection
    pub async fn remove(
        &self,
        id: &str,
    ) -> Option<PendingOOBConnection> {
        let existing = self
            .connections
            .get(id)
            .await
            .ok()
            .flatten();
        if existing.is_some()
            && let Err(e) = self
                .connections
                .delete(id)
                .await
        {
            debug!("Failed to remove OOB connection: {}", e);
        }
        existing
    }

    /// List all pending connections
    #[allow(dead_code)]
    pub async fn list_all(&self) -> Vec<PendingOOBConnection> {
        self.connections
            .list_all()
            .await
            .unwrap_or_default()
    }

    /// Clean up expired connections
    #[allow(dead_code)]
    pub async fn cleanup_expired(&self) {
        let now = Utc::now();

        // Collect expired IDs
        let expired_ids: Vec<String> = {
            let cache = self
                .connections
                .hash_map()
                .await
                .unwrap_or_default();
            cache
                .iter()
                .filter(|(_, conn)| conn.expires_at <= now)
                .map(|(id, _)| id.clone())
                .collect()
        };

        // Remove expired connections
        for id in expired_ids {
            if let Err(e) = self
                .connections
                .delete(&id)
                .await
            {
                debug!("Failed to remove expired OOB connection: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_oob_connection_json_without_their_issuer_did_deserialises() {
        let json = serde_json::json!({
            "id": "inv-1",
            "our_temporary_did": "did:web:us.example:connection-points:tmp",
            "our_secure_did": "did:web:us.example:connection-points:1111",
            "their_temporary_did": "did:web:them.example:connection-points:tmp",
            "their_secure_did": null,
            "mediator_did": "did:web:mediator.example",
            "connection_point_id": "",
            "invitation_id": "inv-1",
            "role": "Acceptor",
            "state": "WaitingForResponse",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T01:00:00Z"
        });

        let connection: PendingOOBConnection = serde_json::from_value(json).unwrap();

        assert_eq!(connection.their_issuer_did, None);
        assert_eq!(connection.role, ConnectionRole::Acceptor);
    }

    #[test]
    fn pending_connection_json_without_their_issuer_did_deserialises() {
        let json = serde_json::json!({
            "gateway_id": "gw-1",
            "invitation_id": "cp-1",
            "our_temporary_did": "did:web:us.example:connection-points:tmp",
            "our_secure_did": "did:web:us.example:connection-points:1111",
            "their_temporary_did": "did:web:them.example:connection-points:tmp",
            "their_secure_did": "did:web:them.example:connection-points:2222",
            "state": "AwaitingApproval",
            "created_at": "2026-01-01T00:00:00Z"
        });

        let connection: PendingConnection = serde_json::from_value(json).unwrap();

        assert_eq!(connection.their_issuer_did, None);
        assert_eq!(connection.state, PendingConnectionState::AwaitingApproval);
    }

    #[test]
    fn pending_connection_their_issuer_did_round_trips() {
        let connection = PendingConnection {
            gateway_id: "gw-1".to_string(),
            invitation_id: "cp-1".to_string(),
            our_temporary_did: "did:web:us.example:connection-points:tmp".to_string(),
            our_secure_did: "did:web:us.example:connection-points:1111".to_string(),
            their_temporary_did: "did:web:them.example:connection-points:tmp".to_string(),
            their_secure_did: Some("did:web:them.example:connection-points:2222".to_string()),
            their_issuer_did: Some("did:web:them.example".to_string()),
            state: PendingConnectionState::AwaitingApproval,
            created_at: Utc::now(),
        };

        let restored: PendingConnection = serde_json::from_value(serde_json::to_value(&connection).unwrap()).unwrap();

        assert_eq!(restored.their_issuer_did, Some("did:web:them.example".to_string()));
    }
}
