use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

/// DID method to use when generating connection point identities.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionPointDidMethod {
    #[default]
    Web,
    #[cfg(feature = "didwebvh")]
    Webvh,
    Peer,
}

/// Integration configuration for a single integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationIntegration {
    /// ID of the integration to use
    pub integration_id: String,

    /// Template variable values for this integration
    /// Maps variable names (without $ prefix) to their runtime values
    /// Example: {"RECIPIENT": "user@example.com", "TIMESTAMP": "2024-01-15T10:30:00Z"}
    #[serde(default)]
    pub variables: serde_json::Value,
}

/// Type of connection point
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionPointType {
    /// Created by user via UX
    User,
    /// Created automatically by system during gateway connection (inviter side)
    /// This is the permanent connection point after OOB handshake completes
    OobInviter,
    /// Created automatically by system for receiving from OOB acceptor (inviter side)
    /// This is auto-created when initiating an OOB connection
    OobResponder,
    /// Created automatically by system when accepting an OOB invitation (acceptor side)
    /// This is the listener endpoint for receiving messages from the inviter
    OobAcceptor,
    /// Legacy system type (for backward compatibility)
    #[serde(alias = "system")]
    System,
}

/// Represents a gateway connection point (Out-of-Band invitation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConnectionPoint {
    /// Unique identifier for this connection point
    pub id: String,

    /// ID of the gateway this connection point belongs to
    pub gateway_id: String,

    /// ID of the mediator used for this OOB invitation
    pub mediator_id: String,

    /// Unique DID for this connection point (NOT the gateway DID)
    /// Each connection point gets its own DID to avoid duplicate WebSocket connections
    pub connection_point_did: String,

    /// Name/label for this connection point
    pub name: String,

    /// Description of the connection point purpose
    pub description: String,

    /// The OOB ID returned by the mediator
    pub oob_id: String,

    /// The Out-of-Band (OOB) invitation URL
    pub oob_url: String,

    /// The raw OOB invitation message (JSON) - ENCRYPTED
    // Filesystem is currently the only storage backend and encrypts the whole file at rest.
    // Per-field encryption may be enabled when another storage backend is added.
    pub oob_message: serde_json::Value,

    /// Number of times this invitation has been used
    pub use_count: u32,

    /// Optional expiration date for the invitation
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Timestamp when this connection point was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when this connection point was last used
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Optional integration ID to reference a configured integration (deprecated - use integrations array instead)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration_id: Option<String>,

    /// Template variable values for integration configuration (deprecated - use integrations array instead)
    /// Maps variable names (without $ prefix) to their runtime values
    /// Example: {"RECIPIENT": "user@example.com", "TIMESTAMP": "2024-01-15T10:30:00Z"}
    #[serde(default)]
    pub integration_variables: serde_json::Value,

    /// List of integrations (email, Slack, etc.)
    /// Supports multiple integrations per connection point
    #[serde(default)]
    pub integrations: Vec<IntegrationIntegration>,

    /// Type of connection point (User or System)
    #[serde(default = "default_cp_type")]
    pub cp_type: ConnectionPointType,

    /// Secret required for accepting the OOB invitation - ENCRYPTED
    /// Only acceptors who know this secret can successfully connect
    // Filesystem is currently the only storage backend and encrypts the whole file at rest.
    // Per-field encryption may be enabled when another storage backend is added.
    #[serde(default)]
    pub secret: String,

    /// List of channel config IDs that should be exposed when queried via this connection point
    /// If empty, all active channels are returned (default behavior)
    #[serde(default)]
    pub exposed_channels: Vec<String>,

    /// Whether this connection point is enabled
    /// Disabled connection points won't start WebSocket listeners
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// DID method used for this connection point's identity
    #[serde(default)]
    pub did_method: ConnectionPointDidMethod,

    /// Runtime health + diagnostics for this connection point's DIDComm link
    /// (proposal section B). Written by the listener/reconnect scheduler and
    /// surfaced by the API as `runtime_status`. Absent until the listener has
    /// recorded a state; omitted from the wire when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_status: Option<crate::comm::connection_health::ConnectionRuntimeStatus>,
}

fn default_enabled() -> bool {
    true
}

fn default_cp_type() -> ConnectionPointType {
    ConnectionPointType::User
}

impl GatewayConnectionPoint {
    pub fn new(
        gateway_id: String,
        mediator_id: String,
        connection_point_did: String,
        name: String,
        description: String,
        oob_id: String,
        oob_url: String,
        oob_message: serde_json::Value,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        cp_type: ConnectionPointType,
        secret: String,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            gateway_id,
            mediator_id,
            connection_point_did,
            name,
            description,
            oob_id,
            oob_url,
            oob_message,
            use_count: 0,
            expires_at,
            created_at: now,
            last_used_at: None,
            integration_id: None,
            integration_variables: serde_json::json!({}),
            integrations: Vec::new(),
            cp_type,
            secret,
            exposed_channels: Vec::new(),
            enabled: true,
            did_method: ConnectionPointDidMethod::default(),
            runtime_status: None,
        }
    }
}
impl StorableEntity for GatewayConnectionPoint {
    fn id(&self) -> &str {
        &self.id
    }
}
