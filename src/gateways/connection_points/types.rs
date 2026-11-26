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
    /// DID of the mediator this connection point was created on. Only the
    /// management API records it, which makes it the marker for connection
    /// points the event hook announces; it also keeps hook events correct
    /// after the mediator record is removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,
    /// Set while the connection point waits for its mediator to admit its DIDs.
    /// Such a point has no listener and, on the inviter side, no invitation yet.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub awaiting_mediator_access: bool,
    /// The permanent connection point minted ahead of the pairing, so its DID can
    /// be admitted on the mediator before the pairing needs it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_permanent: Option<ReservedPermanent>,
}

/// A permanent connection point whose keys are on disk but whose record is stored
/// only when the pairing completes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReservedPermanent {
    pub cp_id: String,
    pub did: String,
    /// The mediator the permanent connection point is homed on.
    pub mediator_id: String,
    pub mediator_did: String,
    /// Set when the pairing stored the permanent connection point, which then owns the
    /// DID's events: deleting the reserving record no longer reports `creation_failed`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub consumed: bool,
}

fn default_enabled() -> bool {
    true
}

fn default_cp_type() -> ConnectionPointType {
    ConnectionPointType::User
}

impl GatewayConnectionPoint {
    /// The recorded expiry: the field, else `expires_at` in the OOB message. `None`
    /// when neither holds a readable date.
    pub fn recorded_expires_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.expires_at.or_else(|| {
            self.oob_message
                .get("expires_at")
                .and_then(|value| serde_json::from_value(value.clone()).ok())
        })
    }

    /// The deadline of a pending acceptance on this temporary connection point: the
    /// recorded expiry, else its creation time plus `pending_expiry_hours`. A recorded
    /// value that cannot be read is an error, never a fresh deadline, so an expired
    /// pairing is never renewed.
    pub fn pending_deadline(
        &self,
        pending_expiry_hours: u64,
    ) -> Result<chrono::DateTime<chrono::Utc>, String> {
        if let Some(recorded) = self.expires_at {
            return Ok(recorded);
        }
        match self
            .oob_message
            .get("expires_at")
        {
            Some(value) => serde_json::from_value(value.clone())
                .map_err(|e| format!("Temporary connection point {} has an unreadable expiry: {e}", self.id)),
            None => i64::try_from(pending_expiry_hours)
                .ok()
                .and_then(chrono::Duration::try_hours)
                .and_then(|lifetime| {
                    self.created_at
                        .checked_add_signed(lifetime)
                })
                .ok_or_else(|| format!("pending_expiry_hours {pending_expiry_hours} is out of range")),
        }
    }

    /// Whether this is the temporary connection point of the pending gateway
    /// `gateway_id`: the one whose pairing recovery rebuilds.
    pub fn is_temporary_point_of(
        &self,
        gateway_id: &str,
    ) -> bool {
        self.oob_message
            .get("pending_gateway_id")
            .and_then(serde_json::Value::as_str)
            == Some(gateway_id)
    }

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
            cp_type,
            secret,
            exposed_channels: Vec::new(),
            enabled: true,
            did_method: ConnectionPointDidMethod::default(),
            runtime_status: None,
            mediator_did: None,
            awaiting_mediator_access: false,
            reserved_permanent: None,
        }
    }

    pub fn is_announced(&self) -> bool {
        self.mediator_did.is_some()
    }

    /// The id of the invitation message the mediator serves for this connection point.
    /// An acceptor's connection-setup names it as `pthid`.
    pub fn invitation_message_id(&self) -> Option<&str> {
        self.oob_message
            .get("@id")
            .and_then(|v| v.as_str())
    }
}
impl StorableEntity for GatewayConnectionPoint {
    fn id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionPointType, GatewayConnectionPoint};

    fn temporary_point() -> GatewayConnectionPoint {
        GatewayConnectionPoint::new(
            "gw-1".to_string(),
            "did:example:mediator".to_string(),
            "did:example:cp".to_string(),
            "CP".to_string(),
            "desc".to_string(),
            "oob-1".to_string(),
            "https://oob.example".to_string(),
            serde_json::json!({}),
            None,
            ConnectionPointType::System,
            "secret".to_string(),
        )
    }

    #[test]
    fn a_recovered_pairing_keeps_the_recorded_expiry_and_is_never_renewed() {
        let recorded = chrono::Utc::now() - chrono::Duration::hours(3);

        let mut field = temporary_point();
        field.expires_at = Some(recorded);
        assert_eq!(
            field
                .pending_deadline(24)
                .unwrap(),
            recorded
        );

        let mut in_message = temporary_point();
        in_message.expires_at = None;
        in_message.oob_message = serde_json::json!({ "expires_at": recorded });
        assert_eq!(
            in_message
                .pending_deadline(24)
                .unwrap(),
            recorded
        );

        let mut unrecorded = temporary_point();
        unrecorded.expires_at = None;
        unrecorded.oob_message = serde_json::json!({});
        assert_eq!(
            unrecorded
                .pending_deadline(2)
                .unwrap(),
            unrecorded.created_at + chrono::Duration::hours(2),
            "without a recorded expiry the deadline counts from the connection point's creation"
        );

        let mut unreadable = temporary_point();
        unreadable.expires_at = None;
        unreadable.oob_message = serde_json::json!({ "expires_at": "not a date" });
        assert!(
            unreadable
                .pending_deadline(24)
                .unwrap_err()
                .contains("unreadable expiry")
        );
    }

    #[test]
    fn an_out_of_range_lifetime_is_an_error_not_a_panic() {
        let mut unrecorded = temporary_point();
        unrecorded.expires_at = None;
        assert!(
            unrecorded
                .pending_deadline(u64::MAX)
                .unwrap_err()
                .contains("out of range")
        );
    }

    #[test]
    fn the_temporary_point_is_the_one_naming_the_pending_gateway() {
        let mut point = temporary_point();
        point.oob_message = serde_json::json!({ "pending_gateway_id": "gw-1" });
        assert!(point.is_temporary_point_of("gw-1"));
        assert!(!point.is_temporary_point_of("gw-2"));
        assert!(!temporary_point().is_temporary_point_of("gw-1"));
    }
}
