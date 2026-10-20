use serde::{Deserialize, Serialize};

use crate::gateways::connection_points::types::GatewayConnectionPoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    #[serde(rename = "connection_point.creation_started")]
    CreationStarted,
    #[serde(rename = "connection_point.created")]
    Created,
    #[serde(rename = "connection_point.creation_failed")]
    CreationFailed,
    #[serde(rename = "connection_point.connected")]
    Connected,
    #[serde(rename = "connection_point.deleted")]
    Deleted,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::CreationStarted => "connection_point.creation_started",
            EventKind::Created => "connection_point.created",
            EventKind::CreationFailed => "connection_point.creation_failed",
            EventKind::Connected => "connection_point.connected",
            EventKind::Deleted => "connection_point.deleted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionPointPayload {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub gateway_id: String,
    pub mediator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,
    pub did: String,
    pub did_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

impl ConnectionPointPayload {
    pub fn minted(
        id: &str,
        name: &str,
        description: &str,
        gateway_id: &str,
        mediator_id: &str,
        mediator_did: &str,
        did: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: Some(description.to_string()).filter(|text| !text.is_empty()),
            gateway_id: gateway_id.to_string(),
            mediator_id: mediator_id.to_string(),
            mediator_did: Some(mediator_did.to_string()),
            did: did.to_string(),
            did_method: did_method(did),
            created_at: None,
        }
    }

    /// `mediator_did` is the DID the Connection Point's listener uses; a stored
    /// record that predates it falls back to its recorded value.
    pub fn from_record(
        record: &GatewayConnectionPoint,
        mediator_did: Option<&str>,
    ) -> Self {
        Self {
            id: record.id.clone(),
            name: record.name.clone(),
            description: Some(record.description.clone()).filter(|text| !text.is_empty()),
            gateway_id: record.gateway_id.clone(),
            mediator_id: record.mediator_id.clone(),
            mediator_did: mediator_did
                .map(str::to_string)
                .or_else(|| record.mediator_did.clone()),
            did: record
                .connection_point_did
                .clone(),
            did_method: did_method(&record.connection_point_did),
            created_at: Some(record.created_at.to_rfc3339()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookEvent {
    pub event: EventKind,
    pub event_id: String,
    pub sequence: u64,
    pub timestamp: String,
    pub connection_point: ConnectionPointPayload,
}

pub fn did_method(did: &str) -> String {
    did.split(':')
        .nth(1)
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_method_handles_short_input() {
        assert_eq!(did_method("did:web:example.com"), "web");
        assert_eq!(did_method("not-a-did"), "");
    }

    #[test]
    fn event_kinds_serialize_to_their_wire_names() {
        for kind in [
            EventKind::CreationStarted,
            EventKind::Created,
            EventKind::CreationFailed,
            EventKind::Connected,
            EventKind::Deleted,
        ] {
            assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str());
        }
    }
}
