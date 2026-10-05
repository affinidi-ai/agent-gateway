//! On-demand issuer attestation exchange with a paired Remote gateway.
//!
//! Pairings established before issuer attestations existed have no
//! `issuer_did` on their Remote gateway record. The requester sends a
//! `gateway-issuer-request` with a fresh nonce over the pairing's Connection
//! Point and expects a `gateway-issuer-response` carrying an attestation of the
//! peer's gateway DID over the Connection Point DID it answered from. The
//! network round trip lives on `ConnectionPointListenerManager`; this module
//! holds the pieces that need no transport.

use std::time::Duration;

use affinidi_messaging_didcomm::Message as DIDCommMessage;

use crate::gateways::connection_points::messages::ReceivedMessage;
use crate::gateways::issuer_attestation::IssuerAttestationError;
use crate::gateways::types::{Gateway, GatewayStatus, GatewayType};
use crate::messages::MessageType;

/// How long the requester waits for the `gateway-issuer-response`.
pub const ISSUER_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// `expires_time` window on the request envelope.
const ISSUER_REQUEST_EXPIRES_SECS: u64 = 30;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum PeerIssuerError {
    #[error("gateway {0} not found")]
    GatewayNotFound(String),
    #[error("no active listener for gateway {0}")]
    NoListener(String),
    #[error("failed to send gateway-issuer-request: {0}")]
    Send(String),
    #[error("no gateway-issuer-response within {}s", ISSUER_REQUEST_TIMEOUT.as_secs())]
    Timeout,
    #[error("issuer response came from {actual:?}, expected {expected:?}")]
    UnexpectedResponder { expected: String, actual: String },
    #[error("issuer response has unexpected message type {0:?}")]
    UnexpectedMessageType(String),
    #[error(transparent)]
    Attestation(#[from] IssuerAttestationError),
    #[error("gateway store error: {0}")]
    Store(String),
}

/// A built `gateway-issuer-request` and the nonce its answer must carry.
pub struct IssuerRequest {
    pub message: DIDCommMessage,
    pub nonce: String,
}

/// Build the request from our Connection Point DID for this pairing to the
/// peer's. The message id doubles as the thread id, so the reply (whose thread
/// id is the request id) can be correlated by the shared response waiter.
pub fn build_issuer_request(
    our_connection_point_did: &str,
    peer_connection_point_did: &str,
) -> IssuerRequest {
    let id = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
        + ISSUER_REQUEST_EXPIRES_SECS;

    let message = DIDCommMessage::build(
        id.clone(),
        MessageType::GatewayIssuerRequest.to_string(),
        serde_json::json!({ "nonce": nonce }),
    )
    .from(our_connection_point_did.to_string())
    .to(peer_connection_point_did.to_string())
    .thid(id)
    .expires_time(expires_at)
    .finalize();

    IssuerRequest { message, nonce }
}

/// Check that a reply is a `gateway-issuer-response` from the peer Connection
/// Point we asked, and return the attestation it carries (if any).
pub fn attestation_from_issuer_response<'a>(
    response: &'a ReceivedMessage,
    expected_peer_connection_point_did: &str,
) -> Result<Option<&'a str>, PeerIssuerError> {
    if response.message_type != MessageType::GatewayIssuerResponse.as_str() {
        return Err(PeerIssuerError::UnexpectedMessageType(response.message_type.clone()));
    }
    let actual = response
        .from_did
        .as_deref()
        .unwrap_or_default();
    if actual != expected_peer_connection_point_did {
        return Err(PeerIssuerError::UnexpectedResponder {
            expected: expected_peer_connection_point_did.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(response
        .message_body
        .get("issuer_attestation")
        .and_then(|v| v.as_str()))
}

/// Whether a Remote gateway record still needs the issuer exchange: only
/// active remote gateways without a stored issuer DID.
pub fn needs_issuer_reconciliation(gateway: &Gateway) -> bool {
    gateway.gateway_type == GatewayType::Remote
        && gateway.status == GatewayStatus::Active
        && gateway.issuer_did.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::messages::MessageMetadata;

    const OUR_CP: &str = "did:web:us.example:connection-points:1111";
    const PEER_CP: &str = "did:web:peer.example:connection-points:2222";

    fn reply(
        message_type: &str,
        from: Option<&str>,
        body: serde_json::Value,
    ) -> ReceivedMessage {
        ReceivedMessage::new(
            "cp-1".to_string(),
            "gw-1".to_string(),
            message_type.to_string(),
            "reply-id".to_string(),
            Some("request-id".to_string()),
            from.map(str::to_string),
            vec![OUR_CP.to_string()],
            None,
            None,
            body,
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: serde_json::Value::Null,
            },
        )
    }

    fn remote_gateway(
        status: GatewayStatus,
        issuer_did: Option<&str>,
    ) -> Gateway {
        let mut gateway = Gateway::new("peer".into(), String::new(), PEER_CP.into(), GatewayType::Remote);
        gateway.status = status;
        gateway.issuer_did = issuer_did.map(str::to_string);
        gateway
    }

    #[test]
    fn request_carries_fresh_nonce_and_uses_its_id_as_thread() {
        let first = build_issuer_request(OUR_CP, PEER_CP);
        let second = build_issuer_request(OUR_CP, PEER_CP);

        assert_eq!(first.message.typ, MessageType::GatewayIssuerRequest.as_str());
        assert_eq!(first.message.body["nonce"], first.nonce);
        assert_eq!(first.message.thid.as_deref(), Some(first.message.id.as_str()));
        assert_eq!(first.message.from.as_deref(), Some(OUR_CP));
        assert_eq!(first.message.to.as_deref(), Some(&[PEER_CP.to_string()][..]));
        assert!(
            first
                .message
                .expires_time
                .is_some()
        );
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.message.id, second.message.id);
    }

    #[test]
    fn response_from_the_asked_peer_yields_its_attestation() {
        let response = reply(
            MessageType::GatewayIssuerResponse.as_str(),
            Some(PEER_CP),
            serde_json::json!({ "issuer_attestation": "a.b.c" }),
        );

        assert_eq!(attestation_from_issuer_response(&response, PEER_CP), Ok(Some("a.b.c")));
    }

    #[test]
    fn response_without_attestation_yields_none() {
        let response = reply(MessageType::GatewayIssuerResponse.as_str(), Some(PEER_CP), serde_json::json!({}));

        assert_eq!(attestation_from_issuer_response(&response, PEER_CP), Ok(None));
    }

    #[test]
    fn response_from_another_connection_point_is_rejected() {
        let response = reply(
            MessageType::GatewayIssuerResponse.as_str(),
            Some("did:web:other.example:connection-points:3333"),
            serde_json::json!({ "issuer_attestation": "a.b.c" }),
        );

        assert_eq!(
            attestation_from_issuer_response(&response, PEER_CP),
            Err(PeerIssuerError::UnexpectedResponder {
                expected: PEER_CP.to_string(),
                actual: "did:web:other.example:connection-points:3333".to_string(),
            })
        );
    }

    #[test]
    fn response_without_sender_is_rejected() {
        let response = reply(MessageType::GatewayIssuerResponse.as_str(), None, serde_json::json!({}));

        assert_eq!(
            attestation_from_issuer_response(&response, PEER_CP),
            Err(PeerIssuerError::UnexpectedResponder {
                expected: PEER_CP.to_string(),
                actual: String::new(),
            })
        );
    }

    #[test]
    fn reply_of_another_type_is_rejected() {
        let response = reply(MessageType::ForwardResponse.as_str(), Some(PEER_CP), serde_json::json!({}));

        assert_eq!(
            attestation_from_issuer_response(&response, PEER_CP),
            Err(PeerIssuerError::UnexpectedMessageType(
                MessageType::ForwardResponse
                    .as_str()
                    .to_string()
            ))
        );
    }

    #[test]
    fn only_active_remote_gateways_without_issuer_need_reconciliation() {
        assert!(needs_issuer_reconciliation(&remote_gateway(GatewayStatus::Active, None)));
        assert!(!needs_issuer_reconciliation(&remote_gateway(GatewayStatus::Active, Some("did:web:peer.example"))));
        assert!(!needs_issuer_reconciliation(&remote_gateway(GatewayStatus::Pending, None)));
        assert!(!needs_issuer_reconciliation(&remote_gateway(GatewayStatus::AwaitingApproval, None)));

        let mut self_gateway = remote_gateway(GatewayStatus::Active, None);
        self_gateway.gateway_type = GatewayType::SelfGateway;
        assert!(!needs_issuer_reconciliation(&self_gateway));
    }

    #[test]
    fn attestation_errors_convert_into_peer_issuer_errors() {
        let err: PeerIssuerError = IssuerAttestationError::Missing.into();

        assert_eq!(err, PeerIssuerError::Attestation(IssuerAttestationError::Missing));
        assert_eq!(err.to_string(), "attestation is missing");
    }
}
