//! DIDComm Message Type Definitions
//!
//! This module defines all supported message types as enums to avoid magic strings
//! and provide type safety for message routing.

use std::fmt;

/// DIDComm message types supported by the application
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    // Trust Ping Protocol (DIDComm v2)
    TrustPing,
    TrustPingResponse,

    // Routing Protocol (DIDComm v2)
    Forward,

    // Problem Reports (DIDComm v2)
    ProblemReport,

    // Basic Message Protocol (DIDComm v2)
    BasicMessage,

    // Discover Features Protocol (DIDComm v2)
    DiscoverFeaturesQuery,
    DiscoverFeaturesDisclose,

    // Out-of-Band Protocol (DIDComm v2)
    OOBInvitation,

    // Connection Protocol (Affinidi Custom)
    ConnectionSetup,
    ConnectionAccepted,
    ConnectionRejected,

    // Gateway Ping Protocol (Affinidi Custom)
    GatewayPing,
    GatewayPong,

    // Gateway Issuer Protocol (Affinidi Custom): a peer asks for the signed
    // attestation binding our gateway DID to the Connection Point DID it talks to
    GatewayIssuerRequest,
    GatewayIssuerResponse,

    // Gateway Channel Query Protocol (Affinidi Custom)
    GetSurfaces,
    GetSurfacesResponse,

    // Gateway Request Forwarding Protocol (Affinidi Custom)
    ForwardRequest,
    ForwardResponse,
    ForwardStreamFrame,
    ForwardStreamQuery,
    ForwardStreamDisclose,

    // x402 Facilitator Protocol (Affinidi Custom)
    X402VerifyRequest,
    X402VerifyResponse,
    X402SettleRequest,
    X402SettleResponse,
    X402SettlementComplete,

    // Message Pickup Protocol (DIDComm v3)
    MessagePickupStatusRequest,
    MessagePickupStatus,
    MessagePickupDeliveryRequest,
    MessagePickupDelivery,
    MessagePickupMessagesReceived,
    MessagePickupLiveDeliveryChange,

    // Present Proof Protocol (DIDComm v3)
    PresentProofRequestPresentation,
    PresentProofPresentation,

    // Issue Credential Protocol (DIDComm v3)
    IssueCredentialOffer,
    IssueCredentialRequest,
    IssueCredentialIssue,

    // AccountManagement
    AccountManagement,

    // Unknown/Unsupported message type
    Unknown(String),
}

impl MessageType {
    /// Parse a message type string into the MessageType enum
    pub fn from_str(type_str: &str) -> Self {
        match type_str {
            // Trust Ping
            "https://didcomm.org/trust-ping/2.0/ping" => Self::TrustPing,
            "https://didcomm.org/trust-ping/2.0/ping-response" => Self::TrustPingResponse,

            // Routing
            "https://didcomm.org/routing/2.0/forward" => Self::Forward,

            // Problem Reports
            "https://didcomm.org/report-problem/2.0/problem-report" => Self::ProblemReport,

            // Basic Message
            "https://didcomm.org/basicmessage/2.0/message" => Self::BasicMessage,

            // Discover Features
            "https://didcomm.org/discover-features/2.0/queries" => Self::DiscoverFeaturesQuery,
            "https://didcomm.org/discover-features/2.0/disclose" => Self::DiscoverFeaturesDisclose,

            // Out of Band
            "https://didcomm.org/out-of-band/2.0/invitation" => Self::OOBInvitation,

            // Connection Protocol
            "https://affinidi.com/atm/client-actions/connection-setup" => Self::ConnectionSetup,
            "https://affinidi.com/atm/client-actions/connection-accepted" => Self::ConnectionAccepted,
            "https://affinidi.com/atm/client-actions/connection-rejected" => Self::ConnectionRejected,

            // Gateway Ping
            "https://affinidi.com/atm/client-actions/gateway-ping" => Self::GatewayPing,
            "https://affinidi.com/atm/client-actions/gateway-pong" => Self::GatewayPong,

            // Gateway Issuer
            "https://affinidi.com/atm/client-actions/gateway-issuer-request" => Self::GatewayIssuerRequest,
            "https://affinidi.com/atm/client-actions/gateway-issuer-response" => Self::GatewayIssuerResponse,

            // Gateway Channel Query
            "https://affinidi.com/atm/client-actions/get-surfaces" => Self::GetSurfaces,
            "https://affinidi.com/atm/client-actions/get-surfaces-response" => Self::GetSurfacesResponse,

            // Gateway Request Forwarding
            "https://affinidi.com/atm/client-actions/forward-request" => Self::ForwardRequest,
            "https://affinidi.com/atm/client-actions/forward-response" => Self::ForwardResponse,
            "https://affinidi.com/atm/forward-stream/1.0/frame" => Self::ForwardStreamFrame,
            "https://affinidi.com/atm/forward-stream/1.0/capabilities-query" => Self::ForwardStreamQuery,
            "https://affinidi.com/atm/forward-stream/1.0/capabilities-disclose" => Self::ForwardStreamDisclose,

            // x402 Facilitator Protocol
            "https://affinidi.com/x402/1.0/verify-request" => Self::X402VerifyRequest,
            "https://affinidi.com/x402/1.0/verify-response" => Self::X402VerifyResponse,
            "https://affinidi.com/x402/1.0/settle-request" => Self::X402SettleRequest,
            "https://affinidi.com/x402/1.0/settle-response" => Self::X402SettleResponse,
            "https://affinidi.io/x402/1.0/settlement-complete" => Self::X402SettlementComplete,

            // Message Pickup
            "https://didcomm.org/messagepickup/3.0/status-request" => Self::MessagePickupStatusRequest,
            "https://didcomm.org/messagepickup/3.0/status" => Self::MessagePickupStatus,
            "https://didcomm.org/messagepickup/3.0/delivery-request" => Self::MessagePickupDeliveryRequest,
            "https://didcomm.org/messagepickup/3.0/delivery" => Self::MessagePickupDelivery,
            "https://didcomm.org/messagepickup/3.0/messages-received" => Self::MessagePickupMessagesReceived,
            "https://didcomm.org/messagepickup/3.0/live-delivery-change" => Self::MessagePickupLiveDeliveryChange,

            // Present Proof
            "https://didcomm.org/present-proof/3.0/request-presentation" => Self::PresentProofRequestPresentation,
            "https://didcomm.org/present-proof/3.0/presentation" => Self::PresentProofPresentation,

            // Issue Credential
            "https://didcomm.org/issue-credential/3.0/offer-credential" => Self::IssueCredentialOffer,
            "https://didcomm.org/issue-credential/3.0/request-credential" => Self::IssueCredentialRequest,
            "https://didcomm.org/issue-credential/3.0/issue-credential" => Self::IssueCredentialIssue,

            // AccountManagement
            "https://didcomm.org/mediator/1.0/account-management" => Self::AccountManagement,

            // Unknown
            _ => Self::Unknown(type_str.to_string()),
        }
    }

    /// Convert MessageType back to its string representation
    pub fn as_str(&self) -> &str {
        match self {
            // Trust Ping
            Self::TrustPing => "https://didcomm.org/trust-ping/2.0/ping",
            Self::TrustPingResponse => "https://didcomm.org/trust-ping/2.0/ping-response",

            // Routing
            Self::Forward => "https://didcomm.org/routing/2.0/forward",

            // Problem Reports
            Self::ProblemReport => "https://didcomm.org/report-problem/2.0/problem-report",

            // Basic Message
            Self::BasicMessage => "https://didcomm.org/basicmessage/2.0/message",

            // Discover Features
            Self::DiscoverFeaturesQuery => "https://didcomm.org/discover-features/2.0/queries",
            Self::DiscoverFeaturesDisclose => "https://didcomm.org/discover-features/2.0/disclose",

            // Out of Band
            Self::OOBInvitation => "https://didcomm.org/out-of-band/2.0/invitation",

            // Connection Protocol
            Self::ConnectionSetup => "https://affinidi.com/atm/client-actions/connection-setup",
            Self::ConnectionAccepted => "https://affinidi.com/atm/client-actions/connection-accepted",
            Self::ConnectionRejected => "https://affinidi.com/atm/client-actions/connection-rejected",

            // Gateway Ping
            Self::GatewayPing => "https://affinidi.com/atm/client-actions/gateway-ping",
            Self::GatewayPong => "https://affinidi.com/atm/client-actions/gateway-pong",

            // Gateway Issuer
            Self::GatewayIssuerRequest => "https://affinidi.com/atm/client-actions/gateway-issuer-request",
            Self::GatewayIssuerResponse => "https://affinidi.com/atm/client-actions/gateway-issuer-response",

            // Gateway Channel Query
            Self::GetSurfaces => "https://affinidi.com/atm/client-actions/get-surfaces",
            Self::GetSurfacesResponse => "https://affinidi.com/atm/client-actions/get-surfaces-response",
            Self::ForwardRequest => "https://affinidi.com/atm/client-actions/forward-request",
            Self::ForwardResponse => "https://affinidi.com/atm/client-actions/forward-response",
            Self::ForwardStreamFrame => "https://affinidi.com/atm/forward-stream/1.0/frame",
            Self::ForwardStreamQuery => "https://affinidi.com/atm/forward-stream/1.0/capabilities-query",
            Self::ForwardStreamDisclose => "https://affinidi.com/atm/forward-stream/1.0/capabilities-disclose",

            // x402 Facilitator Protocol
            Self::X402VerifyRequest => "https://affinidi.com/x402/1.0/verify-request",
            Self::X402VerifyResponse => "https://affinidi.com/x402/1.0/verify-response",
            Self::X402SettleRequest => "https://affinidi.com/x402/1.0/settle-request",
            Self::X402SettleResponse => "https://affinidi.com/x402/1.0/settle-response",
            Self::X402SettlementComplete => "https://affinidi.io/x402/1.0/settlement-complete",

            // Message Pickup
            Self::MessagePickupStatusRequest => "https://didcomm.org/messagepickup/3.0/status-request",
            Self::MessagePickupStatus => "https://didcomm.org/messagepickup/3.0/status",
            Self::MessagePickupDeliveryRequest => "https://didcomm.org/messagepickup/3.0/delivery-request",
            Self::MessagePickupDelivery => "https://didcomm.org/messagepickup/3.0/delivery",
            Self::MessagePickupMessagesReceived => "https://didcomm.org/messagepickup/3.0/messages-received",
            Self::MessagePickupLiveDeliveryChange => "https://didcomm.org/messagepickup/3.0/live-delivery-change",

            // Present Proof
            Self::PresentProofRequestPresentation => "https://didcomm.org/present-proof/3.0/request-presentation",
            Self::PresentProofPresentation => "https://didcomm.org/present-proof/3.0/presentation",

            // Issue Credential
            Self::IssueCredentialOffer => "https://didcomm.org/issue-credential/3.0/offer-credential",
            Self::IssueCredentialRequest => "https://didcomm.org/issue-credential/3.0/request-credential",
            Self::IssueCredentialIssue => "https://didcomm.org/issue-credential/3.0/issue-credential",

            // AccountManagement
            Self::AccountManagement => "https://didcomm.org/mediator/1.0/account-management",

            // Unknown
            Self::Unknown(s) => s,
        }
    }

    /// Get the protocol family for this message type
    pub fn protocol_family(&self) -> ProtocolFamily {
        match self {
            Self::TrustPing | Self::TrustPingResponse => ProtocolFamily::TrustPing,
            Self::Forward => ProtocolFamily::Routing,
            Self::ProblemReport => ProtocolFamily::ProblemReport,
            Self::BasicMessage => ProtocolFamily::BasicMessage,
            Self::DiscoverFeaturesQuery | Self::DiscoverFeaturesDisclose => ProtocolFamily::DiscoverFeatures,
            Self::OOBInvitation => ProtocolFamily::OutOfBand,
            Self::ConnectionSetup | Self::ConnectionAccepted | Self::ConnectionRejected => ProtocolFamily::Connection,
            Self::GatewayPing | Self::GatewayPong => ProtocolFamily::GatewayPing,
            Self::GatewayIssuerRequest | Self::GatewayIssuerResponse => ProtocolFamily::GatewayIssuer,
            Self::GetSurfaces | Self::GetSurfacesResponse => ProtocolFamily::GatewayQuery,
            Self::ForwardRequest
            | Self::ForwardResponse
            | Self::ForwardStreamFrame
            | Self::ForwardStreamQuery
            | Self::ForwardStreamDisclose => ProtocolFamily::RequestForwarding,
            Self::X402VerifyRequest
            | Self::X402VerifyResponse
            | Self::X402SettleRequest
            | Self::X402SettleResponse
            | Self::X402SettlementComplete => ProtocolFamily::X402Facilitator,
            Self::MessagePickupStatusRequest
            | Self::MessagePickupStatus
            | Self::MessagePickupDeliveryRequest
            | Self::MessagePickupDelivery
            | Self::MessagePickupMessagesReceived
            | Self::MessagePickupLiveDeliveryChange => ProtocolFamily::MessagePickup,
            Self::PresentProofRequestPresentation | Self::PresentProofPresentation => ProtocolFamily::PresentProof,
            Self::IssueCredentialOffer | Self::IssueCredentialRequest | Self::IssueCredentialIssue => {
                ProtocolFamily::IssueCredential
            }
            Self::AccountManagement => ProtocolFamily::AccountManagement,
            Self::Unknown(_) => ProtocolFamily::Unknown,
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Protocol families for organizing message types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolFamily {
    TrustPing,
    Routing,
    ProblemReport,
    BasicMessage,
    DiscoverFeatures,
    OutOfBand,
    Connection,
    GatewayPing,
    GatewayIssuer,
    GatewayQuery,
    RequestForwarding,
    X402Facilitator,
    MessagePickup,
    PresentProof,
    IssueCredential,
    AccountManagement,
    Unknown,
}

impl fmt::Display for ProtocolFamily {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        match self {
            Self::TrustPing => write!(f, "Trust Ping"),
            Self::Routing => write!(f, "Routing"),
            Self::ProblemReport => write!(f, "Problem Report"),
            Self::BasicMessage => write!(f, "Basic Message"),
            Self::DiscoverFeatures => write!(f, "Discover Features"),
            Self::OutOfBand => write!(f, "Out-of-Band"),
            Self::Connection => write!(f, "Connection"),
            Self::GatewayPing => write!(f, "Gateway Ping"),
            Self::GatewayIssuer => write!(f, "Gateway Issuer"),
            Self::GatewayQuery => write!(f, "Gateway Query"),
            Self::RequestForwarding => write!(f, "Request Forwarding"),
            Self::X402Facilitator => write!(f, "x402 Facilitator"),
            Self::MessagePickup => write!(f, "Message Pickup"),
            Self::PresentProof => write!(f, "Present Proof"),
            Self::IssueCredential => write!(f, "Issue Credential"),
            Self::AccountManagement => write!(f, "Account Management"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_issuer_types_round_trip_through_their_uris() {
        for message_type in [MessageType::GatewayIssuerRequest, MessageType::GatewayIssuerResponse] {
            assert_eq!(MessageType::from_str(message_type.as_str()), message_type);
            assert_eq!(message_type.protocol_family(), ProtocolFamily::GatewayIssuer);
        }
    }

    #[test]
    fn gateway_issuer_type_uris_are_stable() {
        assert_eq!(
            MessageType::GatewayIssuerRequest.as_str(),
            "https://affinidi.com/atm/client-actions/gateway-issuer-request"
        );
        assert_eq!(
            MessageType::GatewayIssuerResponse.as_str(),
            "https://affinidi.com/atm/client-actions/gateway-issuer-response"
        );
        assert_eq!(ProtocolFamily::GatewayIssuer.to_string(), "Gateway Issuer");
    }

    #[test]
    fn unknown_uri_stays_unknown() {
        let parsed = MessageType::from_str("https://affinidi.com/atm/client-actions/gateway-issuer");

        assert_eq!(parsed, MessageType::Unknown("https://affinidi.com/atm/client-actions/gateway-issuer".into()));
        assert_eq!(parsed.protocol_family(), ProtocolFamily::Unknown);
    }
}
