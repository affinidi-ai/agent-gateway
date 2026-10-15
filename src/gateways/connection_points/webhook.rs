//! Raises `connection_point.message_received` for each message a connection point receives.

use std::collections::HashMap;

use super::messages::ReceivedMessage;
use super::types::GatewayConnectionPoint;
use crate::integrations::delivery::dispatch::dispatch;

const MESSAGE_RECEIVED: &str = "connection_point.message_received";

#[derive(Clone)]
pub struct WebhookClient {}

impl WebhookClient {
    pub fn new() -> Self {
        Self {}
    }

    /// Delivers the message to every integration whose event set holds
    /// `connection_point.message_received`, in the background.
    pub async fn trigger_integration(
        &self,
        connection_point: &GatewayConnectionPoint,
        message: &ReceivedMessage,
    ) -> Result<(), String> {
        dispatch(MESSAGE_RECEIVED, message_values(connection_point, message));
        Ok(())
    }
}

impl Default for WebhookClient {
    fn default() -> Self {
        Self::new()
    }
}

/// The connection point, the message and when it was received.
fn message_values(
    connection_point: &GatewayConnectionPoint,
    message: &ReceivedMessage,
) -> HashMap<String, String> {
    let now = chrono::Utc::now();
    HashMap::from([
        ("CP_ID".to_string(), connection_point.id.clone()),
        ("CP_NAME".to_string(), connection_point.name.clone()),
        (
            "CP_DESCRIPTION".to_string(),
            connection_point
                .description
                .clone(),
        ),
        (
            "GATEWAY_ID".to_string(),
            connection_point
                .gateway_id
                .clone(),
        ),
        (
            "GATEWAY".to_string(),
            connection_point
                .gateway_id
                .clone(),
        ),
        (
            "MEDIATOR_ID".to_string(),
            connection_point
                .mediator_id
                .clone(),
        ),
        ("MESSAGE_ID".to_string(), message.id.clone()),
        ("MESSAGE_TYPE".to_string(), message.message_type.clone()),
        (
            "FROM_DID".to_string(),
            message
                .from_did
                .clone()
                .unwrap_or_default(),
        ),
        (
            "MESSAGE_BODY".to_string(),
            message
                .message_body
                .to_string(),
        ),
        (
            "RECEIVED_AT".to_string(),
            message
                .received_at
                .to_rfc3339(),
        ),
        ("TIMESTAMP".to_string(), now.to_rfc3339()),
        (
            "DATE".to_string(),
            now.format("%Y-%m-%d")
                .to_string(),
        ),
        (
            "TIME".to_string(),
            now.format("%H:%M:%S")
                .to_string(),
        ),
        (
            "DATETIME".to_string(),
            now.format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::connection_points::messages::MessageMetadata;
    use crate::gateways::connection_points::types::ConnectionPointType;
    use serde_json::json;

    fn connection_point() -> GatewayConnectionPoint {
        GatewayConnectionPoint::new(
            "gw-1".to_string(),
            "mediator-1".to_string(),
            "did:peer:cp".to_string(),
            "Orders".to_string(),
            "Order intake".to_string(),
            "oob-1".to_string(),
            "https://example.com/oob".to_string(),
            json!({}),
            None,
            ConnectionPointType::User,
            String::new(),
        )
    }

    fn message() -> ReceivedMessage {
        ReceivedMessage::new(
            "cp-1".to_string(),
            "gw-1".to_string(),
            "https://didcomm.org/basicmessage/2.0/message".to_string(),
            "didcomm-1".to_string(),
            None,
            Some("did:peer:sender".to_string()),
            Vec::new(),
            None,
            None,
            json!({"content": "hello"}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: json!({}),
            },
        )
    }

    #[test]
    fn a_received_message_names_its_connection_point_sender_and_body() {
        let connection_point = connection_point();
        let message = message();

        let values = message_values(&connection_point, &message);

        assert_eq!(values["CP_ID"], connection_point.id);
        assert_eq!(values["CP_NAME"], "Orders");
        assert_eq!(values["CP_DESCRIPTION"], "Order intake");
        assert_eq!(values["GATEWAY_ID"], "gw-1");
        assert_eq!(values["GATEWAY"], "gw-1");
        assert_eq!(values["MEDIATOR_ID"], "mediator-1");
        assert_eq!(values["MESSAGE_ID"], message.id);
        assert_eq!(values["MESSAGE_TYPE"], "https://didcomm.org/basicmessage/2.0/message");
        assert_eq!(values["FROM_DID"], "did:peer:sender");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&values["MESSAGE_BODY"]).expect("json"),
            json!({"content": "hello"})
        );
        assert_eq!(
            values["RECEIVED_AT"],
            message
                .received_at
                .to_rfc3339()
        );
        for name in ["TIMESTAMP", "DATE", "TIME", "DATETIME"] {
            assert!(!values[name].is_empty(), "{name}");
        }
    }

    #[test]
    fn an_anonymous_sender_leaves_the_sender_empty() {
        let mut anonymous = message();
        anonymous.from_did = None;

        let values = message_values(&connection_point(), &anonymous);

        assert_eq!(values["FROM_DID"], "");
    }
}
