use affinidi_messaging_didcomm::Message as DIDCommMessage;
use tracing::debug;

use super::client::DIDCommClient;

/// Optional cache tuning for the ATM inbound message buffer.
///
/// When omitted, the SDK defaults apply (100 messages / 10 MB).
/// Connection points under load should set higher values to avoid
/// mediator backpressure on the WebSocket reader.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub inbound_cache_count: u32,
    pub inbound_cache_bytes: u64,
}

/// Send a response message correlated to an original message via `thid`.
///
/// Builds a DIDComm message with the given type and body, sets the thread ID
/// to the original message's ID, then packs encrypted and sends via ATM.
pub async fn send_response_message(
    client: &DIDCommClient,
    our_did: &str,
    recipient_did: &str,
    thread_id: &str,
    response_type: &str,
    response_body: serde_json::Value,
) -> Result<(), String> {
    let response_msg =
        DIDCommMessage::build(uuid::Uuid::new_v4().to_string(), response_type.to_string(), response_body)
            .from(our_did.to_string())
            .to(recipient_did.to_string())
            .thid(thread_id.to_string())
            .finalize();

    debug!("Response message created: {:?}", response_msg);

    client
        .pack_and_send_message(&response_msg, recipient_did, our_did)
        .await?;

    Ok(())
}

/// Send a fire-and-forget notification message (no thread correlation).
///
/// Used for settlement-complete, status updates, and other one-way messages
/// where no response is expected.
pub async fn send_notification_message(
    client: &DIDCommClient,
    our_did: &str,
    recipient_did: &str,
    message_type: &str,
    body: serde_json::Value,
) -> Result<(), String> {
    let message = DIDCommMessage::build(uuid::Uuid::new_v4().to_string(), message_type.to_string(), body)
        .from(our_did.to_string())
        .to(recipient_did.to_string())
        .finalize();

    client
        .pack_and_send_message(&message, recipient_did, our_did)
        .await?;

    Ok(())
}

/// Send a `connection-accepted` OOB protocol message.
///
/// The `body` should contain the `channel_did` field that the acceptor
/// needs to finalize the gateway connection, and `thid` is the thread id the
/// body's issuer attestation was bound to.
pub async fn send_connection_accepted(
    client: &DIDCommClient,
    our_did: &str,
    acceptor_did: &str,
    body: serde_json::Value,
    thid: &str,
) -> Result<(), String> {
    use crate::messages::MessageType;

    let message =
        DIDCommMessage::build(uuid::Uuid::new_v4().to_string(), MessageType::ConnectionAccepted.to_string(), body)
            .from(our_did.to_string())
            .to(acceptor_did.to_string())
            .thid(thid.to_string())
            .finalize();

    client
        .pack_and_send_message(&message, acceptor_did, our_did)
        .await?;

    Ok(())
}

/// Send a `connection-rejected` OOB protocol message.
///
/// Sends a rejection with the given reason string to the acceptor.
pub async fn send_connection_rejected(
    client: &DIDCommClient,
    our_did: &str,
    acceptor_did: &str,
    reason: &str,
) -> Result<(), String> {
    use crate::messages::MessageType;

    let message = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::ConnectionRejected.to_string(),
        serde_json::json!({ "reason": reason }),
    )
    .from(our_did.to_string())
    .to(acceptor_did.to_string())
    .finalize();

    client
        .pack_and_send_message(&message, acceptor_did, our_did)
        .await?;

    Ok(())
}
