use affinidi_messaging_didcomm::Message as DIDCommMessage;

use super::client::DIDCommClient;

/// Result of a demultiplexed response message delivered by the stream reader.
#[derive(Debug, Clone)]
pub struct PollResult {
    pub msg_type: String,
    pub body: serde_json::Value,
}

/// Pack a DIDComm message and forward it via the mediator.
pub async fn pack_and_forward(
    client: &DIDCommClient,
    message: &DIDCommMessage,
    from_did: &str,
    to_did: &str,
    mediator_did: &str,
) -> Result<(), String> {
    let atm = client.atm();
    let profile = client.profile();

    let packed = atm
        .pack_encrypted(message, to_did, Some(from_did), Some(from_did))
        .await
        .map_err(|e| format!("Failed to pack message: {:?}", e))?;

    atm.forward_and_send_message(profile, false, &packed.0, Some(&message.id), mediator_did, to_did, None, None, false)
        .await
        .map_err(|e| format!("Failed to forward message: {:?}", e))?;

    Ok(())
}
