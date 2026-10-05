use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::{debug, info, warn};

use crate::identity::state::IdentityApiState;

/// Handler for receiving DIDComm messages
/// This endpoint receives encrypted DIDComm v2 messages
pub async fn didcomm_endpoint(
    State(_state): State<IdentityApiState>,
    body: Bytes,
) -> Result<Response, StatusCode> {
    info!("Received DIDComm message, size: {} bytes", body.len());

    // Try to parse as JSON first to see what we received
    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(json) => {
            debug!("DIDComm message JSON: {}", serde_json::to_string_pretty(&json).unwrap_or_default());

            // Log the message type if available
            if let Some(msg_type) = json
                .get("type")
                .and_then(|v| v.as_str())
            {
                info!("DIDComm message type: {}", msg_type);
            }

            // For now, just acknowledge receipt
            // TODO: Implement full DIDComm message processing with affinidi-messaging-sdk
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "received",
                    "message": "DIDComm message received and logged"
                })),
            )
                .into_response())
        }
        Err(e) => {
            warn!("Failed to parse DIDComm message as JSON: {}", e);
            // Might be encrypted, try to decrypt
            // TODO: Implement decryption with SDK
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "received",
                    "message": "Encrypted DIDComm message received (decryption not yet implemented)"
                })),
            )
                .into_response())
        }
    }
}

/// Handler for DIDComm WebSocket connections (optional, for bidirectional messaging)
pub async fn didcomm_ws_endpoint() -> impl IntoResponse {
    // TODO: Implement WebSocket support for DIDComm
    (StatusCode::NOT_IMPLEMENTED, "WebSocket DIDComm endpoint not yet implemented")
}
