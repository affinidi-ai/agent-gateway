use std::sync::Arc;
use std::time::{Duration, Instant};

use affinidi_messaging_sdk::profiles::ATMProfile;
use affinidi_tdk_common::TDKSharedState;
use highway::HighwayHash;

use super::client::DIDCommClient;

#[derive(Debug, Clone)]
pub struct MediatorAuthTestResult {
    pub compatible: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MediatorTrustPingResult {
    pub success: bool,
    pub round_trip_ms: Option<u64>,
    pub error: Option<String>,
}

pub async fn cache_did_document(
    client: &DIDCommClient,
    did: &str,
    did_document: serde_json::Value,
) -> Result<(), String> {
    cache_did_document_in_tdk_state(client.tdk_state(), did, did_document).await
}

pub async fn cache_did_document_in_tdk_state(
    tdk_state: &TDKSharedState,
    did: &str,
    did_document: serde_json::Value,
) -> Result<(), String> {
    let cache = tdk_state
        .did_resolver()
        .get_cache();

    let did_hash = highway::HighwayHasher::default().hash128(did.as_bytes());

    let document: affinidi_did_common::Document =
        serde_json::from_value(did_document).map_err(|e| format!("Failed to parse DID document: {:?}", e))?;

    cache
        .insert(did_hash, document)
        .await;

    Ok(())
}

pub async fn test_authentication(
    client: &DIDCommClient,
    mediator_did: &str,
    timeout: Duration,
) -> Result<MediatorAuthTestResult, String> {
    let atm = client.atm().as_ref();
    let profile = client.profile();

    let alias = format!("auth-test-{}", uuid::Uuid::new_v4());

    let auth_future = ATMProfile::new(atm, Some(alias), profile.inner.did.to_string(), Some(mediator_did.to_string()));

    let result = match tokio::time::timeout(timeout, auth_future).await {
        Err(_) => Ok(MediatorAuthTestResult {
            compatible: false,
            error: Some("Authentication timed out".to_string()),
        }),
        Ok(Ok(_)) => Ok(MediatorAuthTestResult { compatible: true, error: None }),
        Ok(Err(e)) => {
            let error_msg = format!("{:?}", e);
            let mapped_error = if error_msg.contains("404") || error_msg.contains("Not Found") {
                "Authentication endpoint not found".to_string()
            } else if error_msg.contains("auth") || error_msg.contains("Auth") {
                format!("Authentication failed: {}", error_msg)
            } else {
                format!("Failed to authenticate with mediator: {}", error_msg)
            };

            Ok(MediatorAuthTestResult {
                compatible: false,
                error: Some(mapped_error),
            })
        }
    };

    if let Err(e) = profile.stop_websocket().await {
        tracing::warn!("Failed to stop websocket for did {}: {:?}", profile.inner.did, e);
    }

    result
}

pub async fn trust_ping(
    client: &DIDCommClient,
    mediator_did: &str,
    timeout: Duration,
) -> Result<MediatorTrustPingResult, String> {
    let atm = client.atm().as_ref();
    let profile = client.profile();

    let ping_future = async {
        let session_profile = ATMProfile::new(
            atm,
            Some(format!("trust-ping-{}", uuid::Uuid::new_v4())),
            profile.inner.did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await
        .map_err(|e| format!("Failed to create mediator profile for trust ping: {:?}", e))?;
        let session_profile = Arc::new(session_profile);

        atm.profile_enable_websocket(&session_profile)
            .await
            .map_err(|e| format!("Failed to enable mediator websocket: {:?}", e))?;

        let start = Instant::now();

        let ping_result = atm
            .trust_ping()
            .send_ping(&session_profile, mediator_did, true, true, false)
            .await
            .map_err(|e| format!("Failed to send trust ping: {:?}", e))?;

        let message_id = ping_result.message_id;
        let response = atm
            .message_pickup()
            .live_stream_get(&session_profile, &message_id, timeout, true)
            .await;

        let elapsed = start.elapsed().as_millis() as u64;
        if let Err(e) = session_profile
            .stop_websocket()
            .await
        {
            tracing::warn!("Failed to stop websocket for did {}: {:?}", mediator_did, e);
        }

        match response {
            Ok(Some(_)) => Ok(MediatorTrustPingResult {
                success: true,
                round_trip_ms: Some(elapsed),
                error: None,
            }),
            Ok(None) => Ok(MediatorTrustPingResult {
                success: false,
                round_trip_ms: None,
                error: Some("No pong response received".to_string()),
            }),
            Err(e) => Ok(MediatorTrustPingResult {
                success: false,
                round_trip_ms: None,
                error: Some(format!("Trust ping error: {:?}", e)),
            }),
        }
    };

    match tokio::time::timeout(timeout, ping_future).await {
        Err(_) => Ok(MediatorTrustPingResult {
            success: false,
            round_trip_ms: None,
            error: Some("Trust ping timed out".to_string()),
        }),
        Ok(result) => result,
    }
}
