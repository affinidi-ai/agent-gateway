//! Thread-keyed one-shot waiters for fabric replies delivered over a
//! Connection Point listener: `forward-response` and
//! `gateway-issuer-response` both complete the waiter registered under the
//! request message id.

use std::sync::OnceLock;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::oneshot;
use tracing::warn;

use crate::gateways::connection_points::messages::ReceivedMessage;

struct ForwardResponseWaiter {
    expected_from_did: String,
    tx: oneshot::Sender<ReceivedMessage>,
}

static FORWARD_RESPONSE_WAITERS: OnceLock<DashMap<String, ForwardResponseWaiter>> = OnceLock::new();

fn waiters() -> &'static DashMap<String, ForwardResponseWaiter> {
    FORWARD_RESPONSE_WAITERS.get_or_init(DashMap::new)
}

pub(crate) fn register_forward_response_waiter(
    thid: &str,
    expected_from_did: &str,
) -> Result<oneshot::Receiver<ReceivedMessage>, String> {
    let (tx, rx) = oneshot::channel();
    let waiter = ForwardResponseWaiter {
        expected_from_did: expected_from_did.to_string(),
        tx,
    };
    if let Some(existing) = waiters().insert(thid.to_string(), waiter) {
        waiters().insert(thid.to_string(), existing);
        Err(format!("ForwardResponse waiter already registered for thread '{thid}'"))
    } else {
        Ok(rx)
    }
}

pub(crate) fn complete_forward_response_waiter(message: &ReceivedMessage) -> bool {
    let Some(thid) = &message.didcomm_thid else {
        return false;
    };

    let completed = waiters().remove_if(thid, |_, waiter| message.from_did.as_ref() == Some(&waiter.expected_from_did));
    match completed {
        Some((_, waiter)) => waiter
            .tx
            .send(message.clone())
            .is_ok(),
        None => {
            if let Some(waiter) = waiters().get(thid) {
                warn!(
                    thid = %thid,
                    expected_from_did = %waiter.expected_from_did,
                    from_did = ?message.from_did,
                    "Ignoring fabric ForwardResponse from unexpected sender"
                );
            }
            false
        }
    }
}

pub(crate) fn remove_forward_response_waiter(thid: &str) {
    waiters().remove(thid);
}

pub(crate) async fn wait_for_forward_response(
    thid: &str,
    rx: oneshot::Receiver<ReceivedMessage>,
    timeout: Duration,
) -> Option<ReceivedMessage> {
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(message)) => Some(message),
        Ok(Err(_)) | Err(_) => {
            remove_forward_response_waiter(thid);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::gateways::connection_points::messages::MessageMetadata;
    use crate::messages::MessageType;

    const GATEWAY_DID: &str = "did:example:gateway";

    fn received_forward_response(
        thid: &str,
        from_did: Option<&str>,
    ) -> ReceivedMessage {
        ReceivedMessage::new(
            "cp-1".to_string(),
            "gateway-1".to_string(),
            MessageType::ForwardResponse
                .as_str()
                .to_string(),
            uuid::Uuid::new_v4().to_string(),
            Some(thid.to_string()),
            from_did.map(str::to_string),
            vec!["did:example:recipient".to_string()],
            None,
            None,
            json!({"status": 200, "headers": {}, "body": "ok"}),
            MessageMetadata {
                encrypted: true,
                authenticated: true,
                from_key: None,
                extra: json!({}),
            },
        )
    }

    #[tokio::test]
    async fn registered_waiter_completes_by_thread_id() {
        let thid = uuid::Uuid::new_v4().to_string();
        let rx = register_forward_response_waiter(&thid, GATEWAY_DID).unwrap();
        let message = received_forward_response(&thid, Some(GATEWAY_DID));

        assert!(complete_forward_response_waiter(&message));
        let received = wait_for_forward_response(&thid, rx, Duration::from_millis(10))
            .await
            .unwrap();

        assert_eq!(
            received
                .didcomm_thid
                .as_deref(),
            Some(thid.as_str())
        );
        assert_eq!(received.message_body["body"], "ok");
    }

    #[tokio::test]
    async fn response_from_unexpected_sender_does_not_complete_waiter() {
        let thid = uuid::Uuid::new_v4().to_string();
        let rx = register_forward_response_waiter(&thid, GATEWAY_DID).unwrap();

        assert!(!complete_forward_response_waiter(&received_forward_response(&thid, Some("did:example:attacker"))));
        assert!(!complete_forward_response_waiter(&received_forward_response(&thid, None)));

        assert!(complete_forward_response_waiter(&received_forward_response(&thid, Some(GATEWAY_DID))));
        let received = wait_for_forward_response(&thid, rx, Duration::from_millis(10))
            .await
            .unwrap();

        assert_eq!(received.from_did.as_deref(), Some(GATEWAY_DID));
    }

    #[tokio::test]
    async fn duplicate_registration_preserves_original_waiter() {
        let thid = uuid::Uuid::new_v4().to_string();
        let original_rx = register_forward_response_waiter(&thid, GATEWAY_DID).unwrap();

        assert!(register_forward_response_waiter(&thid, "did:example:other").is_err());

        let message = received_forward_response(&thid, Some(GATEWAY_DID));
        assert!(complete_forward_response_waiter(&message));
        let received = wait_for_forward_response(&thid, original_rx, Duration::from_millis(10))
            .await
            .unwrap();

        assert_eq!(
            received
                .didcomm_thid
                .as_deref(),
            Some(thid.as_str())
        );
    }

    #[tokio::test]
    async fn timeout_removes_waiter() {
        let thid = uuid::Uuid::new_v4().to_string();
        let rx = register_forward_response_waiter(&thid, GATEWAY_DID).unwrap();

        assert!(
            wait_for_forward_response(&thid, rx, Duration::from_millis(1))
                .await
                .is_none()
        );
        assert!(register_forward_response_waiter(&thid, GATEWAY_DID).is_ok());
        remove_forward_response_waiter(&thid);
    }

    #[tokio::test]
    async fn response_without_waiter_is_not_completed() {
        let thid = uuid::Uuid::new_v4().to_string();
        let message = received_forward_response(&thid, Some(GATEWAY_DID));

        assert!(!complete_forward_response_waiter(&message));
    }
}
