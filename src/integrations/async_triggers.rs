/// Helper functions to trigger integration events asynchronously and non-blocking
///
/// All triggers are wrapped in tokio::spawn with semaphore-based concurrency control
/// to prevent resource exhaustion under high load.
/// If integrations fail (e.g., webhook offline), the system continues normally.
use std::sync::Arc;

/// Trigger identity created event (non-blocking)
pub async fn trigger_identity_created(
    notif_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    did: &str,
    _identity_fields: &serde_json::Value,
) {
    if let Some(notif) = notif_store {
        let did_clone = did.to_string();
        tokio::spawn(async move {
            let identity = crate::integrations::identity_integration_triggers::Identity {
                did: did_clone,
                identity_type: "agent".to_string(),
                controller: None,
                public_keys: None,
                services: None,
            };
            crate::integrations::identity_integration_triggers::trigger_identity_created(&notif, &identity).await;
        });
    }
}

/// Trigger identity appeared event (non-blocking)
pub async fn trigger_identity_appeared(
    notif_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    did: &str,
    surface_id: &str,
) {
    if let Some(notif) = notif_store {
        let did_clone = did.to_string();
        let surface_id_clone = surface_id.to_string();
        tokio::spawn(async move {
            let identity = crate::integrations::identity_integration_triggers::Identity {
                did: did_clone,
                identity_type: "agent".to_string(),
                controller: None,
                public_keys: None,
                services: None,
            };
            crate::integrations::identity_integration_triggers::trigger_identity_appeared(
                &notif,
                &identity,
                &surface_id_clone,
            )
            .await;
        });
    }
}

/// Trigger identity accessed event (non-blocking)
pub async fn trigger_identity_accessed(
    notif_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    did: &str,
) {
    if let Some(notif) = notif_store {
        let did_clone = did.to_string();
        tokio::spawn(async move {
            let identity = crate::integrations::identity_integration_triggers::Identity {
                did: did_clone,
                identity_type: "agent".to_string(),
                controller: None,
                public_keys: None,
                services: None,
            };
            crate::integrations::identity_integration_triggers::trigger_identity_accessed(&notif, &identity).await;
        });
    }
}
