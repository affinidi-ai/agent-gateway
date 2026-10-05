use super::background_tasks::spawn_background_task;
/// Helper functions to trigger integration events asynchronously and non-blocking
///
/// All triggers are wrapped in tokio::spawn with semaphore-based concurrency control
/// to prevent resource exhaustion under high load.
/// If integrations fail (e.g., webhook offline), the system continues normally.
use std::sync::Arc;

/// Trigger connection point created event (non-blocking)
pub fn trigger_connection_point_created_async(
    notif_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    connection_point: &crate::gateways::connection_points::types::GatewayConnectionPoint,
) {
    if let Some(notif) = notif_store {
        let cp_json = serde_json::to_value(connection_point).ok();
        if let Some(cp_value) = cp_json {
            spawn_background_task("connection_point.created", async move {
                let cp_obj = crate::integrations::connection_point_integration_triggers::ConnectionPoint {
                    id: cp_value["id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    name: cp_value["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    description: cp_value["description"]
                        .as_str()
                        .map(|s| s.to_string()),
                    gateway_id: cp_value["gateway_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    did: cp_value["did"]
                        .as_str()
                        .map(|s| s.to_string()),
                    created_at: cp_value["created_at"]
                        .as_str()
                        .map(|s| s.to_string()),
                    updated_at: cp_value["updated_at"]
                        .as_str()
                        .map(|s| s.to_string()),
                    status: None,
                    connection_count: None,
                };
                crate::integrations::connection_point_integration_triggers::trigger_connection_point_created(
                    &notif, &cp_obj,
                )
                .await;
            });
        }
    }
}

/// Trigger connection point updated event (non-blocking)
pub fn trigger_connection_point_updated_async(
    notif_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    old_connection_point: &crate::gateways::connection_points::types::GatewayConnectionPoint,
    new_connection_point: &crate::gateways::connection_points::types::GatewayConnectionPoint,
) {
    if let Some(notif) = notif_store {
        let old_json = serde_json::to_value(old_connection_point).ok();
        let new_json = serde_json::to_value(new_connection_point).ok();

        if let (Some(old_value), Some(new_value)) = (old_json, new_json) {
            tokio::spawn(async move {
                let old_cp = crate::integrations::connection_point_integration_triggers::ConnectionPoint {
                    id: old_value["id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    name: old_value["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    description: old_value["description"]
                        .as_str()
                        .map(|s| s.to_string()),
                    gateway_id: old_value["gateway_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    did: old_value["did"]
                        .as_str()
                        .map(|s| s.to_string()),
                    created_at: old_value["created_at"]
                        .as_str()
                        .map(|s| s.to_string()),
                    updated_at: old_value["updated_at"]
                        .as_str()
                        .map(|s| s.to_string()),
                    status: None,
                    connection_count: None,
                };

                let new_cp = crate::integrations::connection_point_integration_triggers::ConnectionPoint {
                    id: new_value["id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    name: new_value["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    description: new_value["description"]
                        .as_str()
                        .map(|s| s.to_string()),
                    gateway_id: new_value["gateway_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    did: new_value["did"]
                        .as_str()
                        .map(|s| s.to_string()),
                    created_at: new_value["created_at"]
                        .as_str()
                        .map(|s| s.to_string()),
                    updated_at: new_value["updated_at"]
                        .as_str()
                        .map(|s| s.to_string()),
                    status: None,
                    connection_count: None,
                };

                crate::integrations::connection_point_integration_triggers::trigger_connection_point_updated(
                    &notif, &old_cp, &new_cp,
                )
                .await;
            });
        }
    }
}

/// Trigger connection point deleted event (non-blocking)
pub fn trigger_connection_point_deleted_async(
    notif_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    connection_point: &crate::gateways::connection_points::types::GatewayConnectionPoint,
) {
    if let Some(notif) = notif_store {
        let cp_json = serde_json::to_value(connection_point).ok();
        if let Some(cp_value) = cp_json {
            tokio::spawn(async move {
                let cp_obj = crate::integrations::connection_point_integration_triggers::ConnectionPoint {
                    id: cp_value["id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    name: cp_value["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    description: cp_value["description"]
                        .as_str()
                        .map(|s| s.to_string()),
                    gateway_id: cp_value["gateway_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    did: cp_value["did"]
                        .as_str()
                        .map(|s| s.to_string()),
                    created_at: cp_value["created_at"]
                        .as_str()
                        .map(|s| s.to_string()),
                    updated_at: cp_value["updated_at"]
                        .as_str()
                        .map(|s| s.to_string()),
                    status: None,
                    connection_count: None,
                };
                crate::integrations::connection_point_integration_triggers::trigger_connection_point_deleted(
                    &notif, &cp_obj,
                )
                .await;
            });
        }
    }
}
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
