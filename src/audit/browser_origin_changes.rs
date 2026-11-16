//! Records of management saves that changed a surface's `browser_origins`: the origins whose
//! pages a browser lets call the surface. Each names the actor of the management request it is
//! built in and is written only when a sink selects its event; each is also logged at info.

use tracing::info;

use crate::audit::context::current_actor;
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::{
    BrowserOriginsChangeDetails, DelegationAuditAction, action_category, audit_event, emit,
};

/// Records and logs a surface write that changed its `browser_origins`, a new surface's included.
/// Writes nothing for a save that leaves them as they were, and nothing outside a management
/// request: startup migrations, replication and configuration reloads are not user changes.
pub fn surface_written(
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
) {
    let Some(actor) = current_actor() else {
        return;
    };
    let Some(surface) = after else {
        return;
    };
    let previous_origins = before
        .map(|before| before.browser_origins.clone())
        .unwrap_or_default();
    if previous_origins == surface.browser_origins {
        return;
    }
    info!(
        surface_id = ?surface.surface_id,
        previous_origins = ?previous_origins,
        origins = ?surface.browser_origins,
        "A surface save changed its browser origins"
    );
    let action = DelegationAuditAction::BrowserOriginsChanged(Box::new(BrowserOriginsChangeDetails {
        actor,
        previous_origins,
        origins: surface
            .browser_origins
            .clone(),
    }));
    let surface_id = surface.surface_id.clone();
    let name = surface.name.clone();
    emit(action_category(&action), move || {
        let mut event = audit_event(action, None, None, None, Some(&surface_id));
        event.channel_name = Some(name);
        event
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::context::in_management_request;
    use crate::audit::events::Actor;
    use crate::audit::producer::capture;
    use serde_json::json;

    fn surface(origins: &[&str]) -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "s-1",
            "name": "Chat agent",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/chat", "protocol": "a2a" },
            "target": { "endpoint": "https://upstream" },
            "browser_origins": origins,
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn a_management_save_that_changes_the_origins_records_both_lists() {
        let before = surface(&["https://chat.example.com"]);
        let after = surface(&["https://chat.example.com", "https://app.example.com"]);
        let ((), records) =
            capture(in_management_request(Actor::user("u-1"), async { surface_written(Some(&before), Some(&after)) }))
                .await;
        assert_eq!(records.len(), 1);
        assert_eq!(action_category(&records[0].event), "browser_origins_changed");
        assert!(records[0].event.is_vp_audit());
        assert_eq!(
            records[0]
                .surface_id
                .as_deref(),
            Some("s-1")
        );
        let stored = serde_json::to_value(&records[0].event).unwrap();
        let change = &stored["browser_origins_changed"];
        assert_eq!(change["previous_origins"], json!(["https://chat.example.com"]));
        assert_eq!(change["origins"], json!(["https://chat.example.com", "https://app.example.com"]));
    }

    #[tokio::test]
    async fn a_new_surface_with_origins_records_an_empty_previous_list() {
        let after = surface(&["https://chat.example.com"]);
        let ((), records) =
            capture(in_management_request(Actor::user("u-1"), async { surface_written(None, Some(&after)) })).await;
        assert_eq!(records.len(), 1);
        let stored = serde_json::to_value(&records[0].event).unwrap();
        assert_eq!(stored["browser_origins_changed"]["previous_origins"], json!([]));
    }

    #[tokio::test]
    async fn a_save_without_a_change_or_outside_a_management_request_records_nothing() {
        let same = surface(&["https://chat.example.com"]);
        let ((), records) =
            capture(in_management_request(Actor::user("u-1"), async { surface_written(Some(&same), Some(&same)) }))
                .await;
        assert!(records.is_empty(), "unchanged: {records:?}");
        let ((), records) =
            capture(in_management_request(Actor::user("u-1"), async { surface_written(None, Some(&surface(&[]))) }))
                .await;
        assert!(records.is_empty(), "a new surface without origins: {records:?}");
        let after = surface(&["https://app.example.com"]);
        let ((), records) = capture(async { surface_written(Some(&same), Some(&after)) }).await;
        assert!(records.is_empty(), "not a management change: {records:?}");
    }
}
