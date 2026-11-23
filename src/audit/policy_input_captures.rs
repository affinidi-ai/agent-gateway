//! Records of a dashboard user starting and stopping a policy input capture: watching the live,
//! masked policy input of one surface on its Capture view. Each names the user and the surface,
//! a stop also why it ended, and is written only when a sink selects its event.

use crate::audit::events::Actor;
use crate::delegation_vault::audit::{
    DelegationAuditAction, PolicyInputCaptureDetails, PolicyInputCaptureStop, action_category, audit_event, emit,
};

/// Records that `user_id` started capturing the policy input of `surface_id`.
pub fn started(
    user_id: &str,
    surface_id: &str,
) {
    record(DelegationAuditAction::PolicyInputCaptureStarted(details(user_id, None)), surface_id);
}

/// Records that the capture `user_id` held on the policy input of `surface_id` ended, and why.
pub fn stopped(
    user_id: &str,
    surface_id: &str,
    reason: PolicyInputCaptureStop,
) {
    record(DelegationAuditAction::PolicyInputCaptureStopped(details(user_id, Some(reason))), surface_id);
}

fn details(
    user_id: &str,
    reason: Option<PolicyInputCaptureStop>,
) -> Box<PolicyInputCaptureDetails> {
    Box::new(PolicyInputCaptureDetails {
        actor: Actor::user(user_id),
        reason,
    })
}

fn record(
    action: DelegationAuditAction,
    surface_id: &str,
) {
    let surface_id = surface_id.to_string();
    emit(action_category(&action), move || audit_event(action, None, None, None, Some(&surface_id)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::producer::capture;
    use serde_json::json;

    #[tokio::test]
    async fn a_started_capture_names_the_user_and_the_surface() {
        let ((), records) = capture(async { started("u-1", "s-1") }).await;

        assert_eq!(records.len(), 1);
        assert_eq!(action_category(&records[0].event), "policy_input_capture_started");
        assert!(records[0].event.is_vp_audit());
        assert_eq!(
            records[0]
                .surface_id
                .as_deref(),
            Some("s-1")
        );
        let stored = serde_json::to_value(&records[0].event).unwrap();
        assert_eq!(stored["policy_input_capture_started"]["actor"], json!({ "kind": "user", "id": "u-1" }));
        assert!(
            stored["policy_input_capture_started"]
                .get("reason")
                .is_none(),
            "{stored}"
        );
    }

    #[tokio::test]
    async fn a_stopped_capture_names_the_user_the_surface_and_why_it_ended() {
        for (reason, spelled) in [
            (PolicyInputCaptureStop::Stopped, "stopped"),
            (PolicyInputCaptureStop::ConnectionClosed, "connection_closed"),
            (PolicyInputCaptureStop::SessionEnded, "session_ended"),
            (PolicyInputCaptureStop::PermissionMissing, "permission_missing"),
            (PolicyInputCaptureStop::TurnedOff, "turned_off"),
        ] {
            let ((), records) = capture(async { stopped("u-1", "s-1", reason) }).await;

            assert_eq!(records.len(), 1, "{spelled}");
            assert_eq!(action_category(&records[0].event), "policy_input_capture_stopped");
            assert!(records[0].event.is_vp_audit());
            assert_eq!(
                records[0]
                    .surface_id
                    .as_deref(),
                Some("s-1")
            );
            let stored = serde_json::to_value(&records[0].event).unwrap();
            assert_eq!(stored["policy_input_capture_stopped"]["actor"]["id"], "u-1");
            assert_eq!(stored["policy_input_capture_stopped"]["reason"], spelled);
        }
    }
}
