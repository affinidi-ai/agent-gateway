//! `PUT` and `DELETE /v1/surfaces/{surface_id}/policy-input-capture`: switch on, for a
//! bounded time, or off the capture of a surface's policy input for the dashboard
//! (see [`crate::policies::input_capture`]).

use axum::{
    Extension, Json,
    extract::{Path, State},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatDelegationContext, PatResourceScope};
use crate::identity::state::IdentityApiState;
use crate::policies::input_capture::MAX_MINUTES;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::PatTenantContext;

use super::surfaces::{
    SURFACE_WRITES, SurfaceApiError, SurfaceChange, apply_surface_change, management_actor, resource_scope,
    surface_visible, surface_writable, tenant_context,
};

/// Body of `PUT /v1/surfaces/{surface_id}/policy-input-capture`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnablePolicyInputCapture {
    /// How long, from now, the policy input is captured: 1 to [`MAX_MINUTES`].
    pub minutes: i64,
}

/// The surface's policy input capture setting after a change.
#[derive(Debug, Serialize)]
pub struct PolicyInputCaptureResponse {
    pub surface_id: String,
    pub policy_input_capture_until: Option<DateTime<Utc>>,
}

fn capture_until(
    minutes: i64,
    now: DateTime<Utc>,
) -> Result<DateTime<Utc>, SurfaceApiError> {
    if !(1..=MAX_MINUTES).contains(&minutes) {
        return Err(SurfaceApiError::BadRequest(format!("minutes must be between 1 and {MAX_MINUTES}")));
    }
    Ok(now + Duration::minutes(minutes))
}

/// `PUT /v1/surfaces/{surface_id}/policy-input-capture`: capture the surface's policy input
/// for the next `minutes`, replacing any earlier end time.
pub async fn enable_policy_input_capture(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
    Json(body): Json<EnablePolicyInputCapture>,
) -> Result<Json<PolicyInputCaptureResponse>, SurfaceApiError> {
    let until = capture_until(body.minutes, Utc::now())?;
    set_policy_input_capture(&state, &surface_id, Some(until), &context, &scope, &delegation, &caller).await
}

/// `DELETE /v1/surfaces/{surface_id}/policy-input-capture`: stop capturing the surface's
/// policy input.
pub async fn disable_policy_input_capture(
    Path(surface_id): Path<String>,
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    delegation: Option<Extension<PatDelegationContext>>,
    caller: Option<Extension<AuthGuardOk>>,
) -> Result<Json<PolicyInputCaptureResponse>, SurfaceApiError> {
    set_policy_input_capture(&state, &surface_id, None, &context, &scope, &delegation, &caller).await
}

async fn set_policy_input_capture(
    state: &IdentityApiState,
    surface_id: &str,
    until: Option<DateTime<Utc>>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    delegation: &Option<Extension<PatDelegationContext>>,
    caller: &Option<Extension<AuthGuardOk>>,
) -> Result<Json<PolicyInputCaptureResponse>, SurfaceApiError> {
    let store = state
        .agent_surface_store
        .as_ref()
        .ok_or_else(|| SurfaceApiError::InternalError("Agent surface store not initialized".to_string()))?;
    let not_found = || SurfaceApiError::NotFound(format!("Surface '{surface_id}' not found"));

    let saved = {
        let _writes = SURFACE_WRITES.lock().await;
        let _surface = super::surface_grants::lock_surface(surface_id).await;
        let mut surface = store
            .get(surface_id)
            .await
            .map_err(|e| SurfaceApiError::InternalError(format!("Failed to get surface: {e}")))?
            .ok_or_else(not_found)?;
        let tenant = surface.tenant_id.as_deref();
        if !surface_visible(tenant, surface_id, tenant_context(context), resource_scope(scope)) {
            return Err(not_found());
        }
        if !surface_writable(tenant, surface_id, tenant_context(context), resource_scope(scope)) {
            return Err(SurfaceApiError::Forbidden("surface is outside this token's permitted scope".to_string()));
        }
        surface.policy_input_capture_until = until;
        store
            .save(&surface)
            .await
            .map_err(|e| SurfaceApiError::InternalError(format!("Failed to save surface: {e}")))?;
        surface
    };

    let actor = management_actor(caller, delegation);
    info!(
        surface_id = %surface_id,
        actor = ?actor,
        until = ?until,
        "Policy input capture {}",
        if until.is_some() { "switched on" } else { "switched off" }
    );
    apply_surface_change(state, SurfaceChange::Upsert(&saved)).await;

    Ok(Json(PolicyInputCaptureResponse {
        surface_id: saved.surface_id,
        policy_input_capture_until: saved.policy_input_capture_until,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minutes_from_one_to_the_maximum_set_an_end_time_that_far_ahead() {
        let now = Utc::now();

        assert_eq!(capture_until(1, now).unwrap(), now + Duration::minutes(1));
        assert_eq!(capture_until(MAX_MINUTES, now).unwrap(), now + Duration::minutes(MAX_MINUTES));
    }

    #[test]
    fn minutes_outside_one_to_the_maximum_are_refused() {
        let now = Utc::now();

        for minutes in [0, -5, MAX_MINUTES + 1] {
            let error = capture_until(minutes, now).unwrap_err();
            assert!(
                matches!(&error, SurfaceApiError::BadRequest(message) if message.contains("between 1 and 60")),
                "{minutes}: {error:?}"
            );
        }
    }
}
