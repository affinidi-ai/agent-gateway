//! Request context that audit records built deep in a call chain pick up
//! without it being passed down every signature.

use std::future::Future;

use crate::audit::events::Actor;
use crate::delegation_vault::audit::AuditCallerContext;

tokio::task_local! {
    static CALLER: Option<AuditCallerContext>;
    static ACTOR: Actor;
}

/// Runs a management API request as `actor`, with a request id of its own,
/// so every change record it writes names who made it and shares one id.
pub async fn in_management_request<F: Future>(
    actor: Actor,
    future: F,
) -> F::Output {
    use crate::observability::policy_audit::{REQUEST_ID, new_request_id};
    ACTOR
        .scope(actor, REQUEST_ID.scope(new_request_id(), future))
        .await
}

/// The actor set by [`in_management_request`], if any.
pub fn current_actor() -> Option<Actor> {
    ACTOR
        .try_with(Clone::clone)
        .ok()
}

/// Runs `future` with `caller` as the caller of every audit record it builds.
pub async fn with_caller<F: Future>(
    caller: Option<AuditCallerContext>,
    future: F,
) -> F::Output {
    CALLER
        .scope(caller, future)
        .await
}

/// The caller set by [`with_caller`], if any.
pub fn current_caller() -> Option<AuditCallerContext> {
    CALLER
        .try_with(Clone::clone)
        .ok()
        .flatten()
}
