//! Request context that audit records built deep in a call chain pick up
//! without it being passed down every signature.

use std::future::Future;

use crate::delegation_vault::audit::AuditCallerContext;

tokio::task_local! {
    static CALLER: Option<AuditCallerContext>;
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
