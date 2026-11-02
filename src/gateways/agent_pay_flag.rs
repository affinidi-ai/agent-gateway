//! The `agent_pay_delegation` dashboard feature flag.
//!
//! Off by default. While off, this gateway connects no new payment gateway and
//! turns no peer into one; payment gateways already connected keep taking
//! payments and stay readable. Read per request from the system settings, like
//! `mediator_federation`, so a user's own flag overrides never change it.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::MethodRouter,
};

pub const FLAG_AGENT_PAY: &str = "agent_pay_delegation";

/// Whether payment gateways may be added. False when settings are unavailable.
pub fn agent_pay_enabled() -> bool {
    crate::storage::settings_store::system_flag_enabled(FLAG_AGENT_PAY)
}

/// `403` naming the flag while it is off.
pub fn require_agent_pay(enabled: bool) -> Result<(), (StatusCode, String)> {
    if enabled {
        return Ok(());
    }
    Err((StatusCode::FORBIDDEN, format!("Adding a payment gateway requires the {FLAG_AGENT_PAY} feature flag")))
}

/// Refuses `route` with `403` while the flag is off.
pub fn gate_adding_payment_gateways(route: MethodRouter) -> MethodRouter {
    gate_with(route, agent_pay_enabled)
}

fn gate_with(
    route: MethodRouter,
    enabled: fn() -> bool,
) -> MethodRouter {
    route.layer(axum::middleware::from_fn_with_state(enabled, refuse_while_off))
}

async fn refuse_while_off(
    State(enabled): State<fn() -> bool>,
    request: Request,
    next: Next,
) -> Response {
    match require_agent_pay(enabled()) {
        Ok(()) => next.run(request).await,
        Err(refusal) => refusal.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::post};
    use tower::ServiceExt;

    async fn status_with(enabled: fn() -> bool) -> StatusCode {
        Router::new()
            .route("/add", gate_with(post(|| async { StatusCode::CREATED }), enabled))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/add")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn the_gate_refuses_before_the_handler_while_the_flag_is_off() {
        assert_eq!(status_with(|| false).await, StatusCode::FORBIDDEN);
        assert_eq!(status_with(|| true).await, StatusCode::CREATED);
    }

    #[test]
    fn adding_a_payment_gateway_is_refused_while_the_flag_is_off() {
        assert!(require_agent_pay(true).is_ok());
        let (status, message) = require_agent_pay(false).unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(message, "Adding a payment gateway requires the agent_pay_delegation feature flag");
    }

    #[test]
    fn the_flag_is_off_without_settings() {
        if crate::storage::settings_store::global_settings_store().is_none() {
            assert!(!agent_pay_enabled());
        }
    }
}
