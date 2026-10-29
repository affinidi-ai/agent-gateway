//! Transit Point header E2E, proven at the wire: a recording target shows which
//! of the managed agent's headers reached it, and the managed agent sees which of
//! the target's response headers came back.

use super::helpers::{self, GatewayHarness, RecordingTarget};
use crate::config::agent_surface::AgentSurface;
use axum::http::StatusCode;

/// A surface whose one Transit Point, `target`, needs no transit token and
/// forwards to `target_url`.
fn surface_with_transit_point_to(target_url: &str) -> AgentSurface {
    let mut surface = helpers::build_minimal_outbound_channel();
    surface
        .transit
        .as_mut()
        .unwrap()
        .points[0]
        .target_endpoint = target_url.to_string();
    surface
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap()
}

/// The managed agent's cookies and `Authorization` stop at the Transit Point
/// while its other headers reach the target, and the target's cookies and
/// authentication challenge stop at the Transit Point while its other headers
/// reach the managed agent.
#[tokio::test(flavor = "multi_thread")]
async fn a_transit_point_keeps_cookies_and_challenges_between_the_agent_and_the_target() {
    let target = RecordingTarget::start(
        StatusCode::UNAUTHORIZED,
        &[
            ("set-cookie", "vendor_sid=vendor-session; Path=/; HttpOnly"),
            ("set-cookie", "vendor_lb=node-2"),
            (
                "www-authenticate",
                r#"Bearer resource_metadata="https://vendor.example/.well-known/oauth-protected-resource""#,
            ),
            ("x-vendor-request-id", "vendor-request-1"),
        ],
    )
    .await;
    let target_url = target.url.clone();
    let h = GatewayHarness::start_with_outbound(move |_, gw_config, _| {
        gw_config.surfaces = vec![surface_with_transit_point_to(&target_url)];
    })
    .await;

    let response = client()
        .post(format!(
            "{}/outbound/smoke/target",
            h.outbound_url
                .as_ref()
                .unwrap()
        ))
        .header("content-type", "application/json")
        .header("cookie", "agent_session=agent-1")
        .header("authorization", "Bearer agent-own-token")
        .header("x-api-key", "agent-own-key")
        .header("x-agent-context", "context-1")
        .body(r#"{"jsonrpc":"2.0","method":"test","id":1}"#)
        .send()
        .await
        .unwrap();

    let received = target.received();
    assert_eq!(received.len(), 1);
    let sent = &received[0];
    assert!(!sent.contains_key("cookie"), "{sent:?}");
    assert!(!sent.contains_key("authorization"), "{sent:?}");
    assert_eq!(sent["x-api-key"], "agent-own-key");
    assert_eq!(sent["x-agent-context"], "context-1");

    assert_eq!(response.status(), 401);
    assert!(
        !response
            .headers()
            .contains_key("set-cookie"),
        "{:?}",
        response.headers()
    );
    assert!(
        !response
            .headers()
            .contains_key("www-authenticate"),
        "{:?}",
        response.headers()
    );
    assert_eq!(response.headers()["x-vendor-request-id"], "vendor-request-1");
}
