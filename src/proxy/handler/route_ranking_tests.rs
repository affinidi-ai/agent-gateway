//! Which surface the Access Point serves a request to, chosen by route.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::json;

use crate::component_tests::helpers::MockServer;
use crate::config::agent_surface::AgentSurface;

fn surface(
    id: &str,
    route: &str,
    endpoint: &str,
) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": id, "name": id,
        "access_point": {"listen_address": "https://gateway.example", "route": route, "protocol": "a2a"},
        "target": {"endpoint": endpoint}
    }))
    .unwrap()
}

async fn served_by(
    stored_routes: [(&str, &MockServer); 2],
    path: &str,
) -> axum::http::StatusCode {
    let [(first_route, first), (second_route, second)] = stored_routes;
    let router = super::variant_routing_tests::router(surface("first", first_route, &first.url()));
    {
        let mut channels = router.channels.write().await;
        let mut other = channels[0].clone();
        other.surface = Arc::new(surface("second", second_route, &second.url()));
        other.task_id = "second".into();
        channels.push(other);
    }
    super::variant_routing_tests::send(router, path)
        .await
        .0
}

async fn target() -> MockServer {
    MockServer::start_with_response(json!({"jsonrpc": "2.0", "id": 1, "result": {"kind": "message"}}).to_string()).await
}

#[tokio::test]
async fn a_route_stored_with_trailing_slashes_does_not_outrank_a_more_specific_route() {
    let (acme, pay) = (target().await, target().await);

    let status =
        served_by([("/agents/acme//////////", &acme), ("/agents/acme/pay", &pay)], "/agents/acme/pay/rpc").await;

    assert_eq!(status, 200);
    assert_eq!(
        pay.request_count
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        acme.request_count
            .load(Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn the_less_specific_route_still_serves_the_paths_the_more_specific_one_does_not() {
    let (acme, pay) = (target().await, target().await);

    let status =
        served_by([("/agents/acme//////////", &acme), ("/agents/acme/pay", &pay)], "/agents/acme/orders").await;

    assert_eq!(status, 200);
    assert_eq!(
        acme.request_count
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(
        pay.request_count
            .load(Ordering::SeqCst),
        0
    );
}
