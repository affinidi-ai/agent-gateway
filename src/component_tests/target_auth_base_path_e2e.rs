//! The Target credential stays under the Target base path: a request whose path
//! climbs out of it is refused with a 502 before anything reaches the Target, a
//! request under it is forwarded with the credential, and a credentialed forward
//! returns a Target's redirect instead of following it.

use super::helpers::{self, GatewayHarness, MockServer};
use super::target_auth_provider_e2e::write_secret;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) const RPC_BODY: &str = r#"{"jsonrpc":"2.0","method":"message/send","id":1,"params":{}}"#;

fn credentialed_surface(
    bootstrap: &crate::config::BootstrapConfig,
    target_endpoint: String,
) -> crate::config::agent_surface::AgentSurface {
    write_secret(bootstrap, "target-key", "gateway-value");
    let mut surface = helpers::build_minimal_channel();
    surface.target.endpoint = target_endpoint;
    surface.target.auth = Some(
        serde_json::from_value(json!({
            "method": {"static_secret": {
                "secret_id": "target-key", "header_name": "X-Api-Key", "header_format": "{value}"
            }}
        }))
        .unwrap(),
    );
    surface
}

/// Send `path` to the gateway exactly as written, since an HTTP client would
/// resolve its dot segments before sending.
pub(super) async fn raw_post(
    gateway_base: &str,
    path: &str,
) -> (u16, String) {
    let authority = gateway_base
        .strip_prefix("http://")
        .unwrap();
    let mut stream = tokio::net::TcpStream::connect(authority)
        .await
        .unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{RPC_BODY}",
        RPC_BODY.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .unwrap();
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .unwrap();
    let status = response
        .split(' ')
        .nth(1)
        .and_then(|status| status.parse().ok())
        .unwrap_or_else(|| panic!("no status line in the gateway response to {path}"));
    (status, response)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_path_outside_the_target_base_path_is_refused_before_the_target() {
    let mock = MockServer::start().await;
    let target = format!("{}/base", mock.url());
    let h = GatewayHarness::start_with_mock(mock, |_, gw_config, bootstrap| {
        gw_config.surfaces = vec![credentialed_surface(bootstrap, target)];
    })
    .await;

    for path in [
        "/smoke/%2e%2e/admin",
        "/smoke/%2E%2E/admin",
        "/smoke/../admin",
        "/smoke/./../admin",
        "/smoke/..;/admin",
        "/smoke/..%2Fadmin",
        "/smoke/%252e%252e/admin",
    ] {
        let (status, response) = raw_post(&h.gateway_base, path).await;
        assert_eq!(status, 502, "{path}");
        assert!(response.contains("Target authentication failed"), "{path}");
    }
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        0
    );

    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(RPC_BODY)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let received = h
        .mock
        .last_request_rx
        .borrow()
        .clone()
        .expect("the target received the request");
    assert_eq!(received.path, "/base/rpc");
    let credential = received
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-api-key"))
        .map(|(_, value)| value.as_str());
    assert_eq!(credential, Some("gateway-value"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credentialed_forward_returns_a_redirect_without_following_it() {
    let followed = Arc::new(AtomicUsize::new(0));
    let counter = followed.clone();
    let elsewhere = axum::Router::new().fallback(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        async { "followed" }
    });
    let elsewhere_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let location = format!(
        "http://{}/stolen",
        elsewhere_listener
            .local_addr()
            .unwrap()
    );
    let redirecting_location = location.clone();
    let redirecting = axum::Router::new().fallback(move || {
        let location = redirecting_location.clone();
        async move { (axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, location)]) }
    });
    let redirecting_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
    let target = format!(
        "http://{}/base",
        redirecting_listener
            .local_addr()
            .unwrap()
    );
    let mut servers = tokio::task::JoinSet::new();
    servers.spawn(async move { axum::serve(elsewhere_listener, elsewhere).await });
    servers.spawn(async move { axum::serve(redirecting_listener, redirecting).await });
    let h = GatewayHarness::start(|_, gw_config, bootstrap| {
        gw_config.surfaces = vec![credentialed_surface(bootstrap, target)];
    })
    .await;

    let response = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(&h.gateway_url)
        .header("content-type", "application/json")
        .body(RPC_BODY)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 302);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok()),
        Some(location.as_str())
    );
    assert_eq!(followed.load(Ordering::SeqCst), 0);
}
