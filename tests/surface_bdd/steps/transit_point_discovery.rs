use super::when::ensure_gateway_running;
use crate::bdd_support::http::collect_headers;
use crate::world::SurfaceWorld;
use cucumber::{then, when};

// ============================================================================
// WHEN Steps: Perform Actions
// ============================================================================

/// Send a GET request to a Transit Point discovery endpoint with transit token
#[when(expr = "managed agent {string} sends GET {string} with transit token through Transit Point {string}")]
async fn send_get_with_token_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: String,
    path: String,
    transit_point: String,
) {
    send_discovery_request_through_transit_point(world, &agent_name, "GET", &path, &transit_point, true).await;
}

/// Send a HEAD request to a Transit Point discovery endpoint with transit token
#[when(expr = "managed agent {string} sends HEAD {string} with transit token through Transit Point {string}")]
async fn send_head_with_token_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: String,
    path: String,
    transit_point: String,
) {
    send_discovery_request_through_transit_point(world, &agent_name, "HEAD", &path, &transit_point, true).await;
}

/// Send a GET request to a Transit Point discovery endpoint without transit token
#[when(expr = "managed agent {string} sends GET {string} without transit token through Transit Point {string}")]
async fn send_get_without_token_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: String,
    path: String,
    transit_point: String,
) {
    send_discovery_request_through_transit_point(world, &agent_name, "GET", &path, &transit_point, false).await;
}

/// Internal function to send HTTP discovery request through a Transit Point
///
/// Constructs the URL path to reach the Transit Point through the gateway:
/// http://gateway:port/{surface_route}/transit/{transit_point}{path}
///
/// If include_token is true, adds the X-Transit-Token header from the test context.
async fn send_discovery_request_through_transit_point(
    world: &mut SurfaceWorld,
    _agent_name: &str,
    method: &str,
    path: &str,
    transit_point: &str,
    include_token: bool,
) {
    // Ensure gateway is running before making the request
    ensure_gateway_running(world).await;

    let infra = world
        .infra
        .as_ref()
        .expect("gateway infra must be running");
    let gateway_port = infra.gateway_port;
    let surface_route = &world.surface_config.route;

    // Build URL: http://localhost:port/outbound/{surface_route}/{transit_point}{path}
    // Pattern from src/proxy/outbound_handler.rs:
    // /outbound/<aap-path>/<virtual-channel>/<remaining-path>
    let url = format!("http://127.0.0.1:{}/outbound{}/{}{}", gateway_port, surface_route, transit_point, path);

    let client = reqwest::Client::new();
    let mut request = match method {
        "GET" => client.get(&url),
        "HEAD" => client.head(&url),
        _ => panic!("Unsupported HTTP method: {}", method),
    };

    // Add transit token header if requested
    if include_token && let Some(transit_token) = world.transit_token.as_ref() {
        request = request.header("X-Transit-Token", transit_token);
    }

    // Send the request and record the response
    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let headers = collect_headers(response.headers());
            let body = response
                .json()
                .await
                .unwrap_or_else(|_| serde_json::json!({}));

            world.last_response = Some(crate::bdd_support::admin_client::RecordedResponse { status, headers, body });
            world.last_error_reason = None;
        }
        Err(e) => {
            world.last_error_reason = Some(format!("HTTP request failed: {}", e));
            world.last_response = None;
        }
    }
}

// ============================================================================
// THEN Steps: Verify Outcomes
// ============================================================================

/// Verify the response status from a discovery request
#[then(expr = "the response status is {int} from discovery request")]
fn verify_discovery_response_status(
    world: &mut SurfaceWorld,
    expected_status: i32,
) {
    let response = world
        .last_response
        .as_ref()
        .expect("discovery request must have been sent");

    assert_eq!(
        response.status as i32, expected_status,
        "Expected HTTP {} from discovery request, got {}",
        expected_status, response.status
    );
}
