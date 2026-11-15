use super::when::ensure_gateway_running;
use crate::world::SurfaceWorld;
use cucumber::when;

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

/// Send a HEAD request to a Transit Point discovery endpoint without transit token
#[when(expr = "managed agent {string} sends HEAD {string} without transit token through Transit Point {string}")]
async fn send_head_without_token_through_transit_point(
    world: &mut SurfaceWorld,
    agent_name: String,
    path: String,
    transit_point: String,
) {
    send_discovery_request_through_transit_point(world, &agent_name, "HEAD", &path, &transit_point, false).await;
}

/// Internal function to send HTTP discovery request through a Transit Point
///
/// Constructs the URL path to reach the Transit Point through the gateway:
/// http://gateway:port/outbound/{surface_route}/{transit_point}{path}
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
    let url = format!("http://127.0.0.1:{}/outbound{}/{}{}", gateway_port, surface_route, transit_point, path);

    let client = reqwest::Client::new();
    let mut request = match method {
        "GET" => client.get(&url),
        "HEAD" => client.head(&url),
        _ => panic!("Unsupported HTTP method: {}", method),
    };

    // Add transit token header if requested (reuse existing with_transit_token helper style)
    if include_token {
        if let Some(transit_token) = world.transit_token.as_ref() {
            request = request.header("X-Transit-Token", transit_token);
        }
    }

    // Send the request and record the response in caller_response (used by generic Then steps)
    match request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let headers: std::collections::HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        v.to_str()
                            .unwrap_or("")
                            .to_string(),
                    )
                })
                .collect();
            let body = response
                .json()
                .await
                .unwrap_or_else(|_| serde_json::json!({}));

            world.caller_response = Some(crate::bdd_support::admin_client::RecordedResponse { status, headers, body });
            world.last_error_reason = None;
        }
        Err(e) => {
            world.last_error_reason = Some(format!("HTTP request failed: {}", e));
        }
    }
}

// ============================================================================
// THEN Steps: Verify Outcomes
// ============================================================================

// Note: Use the generic "the response status is {int}" step from then.rs instead of a custom step.
// The discovery request response is stored in caller_response, which the generic step reads.
