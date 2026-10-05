use axum::{body::Body, http::Response};
use hyper::Uri;
use tracing::{debug, info, warn};

pub(crate) fn join_endpoint_path(
    endpoint: &str,
    path_and_query: &str,
) -> String {
    if path_and_query == "/" {
        endpoint
            .trim_end_matches('/')
            .to_string()
    } else if path_and_query.starts_with('/') {
        format!("{}{}", endpoint.trim_end_matches('/'), path_and_query)
    } else {
        format!("{}/{}", endpoint.trim_end_matches('/'), path_and_query)
    }
}

/// Simple protocol routing function - extensible by adding new conditions
pub fn route_protocol_request(
    target_endpoint: &str,
    uri: &Uri,
    _method: &hyper::Method,
    _headers: &hyper::HeaderMap,
    _body: &[u8],
    override_agent_card_location: bool,
    agent_card_location_path: Option<&str>,
) -> ProtocolResult {
    // Extract scheme from target endpoint
    let scheme = if let Some(scheme_end) = target_endpoint.find("://") {
        &target_endpoint[..scheme_end]
    } else {
        // Default to HTTPS if no scheme is provided
        warn!("No scheme found in target endpoint '{}', defaulting to HTTPS", target_endpoint);
        "https"
    };

    debug!("Routing request with scheme: {}", scheme);

    match scheme {
        "http" | "https" => {
            // HTTP/HTTPS - build the target URL as before
            let path_and_query = uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");

            // Allow for default relative-to-root path of .well-known/agent-card.json to be overridden by config
            let target_url = if path_and_query.starts_with("/.well-known/") {
                // Check if agent card location override is enabled
                if override_agent_card_location
                    && agent_card_location_path.is_some()
                    && let Some(custom_path) = agent_card_location_path
                {
                    // Use custom agent card location - append the custom path to the ORIGIN
                    // of the target endpoint (scheme + host + port), stripping any sub-path.
                    // This supports upstreams that serve their agent card at the server root
                    // rather than relative to the API sub-path.
                    let custom_path_clean = if custom_path.starts_with('/') {
                        custom_path.to_string()
                    } else {
                        format!("/{}", custom_path)
                    };
                    // Extract origin from target_endpoint (everything up to the path)
                    let origin = if let Some(scheme_end) = target_endpoint.find("://") {
                        let after_scheme = &target_endpoint[scheme_end + 3..];
                        if let Some(path_start) = after_scheme.find('/') {
                            &target_endpoint[..scheme_end + 3 + path_start]
                        } else {
                            target_endpoint
                        }
                    } else {
                        target_endpoint
                    };
                    format!("{}{}", origin, custom_path_clean)
                } else {
                    // Default behavior: Per A2A spec Section 5.3, the agent card lives at
                    // {agent_base_url}/.well-known/agent-card.json where agent_base_url is the
                    // full target endpoint including any path component.
                    //
                    // Example (ATF-to-ATF, target has a channel path):
                    //   https://gw-b:8443/channel-b/custom-path + /.well-known/agent-card.json
                    //   -> https://gw-b:8443/channel-b/custom-path/.well-known/agent-card.json  ✅
                    //
                    // Example (bare origin target, no path):
                    //   https://backend:8200 + /.well-known/agent-card.json
                    //   -> https://backend:8200/.well-known/agent-card.json  ✅
                    //
                    // If the upstream backend serves its agent card at the server root rather than
                    // relative to its API sub-path, enable `override_agent_card_location` and set
                    // `agent_card_location_path` in the channel configuration instead.
                    join_endpoint_path(target_endpoint, path_and_query)
                }
            } else {
                join_endpoint_path(target_endpoint, path_and_query)
            };
            info!("🌐 HTTP/HTTPS protocol handler forwarding to: {}", target_url);

            ProtocolResult::HttpForward(target_url)
        }
        "fabric" => {
            // Fabric protocol - route through gateway
            info!("🏭 Fabric protocol handler processing request for: {}", target_endpoint);
            info!("📍 Request path: {}", uri.path());

            // Parse fabric://{gateway_id}/{channel_id}
            let fabric_path = &target_endpoint[9..]; // Remove "fabric://"
            let parts: Vec<&str> = fabric_path
                .split('/')
                .collect();

            if parts.len() < 2 {
                warn!("Invalid fabric URL format: {}", target_endpoint);
                let response = Response::builder()
                    .status(axum::http::StatusCode::BAD_REQUEST)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"error":"Invalid fabric URL format. Expected: fabric://{gateway_id}/{channel_id}"}"#,
                    ))
                    .unwrap();
                return ProtocolResult::DirectResponse(response);
            }

            let gateway_id = parts[0];
            let channel_id = parts[1];

            info!("🎯 Routing to gateway {} channel {}", gateway_id, channel_id);

            ProtocolResult::FabricForward {
                gateway_id: gateway_id.to_string(),
                channel_id: channel_id.to_string(),
            }
        }
        "did" => {
            info!("🔗 DID protocol handler processing request for: {}", target_endpoint);
            info!("📍 Request path: {}", uri.path());

            // For now, just return a placeholder response
            // TODO: Implement actual DID resolution and routing
            let response_body = format!("Routing to DID: {} (path: {})", target_endpoint, uri.path());

            let response = Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("content-type", "text/plain")
                .body(Body::from(response_body))
                .unwrap_or_else(|_| {
                    Response::builder()
                        .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Internal server error"))
                        .unwrap()
                });

            info!("✅ DID protocol handler returning direct response");
            ProtocolResult::DirectResponse(response)
        }
        _ => {
            warn!("Unknown protocol scheme: {}, defaulting to HTTPS", scheme);
            // Default to HTTPS for unknown protocols
            let https_target = if target_endpoint.contains("://") {
                target_endpoint.to_string()
            } else {
                format!("https://{}", target_endpoint)
            };

            let path_and_query = uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");

            let target_url = join_endpoint_path(&https_target, path_and_query);
            ProtocolResult::HttpForward(target_url)
        }
    }
}

/// Result of protocol handling
pub enum ProtocolResult {
    /// Forward to HTTP/HTTPS with the given URL
    HttpForward(String),
    /// Forward through gateway fabric to a remote channel
    FabricForward {
        #[allow(dead_code)]
        gateway_id: String,
        #[allow(dead_code)]
        channel_id: String,
    },
    /// Direct response (protocol handled internally)
    DirectResponse(Response<Body>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routed_url(
        target_endpoint: &str,
        request_uri: &str,
    ) -> String {
        match route_protocol_request(
            target_endpoint,
            &request_uri
                .parse::<Uri>()
                .unwrap(),
            &hyper::Method::GET,
            &hyper::HeaderMap::new(),
            &[],
            false,
            None,
        ) {
            ProtocolResult::HttpForward(url) => url,
            _ => panic!("expected HTTP forward"),
        }
    }

    #[test]
    fn http_target_with_trailing_slash_joins_well_known_once() {
        assert_eq!(
            routed_url("https://gateway.example/a2a/requester/", "/.well-known/agent-card.json"),
            "https://gateway.example/a2a/requester/.well-known/agent-card.json"
        );
    }

    #[test]
    fn http_target_with_trailing_slash_joins_normal_path_once() {
        assert_eq!(
            routed_url("https://gateway.example/a2a/requester/", "/message/send?x=1"),
            "https://gateway.example/a2a/requester/message/send?x=1"
        );
    }

    #[test]
    fn http_target_with_trailing_slash_root_request_stays_without_slash() {
        assert_eq!(routed_url("https://gateway.example/a2a/requester/", "/"), "https://gateway.example/a2a/requester");
    }
}
