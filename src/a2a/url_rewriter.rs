//! URL building and rewriting for A2A protocol

use axum::{
    http::{HeaderMap, Uri},
    response::Response,
};
use tracing::{debug, info, warn};

use crate::proxy::backend_identity::ProtectedAgentIdentity;

/// Build target URL from endpoint and request URI, or return direct response for special protocols
#[allow(clippy::result_large_err)]
pub fn build_target_url(
    target_endpoint: &str,
    uri: &Uri,
    method: &hyper::Method,
    headers: &HeaderMap,
    override_agent_card_location: bool,
    agent_card_location_path: Option<&str>,
) -> Result<String, Response> {
    use crate::proxy::{ProtocolResult, route_protocol_request};

    // Route through protocol router
    match route_protocol_request(
        target_endpoint,
        uri,
        method,
        headers,
        &[],
        override_agent_card_location,
        agent_card_location_path,
    ) {
        ProtocolResult::HttpForward(url) => Ok(url),
        ProtocolResult::FabricForward { .. } => {
            // This should not happen in build_target_url - fabric forwarding is handled elsewhere
            warn!("Unexpected FabricForward result in build_target_url");
            Ok(target_endpoint.to_string())
        }
        ProtocolResult::DirectResponse(response) => Err(response),
    }
}

/// Read an agent card's primary endpoint URL, tolerating **either** protocol era.
///
/// A2A v1.0 removed the top-level `url` field and collapsed the transports into an
/// ordered `supportedInterfaces[]` whose **first entry is the preferred one**, so a
/// pure-1.0 card has no `url` at all. This prefers the 1.0 shape and falls back to
/// the v0.3 fields, which keeps readers working across both eras rather than
/// silently seeing nothing for a 1.0 upstream.
///
/// Both key spellings are accepted because cards transcoded from the protobuf
/// definition use snake_case while the JSON spec uses camelCase.
pub fn primary_endpoint_url(agent_card: &serde_json::Value) -> Option<&str> {
    // A2A v1.0 — first interface wins (order encodes preference).
    for key in ["supportedInterfaces", "supported_interfaces"] {
        if let Some(url) = agent_card
            .get(key)
            .and_then(|i| i.as_array())
            .and_then(|i| i.first())
            .and_then(|iface| iface.get("url"))
            .and_then(|u| u.as_str())
        {
            return Some(url);
        }
    }
    // A2A v0.3 fallbacks.
    for key in ["url", "endpoint"] {
        if let Some(url) = agent_card
            .get(key)
            .and_then(|u| u.as_str())
        {
            return Some(url);
        }
    }
    agent_card
        .get("endpoints")
        .and_then(|e| e.as_array())
        .and_then(|e| e.first())
        .and_then(|ep| ep.get("url"))
        .and_then(|u| u.as_str())
}

/// Rewrite URLs in an agent card to point to the proxy endpoint
fn rewrite_urls_in_agent_card(
    agent_card: &mut serde_json::Value,
    proxy_endpoint: &str,
    channel_name: &str,
) -> bool {
    let mut rewrote_something = false;

    // Check for 'url' field (standard A2A agent card format)
    if let Some(url) = agent_card.get_mut("url") {
        let original = url
            .as_str()
            .unwrap_or("unknown");
        debug!("Rewriting 'url': '{}' -> '{}'", original, proxy_endpoint);
        *url = serde_json::Value::String(proxy_endpoint.to_string());
        rewrote_something = true;
    }

    // Also check for 'endpoint' field (alternate format)
    if let Some(endpoint) = agent_card.get_mut("endpoint") {
        let original = endpoint
            .as_str()
            .unwrap_or("unknown");
        debug!("Rewriting 'endpoint': '{}' -> '{}'", original, proxy_endpoint);
        *endpoint = serde_json::Value::String(proxy_endpoint.to_string());
        rewrote_something = true;
    }

    // Also check for endpoints array (some agent cards have multiple)
    if let Some(endpoints) = agent_card
        .get_mut("endpoints")
        .and_then(|e| e.as_array_mut())
    {
        for (i, endpoint) in endpoints
            .iter_mut()
            .enumerate()
        {
            if let Some(url) = endpoint.get_mut("url") {
                let original = url
                    .as_str()
                    .unwrap_or("unknown");
                debug!("Rewriting 'endpoints[{}].url': '{}' -> '{}'", i, original, proxy_endpoint);
                *url = serde_json::Value::String(proxy_endpoint.to_string());
                rewrote_something = true;
            }
        }
    }

    // (see `primary_endpoint_url` for the read-side counterpart of these fields)
    // Interface arrays that carry endpoint URLs:
    //   - A2A v1.0: `supportedInterfaces[].url` (AgentCard.supportedInterfaces →
    //     AgentInterface.url)
    //   - A2A v0.3: `additionalInterfaces[].url`
    // Both are checked in snake_case and camelCase, because cards transcoded from
    // the protobuf definition use snake_case while the JSON spec uses camelCase.
    //
    // EVERY entry must be rewritten, and every key is checked (not first-match):
    // an interface URL left pointing at the upstream would let a client reach the
    // agent directly, bypassing the gateway's auth, policy and identity injection.
    // Array order is preserved (entries are mutated in place) because in v1.0 the
    // order encodes client preference — the first entry is the preferred interface.
    for key in ["supported_interfaces", "supportedInterfaces", "additional_interfaces", "additionalInterfaces"] {
        if let Some(interfaces) = agent_card
            .get_mut(key)
            .and_then(|e| e.as_array_mut())
        {
            for (i, iface) in interfaces
                .iter_mut()
                .enumerate()
            {
                if let Some(url) = iface.get_mut("url") {
                    let original = url
                        .as_str()
                        .unwrap_or("unknown");
                    debug!("Rewriting '{}[{}].url': '{}' -> '{}'", key, i, original, proxy_endpoint);
                    *url = serde_json::Value::String(proxy_endpoint.to_string());
                    rewrote_something = true;
                }
            }
        }
    }

    if !rewrote_something {
        warn!(channel = channel_name, "No 'endpoint' or 'endpoints' field found in agent card to rewrite!");
        warn!(
            "Agent card keys: {:?}",
            agent_card
                .as_object()
                .map(|o| o.keys().collect::<Vec<_>>())
        );
    }

    rewrote_something
}

/// Inject `agentDid` and (when present) `agentDNA` from the surface's
/// did:webvh managed identity onto the agent card.
#[cfg(feature = "didwebvh")]
pub async fn inject_didwebvh_identity_into_agent_card(
    agent_card: &mut serde_json::Value,
    surface: &crate::config::agent_surface::AgentSurface,
    identity_store: Option<&std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
) {
    let (Some(did_config), Some(identity_store)) = (surface.didwebvh_identity_legacy(), identity_store) else {
        return;
    };

    match identity_store
        .get(&did_config.identity_id)
        .await
    {
        Ok(Some(identity)) => {
            if let Some(obj) = agent_card.as_object_mut() {
                obj.insert("agentDid".to_string(), serde_json::Value::String(identity.did.clone()));
                if let Some(dna_value) = identity
                    .metadata
                    .get("agentDNA")
                {
                    obj.insert("agentDNA".to_string(), dna_value.clone());
                    info!(
                        surface = %surface.name,
                        did = %identity.did,
                        "Injected agentDNA into agent card"
                    );
                }
            }
        }
        Ok(None) => {
            warn!(
                surface = %surface.name,
                identity_id = %did_config.identity_id,
                "Configured did:webvh identity not found — skipping DNA injection"
            );
        }
        Err(e) => {
            warn!(
                surface = %surface.name,
                identity_id = %did_config.identity_id,
                error = %e,
                "Failed to load did:webvh identity for agent card — skipping DNA injection"
            );
        }
    }
}

/// No-op stub used when the `didwebvh` feature is disabled, so callers can
/// thread the optional store unconditionally.
#[cfg(not(feature = "didwebvh"))]
pub async fn inject_didwebvh_identity_into_agent_card(
    _agent_card: &mut serde_json::Value,
    _surface: &crate::config::agent_surface::AgentSurface,
    _identity_store: Option<&()>,
) {
}

fn build_proxy_endpoint(
    surface: &crate::config::agent_surface::AgentSurface,
    network_config: &crate::config::NetworkConfig,
) -> String {
    let listen_address = &surface
        .access_point
        .listen_address;

    // Resolve the listener's public URL from listen_address → port → listener external_urls.
    // Falls back to webauthn.external_origin when no matching listener is found.
    let port = network_config
        .map_url_to_port(listen_address)
        .or_else(|| {
            listen_address
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
        });

    let base_url = port
        .and_then(|p| {
            network_config
                .listeners
                .iter()
                .find(|l| l.port == p)
                .and_then(|l| l.external_urls.first())
        })
        .map(|u| u.trim_end_matches('/'))
        .unwrap_or_else(|| {
            warn!(
                surface = %surface.name,
                listen_address,
                "No listener found for access point, falling back to webauthn.external_origin"
            );
            network_config
                .webauthn
                .external_origin
                .trim_end_matches('/')
        });

    if surface.access_point.route == "/"
        || surface
            .access_point
            .route
            .is_empty()
    {
        base_url.to_string()
    } else {
        format!("{}{}", base_url, surface.access_point.route)
    }
}

/// Public URL of an outbound transit point. `TransitPoint.gateway_url`
/// is declared "computed" but never assigned at runtime, so derive it from
/// the same precedence used at route registration in `surface_manager`:
/// TP `listen_address` → channel-wide `transit.outbound_listen_address` →
/// access point `listen_address`. Path is the TP's `listen_path` when set,
/// otherwise the derived `/outgoing<route>/<alias>` route.
pub(crate) fn build_transit_point_proxy_endpoint(
    surface: &crate::config::agent_surface::AgentSurface,
    tp: &crate::config::agent_surface::TransitPoint,
    network_config: &crate::config::NetworkConfig,
) -> String {
    let listen_address = tp
        .listen_address
        .as_deref()
        .or_else(|| {
            surface
                .transit
                .as_ref()
                .and_then(|t| {
                    t.outbound_listen_address
                        .as_deref()
                })
        })
        .unwrap_or(
            &surface
                .access_point
                .listen_address,
        );

    let derived_path;
    let path = match tp.listen_path.as_deref() {
        Some(p) => p,
        None => {
            derived_path = format!(
                "/outgoing{}/{}",
                surface
                    .access_point
                    .route
                    .trim_end_matches('/'),
                tp.alias,
            );
            &derived_path
        }
    };

    let port = network_config
        .map_url_to_port(listen_address)
        .or_else(|| {
            listen_address
                .rsplit(':')
                .next()
                .and_then(|p| p.parse().ok())
        })
        .unwrap_or(443);

    if let Some(base_url) = network_config
        .listeners
        .iter()
        .find(|l| l.port == port)
        .and_then(|l| l.external_urls.first())
    {
        return format!("{}{}", base_url.trim_end_matches('/'), path);
    }

    warn!("No listener found for port {}, falling back to https://{}", port, network_config.webauthn.rp_id);
    let base_url = if port == 443 || port == 80 {
        format!("https://{}", network_config.webauthn.rp_id)
    } else {
        format!("https://{}:{}", network_config.webauthn.rp_id, port)
    };
    format!("{}{}", base_url, path)
}

// Process agent card: rewrite URLs to point at the proxy.
pub async fn process_agent_card(
    body: &[u8],
    surface: &crate::config::agent_surface::AgentSurface,
    _config: &crate::config::GatewayConfig,
    network_config: &crate::config::NetworkConfig,
    _resolved_identity: &ProtectedAgentIdentity,
) -> Result<axum::body::Bytes, anyhow::Error> {
    let mut agent_card: serde_json::Value = serde_json::from_slice(body)?;

    let proxy_endpoint = build_proxy_endpoint(surface, network_config);

    info!(
        "Agent card processing: surface='{}' route='{}' proxy_endpoint='{}'",
        surface.name, surface.access_point.route, proxy_endpoint
    );

    // Log original agent card for debugging
    if let Ok(original_json) = serde_json::to_string_pretty(&agent_card) {
        debug!("Original agent card:\n{}", original_json);
    }

    rewrite_urls_in_agent_card(&mut agent_card, &proxy_endpoint, &surface.name);

    // Log processed agent card for debugging
    if let Ok(processed_json) = serde_json::to_string_pretty(&agent_card) {
        debug!("Processed agent card:\n{}", processed_json);
    }

    // Serialize back to JSON
    let processed = serde_json::to_vec(&agent_card)?;
    Ok(axum::body::Bytes::from(processed))
}

/// Rewrite agent card URLs to point to the proxy instead of the backend server.
///
/// DEPRECATED: Use `process_agent_card` instead — this function is kept for backward compatibility.
pub async fn rewrite_agent_card_urls(
    body: &[u8],
    surface: &crate::config::agent_surface::AgentSurface,
    config: &crate::config::GatewayConfig,
    network_config: &crate::config::NetworkConfig,
    resolved_identity: &ProtectedAgentIdentity,
) -> Result<axum::body::Bytes, anyhow::Error> {
    process_agent_card(body, surface, config, network_config, resolved_identity).await
}

/// Rewrite agent card URLs for the outbound pipeline.
/// `proxy_endpoint` is the outbound virtual channel's `gateway_url`.
pub fn process_outbound_agent_card(
    body: &[u8],
    proxy_endpoint: &str,
    channel_name: &str,
) -> Result<axum::body::Bytes, anyhow::Error> {
    let mut agent_card: serde_json::Value = serde_json::from_slice(body)?;

    rewrite_urls_in_agent_card(&mut agent_card, proxy_endpoint, channel_name);

    let processed = serde_json::to_vec(&agent_card)?;
    Ok(axum::body::Bytes::from(processed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PROXY_URL: &str = "https://gw.internal:9000/outgoing/channels/order/partner-a";

    // ── rewrite_urls_in_agent_card ───────────────────────────────────────

    #[test]
    fn rewrites_legacy_url_field() {
        let mut card = json!({
            "name": "Agent",
            "url": "https://partner.example.com/a2a",
            "version": "1.0.0"
        });
        let result = rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test");
        assert!(result);
        assert_eq!(card["url"], PROXY_URL);
    }

    #[test]
    fn rewrites_supported_interfaces_url() {
        let mut card = json!({
            "name": "Agent",
            "description": "Test",
            "version": "1.0.0",
            "supported_interfaces": [
                { "url": "https://partner.example.com/a2a", "protocol_binding": "JSONRPC", "protocol_version": "1.0" },
                { "url": "https://partner.example.com/grpc", "protocol_binding": "GRPC", "protocol_version": "1.0" }
            ]
        });
        let result = rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test");
        assert!(result);
        assert_eq!(card["supported_interfaces"][0]["url"], PROXY_URL);
        assert_eq!(card["supported_interfaces"][1]["url"], PROXY_URL);
    }

    #[test]
    fn rewrites_camel_case_supported_interfaces() {
        let mut card = json!({
            "name": "Agent",
            "supportedInterfaces": [
                { "url": "https://partner.example.com/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" }
            ]
        });
        let result = rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test");
        assert!(result);
        assert_eq!(card["supportedInterfaces"][0]["url"], PROXY_URL);
    }

    #[test]
    fn primary_endpoint_reads_either_era() {
        // Pure v1.0 card: no top-level `url` at all — the first interface wins.
        let v1 = json!({
            "protocolVersion": "1.0",
            "supportedInterfaces": [
                { "url": "https://agent.example.com/a2a",  "protocolBinding": "JSONRPC" },
                { "url": "https://agent.example.com/grpc", "protocolBinding": "GRPC" }
            ]
        });
        assert_eq!(primary_endpoint_url(&v1), Some("https://agent.example.com/a2a"));

        // Pure v0.3 card.
        let v0_3 = json!({ "protocolVersion": "0.3", "url": "https://legacy.example.com/a2a" });
        assert_eq!(primary_endpoint_url(&v0_3), Some("https://legacy.example.com/a2a"));

        // Dual-emitted card: the 1.0 shape is preferred over the legacy field.
        let dual = json!({
            "url": "https://legacy.example.com/a2a",
            "supportedInterfaces": [{ "url": "https://new.example.com/a2a" }]
        });
        assert_eq!(primary_endpoint_url(&dual), Some("https://new.example.com/a2a"));

        // snake_case (protobuf-transcoded) and the other v0.x spellings.
        let snake = json!({ "supported_interfaces": [{ "url": "https://snake.example.com/a2a" }] });
        assert_eq!(primary_endpoint_url(&snake), Some("https://snake.example.com/a2a"));
        let endpoint = json!({ "endpoint": "https://ep.example.com/a2a" });
        assert_eq!(primary_endpoint_url(&endpoint), Some("https://ep.example.com/a2a"));
        let endpoints = json!({ "endpoints": [{ "url": "https://eps.example.com/a2a" }] });
        assert_eq!(primary_endpoint_url(&endpoints), Some("https://eps.example.com/a2a"));

        // Nothing to read.
        assert_eq!(primary_endpoint_url(&json!({ "name": "no endpoint" })), None);
        assert_eq!(primary_endpoint_url(&json!({ "supportedInterfaces": [] })), None);
    }

    #[test]
    fn rewrites_every_interface_and_preserves_order() {
        // In v1.0 the order of `supportedInterfaces[]` encodes client preference —
        // the first entry is the preferred one — so rewriting must not reorder it.
        let mut card = json!({
            "name": "Agent",
            "supportedInterfaces": [
                { "url": "https://partner.example.com/a2a",  "protocolBinding": "JSONRPC", "protocolVersion": "1.0" },
                { "url": "https://partner.example.com/grpc", "protocolBinding": "GRPC",    "protocolVersion": "1.0" },
                { "url": "https://partner.example.com/rest", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0" }
            ]
        });
        assert!(rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test"));

        let ifaces = card["supportedInterfaces"]
            .as_array()
            .expect("interfaces array");
        assert_eq!(ifaces.len(), 3, "no entries added or dropped");
        // Every URL rewritten...
        for iface in ifaces {
            assert_eq!(iface["url"], PROXY_URL);
        }
        // ...and the bindings stay in their original order.
        assert_eq!(ifaces[0]["protocolBinding"], "JSONRPC");
        assert_eq!(ifaces[1]["protocolBinding"], "GRPC");
        assert_eq!(ifaces[2]["protocolBinding"], "HTTP+JSON");
    }

    #[test]
    fn rewrites_v0_3_additional_interfaces() {
        // v0.3 cards carry extra endpoints in `additionalInterfaces[]`. Leaving any
        // of them un-rewritten would let a client reach the upstream directly,
        // bypassing the gateway's auth and policy.
        let mut card = json!({
            "name": "Legacy Agent",
            "url": "https://legacy.example.com/a2a",
            "preferredTransport": "JSONRPC",
            "additionalInterfaces": [
                { "url": "https://legacy.example.com/grpc", "transport": "GRPC" },
                { "url": "https://legacy.example.com/rest", "transport": "HTTP+JSON" }
            ]
        });
        assert!(rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test"));

        assert_eq!(card["url"], PROXY_URL);
        assert_eq!(card["additionalInterfaces"][0]["url"], PROXY_URL);
        assert_eq!(card["additionalInterfaces"][1]["url"], PROXY_URL);
    }

    #[test]
    fn rewrites_both_interface_key_spellings_when_both_present() {
        // A transcoded card can carry both spellings; first-match-only would leak
        // the upstream URL through whichever key was skipped.
        let mut card = json!({
            "name": "Agent",
            "supported_interfaces": [{ "url": "https://partner.example.com/snake" }],
            "supportedInterfaces": [{ "url": "https://partner.example.com/camel" }]
        });
        assert!(rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test"));

        assert_eq!(card["supported_interfaces"][0]["url"], PROXY_URL);
        assert_eq!(card["supportedInterfaces"][0]["url"], PROXY_URL);
    }

    #[test]
    fn no_upstream_url_survives_a_rewrite() {
        // Guard: after rewriting, the serialized card must not mention the upstream
        // origin anywhere a client could dial. Catches a newly-added URL-bearing
        // field that the rewriter does not yet know about.
        let mut card = json!({
            "name": "Agent",
            "url": "https://partner.example.com/a2a",
            "endpoint": "https://partner.example.com/ep",
            "endpoints": [{ "url": "https://partner.example.com/e1" }],
            "supportedInterfaces": [{ "url": "https://partner.example.com/i1" }],
            "additionalInterfaces": [{ "url": "https://partner.example.com/i2" }]
        });
        assert!(rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test"));

        let serialized = serde_json::to_string(&card).expect("serialize");
        assert!(!serialized.contains("partner.example.com"), "an upstream URL survived the rewrite: {serialized}");
    }

    #[test]
    fn preserves_upstream_protocol_version_on_rewrite() {
        // For a managed-agent surface the served card is the upstream's card,
        // rewritten. Its `protocolVersion` is the UPSTREAM's own and must never be
        // overridden with the gateway's advertised version — a 0.3 managed agent
        // keeps advertising 0.3 so callers know which era to speak.
        let mut card = json!({
            "protocolVersion": "0.3",
            "name": "Legacy Agent",
            "url": "https://legacy.example.com/a2a",
            "preferredTransport": "JSONRPC"
        });
        let result = rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test");
        assert!(result);
        // URL is rewritten to the gateway...
        assert_eq!(card["url"], PROXY_URL);
        // ...but the upstream's advertised version is untouched.
        assert_eq!(card["protocolVersion"], "0.3");
        assert_ne!(card["protocolVersion"], crate::a2a::ADVERTISED_VERSION);
    }

    #[test]
    fn rewrites_mixed_legacy_and_v1_fields() {
        let mut card = json!({
            "name": "Agent",
            "url": "https://old.example.com",
            "supported_interfaces": [
                { "url": "https://new.example.com/a2a", "protocol_binding": "JSONRPC", "protocol_version": "1.0" }
            ]
        });
        let result = rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test");
        assert!(result);
        assert_eq!(card["url"], PROXY_URL);
        assert_eq!(card["supported_interfaces"][0]["url"], PROXY_URL);
    }

    #[test]
    fn returns_false_when_no_url_fields() {
        let mut card = json!({
            "name": "Agent",
            "version": "1.0.0"
        });
        let result = rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test");
        assert!(!result);
    }

    // ── upstream authority leak guard ────────────────────────────────────

    const UPSTREAM_HOST: &str = "agent.internal";
    const UPSTREAM_DOCS_URL: &str = "https://Agent.Internal:8443/docs";
    const UPSTREAM_PROVIDER_URL: &str = "https://AGENT.INTERNAL:8443/";

    const ENDPOINT_INTERFACE_KEYS: [&str; 4] =
        ["supportedInterfaces", "supported_interfaces", "additionalInterfaces", "additional_interfaces"];

    fn mentions_upstream(value: &str) -> bool {
        value
            .to_ascii_lowercase()
            .contains(UPSTREAM_HOST)
    }

    fn endpoint_field_values(card: &serde_json::Value) -> Vec<(String, serde_json::Value)> {
        let mut found = Vec::new();
        for key in ["url", "endpoint"] {
            if let Some(v) = card.get(key) {
                found.push((format!("/{key}"), v.clone()));
            }
        }
        for key in std::iter::once("endpoints").chain(ENDPOINT_INTERFACE_KEYS) {
            if let Some(entries) = card
                .get(key)
                .and_then(|v| v.as_array())
            {
                for (i, entry) in entries.iter().enumerate() {
                    if let Some(v) = entry.get("url") {
                        found.push((format!("/{key}/{i}/url"), v.clone()));
                    }
                }
            }
        }
        found
    }

    fn assert_endpoint_fields_point_at_proxy(
        card: &serde_json::Value,
        expected_count: usize,
    ) {
        let fields = endpoint_field_values(card);
        assert_eq!(fields.len(), expected_count, "endpoint fields found: {fields:?}");
        for (path, value) in &fields {
            let s = value
                .as_str()
                .unwrap_or_else(|| panic!("{path} is not a string: {value}"));
            assert!(!mentions_upstream(s), "{path} still names the upstream: {s}");
            assert_eq!(s, PROXY_URL, "{path} was not rewritten to the proxy endpoint");
        }
    }

    fn collect_upstream_paths(
        value: &serde_json::Value,
        path: &str,
        out: &mut std::collections::BTreeSet<String>,
    ) {
        match value {
            serde_json::Value::String(s) if mentions_upstream(s) => {
                out.insert(path.to_string());
            }
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    collect_upstream_paths(item, &format!("{path}/{i}"), out);
                }
            }
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    collect_upstream_paths(v, &format!("{path}/{k}"), out);
                }
            }
            _ => {}
        }
    }

    fn upstream_paths(card: &serde_json::Value) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        collect_upstream_paths(card, "", &mut out);
        out
    }

    fn v0_3_upstream_card() -> serde_json::Value {
        json!({
            "protocolVersion": "0.3",
            "name": "Legacy Agent",
            "url": "https://Agent.Internal:8443/a2a",
            "preferredTransport": "JSONRPC",
            "additionalInterfaces": [
                { "url": "HTTPS://AGENT.INTERNAL:8443/grpc", "transport": "GRPC" },
                { "url": "https://agent.internal:8443/rest", "transport": "HTTP+JSON" }
            ],
            "additional_interfaces": [
                { "url": "https://Agent.Internal:8443/snake", "transport": "JSONRPC" }
            ],
            "documentationUrl": UPSTREAM_DOCS_URL,
            "provider": { "organization": "Upstream Co", "url": UPSTREAM_PROVIDER_URL }
        })
    }

    fn v1_0_upstream_card() -> serde_json::Value {
        json!({
            "protocolVersion": "1.0",
            "name": "Agent",
            "supportedInterfaces": [
                { "url": "https://Agent.Internal:8443/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0" },
                { "url": "HTTPS://AGENT.INTERNAL:8443/grpc", "protocolBinding": "GRPC", "protocolVersion": "1.0" }
            ],
            "supported_interfaces": [
                { "url": "https://agent.internal:8443/rest", "protocol_binding": "HTTP+JSON", "protocol_version": "1.0" }
            ],
            "endpoint": "https://Agent.Internal:8443/ep",
            "endpoints": [
                { "url": "https://Agent.Internal:8443/e1" },
                { "url": "https://agent.internal/e2" }
            ],
            "documentationUrl": UPSTREAM_DOCS_URL,
            "provider": { "organization": "Upstream Co", "url": UPSTREAM_PROVIDER_URL }
        })
    }

    fn assert_only_non_endpoint_fields_keep_upstream(card: &serde_json::Value) {
        let expected: std::collections::BTreeSet<String> = ["/documentationUrl", "/provider/url"]
            .into_iter()
            .map(String::from)
            .collect();
        let actual = upstream_paths(card);
        assert_eq!(actual, expected, "upstream authority found at unexpected paths: {actual:?}");
        assert_eq!(card["documentationUrl"], UPSTREAM_DOCS_URL);
        assert_eq!(card["provider"]["url"], UPSTREAM_PROVIDER_URL);
        assert_eq!(card["provider"]["organization"], "Upstream Co");
    }

    #[test]
    fn leak_guard_fixtures_start_with_upstream_in_every_endpoint_field() {
        let v0_3 = v0_3_upstream_card();
        let v1_0 = v1_0_upstream_card();
        assert_eq!(upstream_paths(&v0_3).len(), 6);
        assert_eq!(upstream_paths(&v1_0).len(), 8);
        for (path, value) in endpoint_field_values(&v0_3)
            .into_iter()
            .chain(endpoint_field_values(&v1_0))
        {
            assert!(mentions_upstream(value.as_str().unwrap()), "fixture field {path} must name the upstream");
        }
    }

    #[test]
    fn v0_3_card_rewrite_leaves_no_upstream_in_endpoint_fields() {
        let mut card = v0_3_upstream_card();
        assert!(rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test"));

        assert_endpoint_fields_point_at_proxy(&card, 4);
        assert_eq!(card["preferredTransport"], "JSONRPC");
        assert_eq!(card["additionalInterfaces"][0]["transport"], "GRPC");
        assert_eq!(card["additionalInterfaces"][1]["transport"], "HTTP+JSON");
        assert_eq!(card["protocolVersion"], "0.3");
    }

    #[test]
    fn v1_0_card_rewrite_leaves_no_upstream_in_endpoint_fields() {
        let mut card = v1_0_upstream_card();
        assert!(rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test"));

        assert_endpoint_fields_point_at_proxy(&card, 6);
        assert_eq!(card["supportedInterfaces"][0]["protocolBinding"], "JSONRPC");
        assert_eq!(card["supportedInterfaces"][1]["protocolBinding"], "GRPC");
        assert_eq!(card["supported_interfaces"][0]["protocol_binding"], "HTTP+JSON");
        assert_eq!(card["protocolVersion"], "1.0");
    }

    #[test]
    fn rewrite_keeps_upstream_only_in_documentation_and_provider_urls() {
        for mut card in [v0_3_upstream_card(), v1_0_upstream_card()] {
            assert!(rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test"));
            assert_only_non_endpoint_fields_keep_upstream(&card);
        }
    }

    #[test]
    fn process_outbound_leaves_upstream_only_in_non_endpoint_fields() {
        for card in [v0_3_upstream_card(), v1_0_upstream_card()] {
            let body = serde_json::to_vec(&card).expect("serialize fixture");
            let bytes = process_outbound_agent_card(&body, PROXY_URL, "test-channel").expect("rewrite");
            let rewritten: serde_json::Value = serde_json::from_slice(&bytes).expect("rewritten card is JSON");

            let expected_endpoint_fields = endpoint_field_values(&card).len();
            assert_endpoint_fields_point_at_proxy(&rewritten, expected_endpoint_fields);
            assert_only_non_endpoint_fields_keep_upstream(&rewritten);
        }
    }

    #[test]
    fn card_with_only_non_endpoint_upstream_urls_is_left_unchanged() {
        let original = json!({
            "name": "Docs Only",
            "documentationUrl": UPSTREAM_DOCS_URL,
            "provider": { "organization": "Upstream Co", "url": UPSTREAM_PROVIDER_URL }
        });
        let mut card = original.clone();
        assert!(!rewrite_urls_in_agent_card(&mut card, PROXY_URL, "test"));
        assert_eq!(card, original);
    }

    // ── process_outbound_agent_card ──────────────────────────────────────

    #[test]
    fn process_outbound_rewrites_v1_card() {
        let card = json!({
            "name": "Partner A",
            "description": "Test",
            "version": "1.0.0",
            "supported_interfaces": [
                { "url": "https://partner-a.example.com/a2a", "protocol_binding": "JSONRPC", "protocol_version": "1.0" }
            ]
        });
        let body = serde_json::to_vec(&card).unwrap();

        let result = process_outbound_agent_card(&body, PROXY_URL, "test-channel").unwrap();
        let rewritten: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(rewritten["supported_interfaces"][0]["url"], PROXY_URL);
        assert_eq!(rewritten["name"], "Partner A");
    }

    #[test]
    fn process_outbound_rewrites_legacy_card() {
        let card = json!({
            "name": "Partner A",
            "url": "https://partner-a.example.com/a2a",
            "version": "1.0.0"
        });
        let body = serde_json::to_vec(&card).unwrap();

        let result = process_outbound_agent_card(&body, PROXY_URL, "test-channel").unwrap();
        let rewritten: serde_json::Value = serde_json::from_slice(&result).unwrap();

        assert_eq!(rewritten["url"], PROXY_URL);
    }

    #[test]
    fn process_outbound_returns_error_on_invalid_json() {
        let result = process_outbound_agent_card(b"not json", PROXY_URL, "test-channel");
        assert!(result.is_err());
    }

    // ── build_proxy_endpoint ─────────────────────────────────────────────

    fn make_network_config(listeners_json: serde_json::Value) -> crate::config::NetworkConfig {
        make_network_config_with_origin(listeners_json, "https://localhost")
    }

    fn make_network_config_with_origin(
        listeners_json: serde_json::Value,
        external_origin: &str,
    ) -> crate::config::NetworkConfig {
        let cfg = json!({
            "did": { "domain": "test.local" },
            "webauthn": { "rp_id": "localhost", "external_origin": external_origin },
            "integration": { "types": [], "categories": [] },
            "listeners": listeners_json,
            "routes": {},
        });
        serde_json::from_value(cfg).expect("test network config should deserialize")
    }

    fn make_surface(
        listen_address: &str,
        route: &str,
    ) -> crate::config::agent_surface::AgentSurface {
        let cfg = json!({
            "name": "test-surface",
            "access_point": {
                "listen_address": listen_address,
                "route": route,
                "protocol": "a2a",
            },
            "target": { "endpoint": "http://localhost:9001" },
        });
        serde_json::from_value(cfg).expect("test surface should deserialize")
    }

    /// AccessPoint agent cards use the listener's first external_url as
    /// the public base URL for the agent card.
    #[test]
    fn build_proxy_endpoint_uses_listener_external_url() {
        let net = make_network_config_with_origin(
            json!([
                {
                    "id": "in", "name": "in",
                    "bind_address": "0.0.0.0", "port": 8080,
                    "protocol": "http",
                    "external_urls": ["http://localhost:8080"],
                    "listener_type": "inbound"
                }
            ]),
            "https://webauthn.example.com",
        );
        let surface = make_surface("0.0.0.0:8080", "/agents/a2a/buyer");
        assert_eq!(build_proxy_endpoint(&surface, &net), "http://localhost:8080/agents/a2a/buyer");
    }

    /// When a listener has multiple external_urls, the first one is used.
    #[test]
    fn build_proxy_endpoint_uses_first_external_url() {
        let net = make_network_config_with_origin(
            json!([
                {
                    "id": "in", "name": "in",
                    "bind_address": "0.0.0.0", "port": 8080,
                    "protocol": "http",
                    "external_urls": ["https://agent-gateway-1.example.com", "http://localhost:8080"],
                    "listener_type": "inbound"
                }
            ]),
            "https://gw.example.com",
        );
        let surface = make_surface("0.0.0.0:8080", "/agents/a2a/buyer");
        assert_eq!(build_proxy_endpoint(&surface, &net), "https://agent-gateway-1.example.com/agents/a2a/buyer");
    }

    /// When no listener matches, falls back to webauthn.external_origin.
    #[test]
    fn build_proxy_endpoint_falls_back_to_external_origin() {
        let net = make_network_config_with_origin(json!([]), "https://gw.example.com/");
        let surface = make_surface("0.0.0.0:8080", "/agents/a2a/buyer");
        assert_eq!(build_proxy_endpoint(&surface, &net), "https://gw.example.com/agents/a2a/buyer");
    }

    /// Root route ("/" or empty) collapses to the bare base URL.
    #[test]
    fn build_proxy_endpoint_handles_root_route() {
        let net = make_network_config_with_origin(
            json!([
                {
                    "id": "in", "name": "in",
                    "bind_address": "0.0.0.0", "port": 8080,
                    "protocol": "http",
                    "external_urls": ["https://gw.example.com"],
                    "listener_type": "inbound"
                }
            ]),
            "https://fallback.example.com",
        );
        let surface = make_surface("0.0.0.0:8080", "/");
        assert_eq!(build_proxy_endpoint(&surface, &net), "https://gw.example.com");
    }

    // ── build_transit_point_proxy_endpoint ───────────────────────────────

    fn make_surface_with_tp(
        ap_listen: &str,
        route: &str,
        outbound_listen: Option<&str>,
        tp_listen: Option<&str>,
        tp_path: Option<&str>,
        tp_alias: &str,
    ) -> crate::config::agent_surface::AgentSurface {
        let mut tp = json!({
            "alias": tp_alias,
            "target_endpoint": "http://seller.test:9100",
        });
        if let Some(la) = tp_listen {
            tp.as_object_mut()
                .unwrap()
                .insert("listen_address".into(), json!(la));
        }
        if let Some(p) = tp_path {
            tp.as_object_mut()
                .unwrap()
                .insert("listen_path".into(), json!(p));
        }
        let mut transit = json!({ "points": [tp] });
        if let Some(out) = outbound_listen {
            transit
                .as_object_mut()
                .unwrap()
                .insert("outbound_listen_address".into(), json!(out));
        }
        let cfg = json!({
            "name": "test-surface",
            "access_point": {
                "listen_address": ap_listen,
                "route": route,
                "protocol": "a2a",
            },
            "target": { "endpoint": "http://localhost:9001" },
            "transit": transit,
        });
        serde_json::from_value(cfg).expect("test surface should deserialize")
    }

    /// TP overrides win and `listen_path` is appended to the matching
    /// listener's external URL — matches the seller TP shape from
    /// `local-setup/endpoints.json`
    /// (`https://localhost:9000/agents/tp-seller-a2a`).
    #[test]
    fn tp_proxy_endpoint_uses_tp_listen_address_and_path() {
        let net = make_network_config(json!([
            {
                "id": "out", "name": "out",
                "bind_address": "127.0.0.1", "port": 9000,
                "protocol": "https",
                "external_urls": ["https://localhost:9000"],
                "listener_type": "outbound"
            }
        ]));
        let surface = make_surface_with_tp(
            "0.0.0.0:8443",
            "/agents/a2a/buyer",
            None,
            Some("https://localhost:9000"),
            Some("/agents/tp-seller-a2a"),
            "tp-seller-a2a",
        );
        let tp = &surface
            .transit
            .as_ref()
            .unwrap()
            .points[0];
        assert_eq!(
            build_transit_point_proxy_endpoint(&surface, tp, &net),
            "https://localhost:9000/agents/tp-seller-a2a"
        );
    }

    /// No TP override → fall through to channel-wide
    /// `transit.outbound_listen_address`; no `listen_path` →
    /// `/outgoing<route>/<alias>` is derived.
    #[test]
    fn tp_proxy_endpoint_falls_back_to_outbound_listen_and_derived_path() {
        let net = make_network_config(json!([
            {
                "id": "out", "name": "out",
                "bind_address": "127.0.0.1", "port": 9000,
                "protocol": "https",
                "external_urls": ["https://localhost:9000"],
                "listener_type": "outbound"
            }
        ]));
        let surface = make_surface_with_tp(
            "0.0.0.0:8443",
            "/agents/a2a/buyer",
            Some("https://localhost:9000"),
            None,
            None,
            "tp-seller",
        );
        let tp = &surface
            .transit
            .as_ref()
            .unwrap()
            .points[0];
        assert_eq!(
            build_transit_point_proxy_endpoint(&surface, tp, &net),
            "https://localhost:9000/outgoing/agents/a2a/buyer/tp-seller"
        );
    }

    /// When neither the TP nor the channel-wide outbound override is set,
    /// the access point's `listen_address` is used as the final base.
    #[test]
    fn tp_proxy_endpoint_falls_back_to_access_point_listen_address() {
        let net = make_network_config(json!([
            {
                "id": "in", "name": "in",
                "bind_address": "0.0.0.0", "port": 8080,
                "protocol": "http",
                "external_urls": ["http://localhost:8080"],
                "listener_type": "inbound"
            }
        ]));
        let surface = make_surface_with_tp("0.0.0.0:8080", "/agents/a2a/buyer", None, None, None, "tp-seller");
        let tp = &surface
            .transit
            .as_ref()
            .unwrap()
            .points[0];
        assert_eq!(
            build_transit_point_proxy_endpoint(&surface, tp, &net),
            "http://localhost:8080/outgoing/agents/a2a/buyer/tp-seller"
        );
    }
}
