use std::sync::Arc;

use serde_json::{Value, json};

use crate::config::agent_surface::AgentSurface;
use crate::proxy::backend_identity::ProtectedAgentIdentity;

use super::types::A2aProxy;

pub struct PreparedA2aProxyAgentCard {
    pub card: Value,
    pub identity: Option<ProtectedAgentIdentity>,
}

pub async fn prepare_agent_card(
    proxy: &A2aProxy,
    surface: &AgentSurface,
    vc_issuer: Option<&Arc<crate::identity::VCIssuer>>,
    channel_name: &str,
) -> anyhow::Result<PreparedA2aProxyAgentCard> {
    let mut card = synthesize_agent_card(proxy, surface);
    let identity = super::identity::resolve_synthetic_identity(proxy, surface, vc_issuer).await?;

    if let (Some(identity @ ProtectedAgentIdentity::Managed { .. }), Some(vc_issuer)) = (identity.as_ref(), vc_issuer) {
        crate::a2a::upsert_credential_into_agent_card(&mut card, identity, vc_issuer, channel_name).await?;
    }

    Ok(PreparedA2aProxyAgentCard { card, identity })
}

pub fn synthesize_agent_card(
    proxy: &A2aProxy,
    surface: &AgentSurface,
) -> Value {
    let name = proxy
        .agent_card
        .as_ref()
        .and_then(|profile| profile.name.as_deref())
        .unwrap_or(surface.name.as_str());
    let description = proxy
        .agent_card
        .as_ref()
        .and_then(|profile| profile.description.as_deref())
        .unwrap_or(surface.description.as_str());
    let url = surface_a2a_endpoint_url(surface);
    let provider = json!({ "organization": "Affinidi", "url": "https://affinidi.com" });
    // This proxy translates one operation and serves no extended card.
    let extended_agent_card = false;
    // An A2A-proxy surface serves A2A 1.0 only, so the card is a 1.0 card.
    let accepted = surface
        .a2a_settings()
        .accepted_versions;

    let mut card = json!({
        "name": name,
        "description": description,
        // A2A 1.0 renamed `agentProvider` → `provider`.
        "provider": provider.clone(),
        "version": "1.0.0",
        "capabilities": {
            "streaming": false,
            "pushNotifications": false,
            // A2A 1.0 moved `supportsAuthenticatedExtendedCard` here and removed
            // `stateTransitionHistory` entirely.
            "extendedAgentCard": extended_agent_card,
            "extensions": []
        },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [{
            "id": "message-send-text",
            "name": "Text SendMessage",
            "description": "Accepts non-streaming A2A SendMessage requests with text parts",
            "tags": ["a2a-proxy", "message-send", "text"],
            "examples": ["Send a text message"],
            "inputModes": ["text/plain"],
            "outputModes": ["text/plain"]
        }],
        // A2A 1.0: `url` + `preferredTransport` + `additionalInterfaces` collapse into
        // one ordered `supportedInterfaces[]`; the first entry is the preferred one,
        // and `transport` became `protocolBinding`.
        "supportedInterfaces": crate::a2a::version::generated_supported_interfaces(&url, accepted),
    });

    // Legacy v0.3 fields, emitted only when the surface accepts v0.3, which an
    // A2A-proxy surface never does.
    if let Some(legacy) = crate::a2a::version::legacy_v0_3_card_fields(&url, &provider, extended_agent_card, accepted)
        && let Some(object) = card.as_object_mut()
    {
        object.extend(legacy);
    }

    card
}

fn surface_a2a_endpoint_url(surface: &AgentSurface) -> String {
    let base = public_access_point_base(surface);
    let route = surface
        .access_point
        .route
        .trim();
    let route = if route.is_empty() || route == "/" {
        String::new()
    } else if route.starts_with('/') {
        route
            .trim_end_matches('/')
            .to_string()
    } else {
        format!("/{}", route.trim_end_matches('/'))
    };
    format!("{base}{route}/rpc")
}

fn public_access_point_base(surface: &AgentSurface) -> String {
    let listen_address = surface
        .access_point
        .listen_address
        .trim_end_matches('/');
    if listen_address.starts_with("http://") || listen_address.starts_with("https://") {
        listen_address.to_string()
    } else {
        format!("https://{listen_address}")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::a2a_proxies::types::{
        A2aProxy, A2aProxyAgentCardProfile, A2aProxyBackend, A2aProxyStatus, CopilotDirectLineBackend,
    };

    fn proxy(agent_card: Option<A2aProxyAgentCardProfile>) -> A2aProxy {
        A2aProxy {
            id: "worker".to_string(),
            tenant_id: None,
            name: "Worker".to_string(),
            description: "Worker proxy".to_string(),
            status: A2aProxyStatus::Active,
            backend: A2aProxyBackend::CopilotDirectLine(CopilotDirectLineBackend {
                secret_id: "secret".to_string(),
                credential_mode: Default::default(),
                base_url: "https://directline.example".to_string(),
                timeout_secs: 30,
                poll_interval_ms: 500,
                max_poll_attempts: 60,
            }),
            agent_card,
            agent_identity: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn surface() -> AgentSurface {
        serde_json::from_value(json!({
            "name": "Surface Agent",
            "description": "Surface description",
            "access_point": {
                "listen_address": "https://gateway.example",
                "route": "/example",
                "protocol": "a2a"
            },
            "target": { "endpoint": "a2a-proxy://worker" }
        }))
        .expect("surface fixture")
    }

    #[test]
    fn synthesized_card_uses_proxy_profile_when_present() {
        let card = synthesize_agent_card(
            &proxy(Some(A2aProxyAgentCardProfile {
                name: Some("Worker Card".to_string()),
                description: Some("Worker card description".to_string()),
            })),
            &surface(),
        );

        assert_eq!(card["name"], "Worker Card");
        assert_eq!(card["description"], "Worker card description");
        assert_eq!(card["supportedInterfaces"][0]["url"], "https://gateway.example/example/rpc");
        assert_eq!(card["capabilities"]["streaming"], false);
        assert_eq!(card["skills"][0]["id"], "message-send-text");
    }

    #[test]
    fn synthesized_card_falls_back_to_surface_fields() {
        let card = synthesize_agent_card(&proxy(None), &surface());

        assert_eq!(card["name"], "Surface Agent");
        assert_eq!(card["description"], "Surface description");
        assert_eq!(card["supportedInterfaces"][0]["url"], "https://gateway.example/example/rpc");
    }

    /// An A2A-proxy surface serves A2A 1.0 only, so its card is a 1.0 card: one
    /// JSONRPC interface at 1.0 and none of the v0.3 fields.
    #[test]
    fn synthesized_card_is_an_a2a_1_0_only_card() {
        let card = synthesize_agent_card(&proxy(None), &surface());

        // 1.0 collapses the transport fields into one ordered `supportedInterfaces[]`,
        // in camelCase, with `protocolBinding` (not `transport`) and a per-interface
        // version. The binding for the `/rpc` endpoint is JSONRPC, never HTTP+JSON
        // (which is the REST binding's label).
        assert_eq!(
            card["supportedInterfaces"],
            json!([{
                "url": "https://gateway.example/example/rpc",
                "protocolBinding": crate::a2a::version::PROTOCOL_BINDING_JSONRPC,
                "protocolVersion": "1.0"
            }])
        );

        // No v0.3 field, including the top-level version that 1.0 moved onto
        // each interface.
        for legacy in
            ["protocolVersion", "url", "preferredTransport", "agentProvider", "supportsAuthenticatedExtendedCard"]
        {
            assert!(card.get(legacy).is_none(), "`{legacy}` is a v0.3 card field, got {card}");
        }

        // The 1.0 spellings of the renamed and relocated fields.
        assert_eq!(card["provider"]["organization"], "Affinidi");
        assert_eq!(card["capabilities"]["extendedAgentCard"], false);
        assert!(
            card["capabilities"]["stateTransitionHistory"].is_null(),
            "`stateTransitionHistory` was removed in 1.0"
        );

        // Skills must carry `tags` (required in 1.0) and name the 1.0 method.
        assert!(
            card["skills"][0]["tags"]
                .as_array()
                .is_some_and(|t| !t.is_empty()),
            "skill `tags` are required in 1.0"
        );
        assert_eq!(card["skills"][0]["name"], "Text SendMessage");

        // The gateway never signs the cards it generates.
        assert!(card["signatures"].is_null());
    }

    #[test]
    fn synthesized_card_stays_1_0_only_when_0_3_is_the_configured_default_version() {
        if !crate::a2a::version::run_isolated_from_other_tests() {
            return;
        }
        crate::a2a::version::init_advertised_version("0.3");
        assert_eq!(crate::a2a::version::advertised_version(), "0.3");

        let card = synthesize_agent_card(&proxy(None), &surface());

        assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "1.0");
        assert_eq!(
            card["supportedInterfaces"]
                .as_array()
                .map(Vec::len),
            Some(1),
            "the surface refuses 0.3, so the card must not name it"
        );
        assert!(
            card.get("protocolVersion")
                .is_none()
        );
    }

    #[test]
    fn synthesized_card_stays_1_0_only_whatever_the_surface_stores() {
        let mut surface = surface();
        surface.access_point.a2a = Some(crate::config::agent_surface::A2aAccessPointSettings {
            accepted_versions: vec!["0.3".to_string()],
            validation: crate::config::agent_surface::A2aValidation::Full,
        });

        let card = synthesize_agent_card(&proxy(None), &surface);

        assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "1.0");
        assert!(card.get("url").is_none());
    }
}
