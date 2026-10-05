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

    let mut card = json!({
        // Single source of truth for the advertised A2A version — never a literal.
        "protocolVersion": crate::a2a::effective_advertised_version(),
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
            "name": "Text message/send",
            "description": "Accepts non-streaming A2A message/send requests with text parts",
            "tags": ["a2a-proxy", "message-send", "text"],
            "examples": ["Send a text message"],
            "inputModes": ["text/plain"],
            "outputModes": ["text/plain"]
        }],
        // A2A 1.0: `url` + `preferredTransport` + `additionalInterfaces` collapse into
        // one ordered `supportedInterfaces[]`; the first entry is the preferred one,
        // and `transport` became `protocolBinding`. Every protocol version the
        // gateway accepts is listed, so a v0.3 caller can discover it is served.
        "supportedInterfaces": crate::a2a::version::generated_supported_interfaces(&url),
    });

    // Legacy v0.3 fields, emitted only while the gateway still accepts v0.3 —
    // otherwise the card would advertise an entry point it refuses.
    if let Some(legacy) = crate::a2a::version::legacy_v0_3_card_fields(&url, &provider, extended_agent_card)
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
        assert_eq!(card["url"], "https://gateway.example/example/rpc");
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

    #[test]
    fn synthesized_card_advertises_1_0_when_no_version_is_configured() {
        let card = synthesize_agent_card(&proxy(None), &surface());

        assert_eq!(card["protocolVersion"], "1.0");
        assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "1.0");
    }

    #[test]
    fn synthesized_card_advertises_the_configured_version() {
        if !crate::a2a::version::run_isolated_from_other_tests() {
            return;
        }
        crate::a2a::version::init_advertised_version("0.3");

        let card = synthesize_agent_card(&proxy(None), &surface());

        assert_eq!(card["protocolVersion"], "0.3");
        assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "0.3");
        assert_eq!(card["supportedInterfaces"][1]["protocolVersion"], "1.0");
    }

    #[test]
    fn synthesized_card_is_valid_a2a_1_0() {
        let card = synthesize_agent_card(&proxy(None), &surface());

        // Version comes from the single source of truth.
        assert_eq!(card["protocolVersion"], crate::a2a::effective_advertised_version());

        // 1.0 collapses the transport fields into one ordered `supportedInterfaces[]`,
        // in camelCase, with `protocolBinding` (not `transport`) and a per-interface
        // version. The binding for the `/rpc` endpoint is JSONRPC, never HTTP+JSON
        // (which is the REST binding's label).
        let iface = &card["supportedInterfaces"][0];
        assert_eq!(iface["url"], "https://gateway.example/example/rpc");
        assert_eq!(iface["protocolBinding"], crate::a2a::version::PROTOCOL_BINDING_JSONRPC);
        assert_eq!(iface["protocolVersion"], crate::a2a::effective_advertised_version());

        // Every version the gateway accepts is discoverable from the card, so a
        // v0.3 caller is not misled into thinking only 1.0 is served.
        let listed: Vec<&str> = card["supportedInterfaces"]
            .as_array()
            .expect("supportedInterfaces should be an array")
            .iter()
            .map(|i| {
                i["protocolVersion"]
                    .as_str()
                    .unwrap()
            })
            .collect();
        for version in crate::a2a::version::accepted_versions() {
            assert!(listed.contains(version), "accepted version {version} must be advertised, got {listed:?}");
        }
        assert!(iface["transport"].is_null(), "`transport` was renamed to `protocolBinding` in 1.0");

        // Renamed / relocated / removed fields.
        // The 1.0 spellings are canonical.
        assert_eq!(card["provider"]["organization"], "Affinidi");
        assert_eq!(card["capabilities"]["extendedAgentCard"], false);

        // While legacy compatibility is on, the v0.3 spellings are emitted too,
        // so a v0.3 reader gets a card it can act on rather than one it can only
        // partially parse. They track the 1.0 values rather than being hardcoded.
        assert_eq!(card["agentProvider"], card["provider"]);
        assert_eq!(card["supportsAuthenticatedExtendedCard"], card["capabilities"]["extendedAgentCard"]);

        // Removed outright in 1.0 with no successor, so it is not resurrected.
        assert!(
            card["capabilities"]["stateTransitionHistory"].is_null(),
            "`stateTransitionHistory` was removed in 1.0"
        );

        // Skills must carry `tags` (required in 1.0).
        assert!(
            card["skills"][0]["tags"]
                .as_array()
                .is_some_and(|t| !t.is_empty()),
            "skill `tags` are required in 1.0"
        );

        // Legacy v0.3 fields stay dual-emitted so a 0.3 client can still reach the
        // endpoint during the deprecation window.
        assert_eq!(card["url"], "https://gateway.example/example/rpc");
        assert_eq!(card["preferredTransport"], crate::a2a::version::PROTOCOL_BINDING_JSONRPC);

        // The gateway never signs the cards it generates.
        assert!(card["signatures"].is_null());
    }

    #[test]
    fn synthesized_card_is_1_0_only_when_legacy_compatibility_is_off() {
        if !crate::a2a::version::run_isolated_from_other_tests() {
            return;
        }
        use crate::storage::settings_store::{DashboardSettings, SettingsStore, set_global_settings_store};

        let store = SettingsStore::new("unused-settings-dir");
        store
            .update(DashboardSettings {
                feature_flags: [(crate::a2a::version::FLAG_A2A_LEGACY_COMPATIBILITY.to_string(), false)].into(),
                ..DashboardSettings::default()
            })
            .expect("default settings are valid");
        set_global_settings_store(Arc::new(store));
        assert!(!crate::a2a::version::legacy_v0_3_enabled(), "the flag must be off for this test to mean anything");

        let card = synthesize_agent_card(&proxy(None), &surface());

        assert_eq!(
            card["supportedInterfaces"],
            json!([{
                "url": "https://gateway.example/example/rpc",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0"
            }]),
            "only the version the gateway accepts may be advertised"
        );
        for legacy in ["url", "preferredTransport", "agentProvider", "supportsAuthenticatedExtendedCard"] {
            assert!(card.get(legacy).is_none(), "`{legacy}` must not be emitted when v0.3 is refused, got {card}");
        }
        assert_eq!(card["provider"]["organization"], "Affinidi");
        assert_eq!(card["capabilities"]["extendedAgentCard"], false);
    }

    #[test]
    fn synthesized_card_never_names_a_refused_configured_version() {
        if !crate::a2a::version::run_isolated_from_other_tests() {
            return;
        }
        use crate::storage::settings_store::{DashboardSettings, SettingsStore, set_global_settings_store};

        crate::a2a::version::init_advertised_version("0.3");
        let store = SettingsStore::new("unused-settings-dir");
        store
            .update(DashboardSettings {
                feature_flags: [(crate::a2a::version::FLAG_A2A_LEGACY_COMPATIBILITY.to_string(), false)].into(),
                ..DashboardSettings::default()
            })
            .expect("default settings are valid");
        set_global_settings_store(Arc::new(store));
        assert_eq!(crate::a2a::version::advertised_version(), "0.3");
        assert!(!crate::a2a::version::legacy_v0_3_enabled());

        let card = synthesize_agent_card(&proxy(None), &surface());

        assert_eq!(card["protocolVersion"], "1.0", "the configured 0.3 is refused, so it must not be advertised");
        assert_eq!(card["supportedInterfaces"][0]["protocolVersion"], "1.0");
        assert_eq!(
            card["supportedInterfaces"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }
}
