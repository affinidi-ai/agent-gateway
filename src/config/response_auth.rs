//! Response authentication (`target.response_auth`): how a Target's response proves it comes
//! from the surface's registered managed agent before the gateway uses it. The counterpart of
//! Target authentication, which lets the managed agent check the gateway.

use serde::{Deserialize, Serialize};

use crate::source_auth::models::MtlsTrust;

/// How a Target's responses prove they come from the registered managed agent.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseAuthConfig {
    /// The managed agent returns one of the keys a secret holds in a response header.
    ApiKey(ApiKeyResponseAuth),
    /// The managed agent's server certificate passes `server_trust` in the TLS handshake.
    Mtls(MtlsResponseAuth),
}

/// The trust a managed agent's server certificate must pass, using only the configured
/// certificates, and the stored certificate, with its private key, the gateway presents to it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MtlsResponseAuth {
    pub server_trust: MtlsTrust,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_certificate_id: Option<String>,
}

impl MtlsResponseAuth {
    /// The certificate ids `server_trust` names.
    pub fn trust_certificate_ids(&self) -> &[String] {
        match &self.server_trust {
            MtlsTrust::Pinned { certificate_ids } => certificate_ids,
            MtlsTrust::Ca { ca_certificate_ids, .. } => ca_certificate_ids,
        }
    }
}

/// The response header a managed agent returns its key in, and the secret holding the keys
/// accepted there. The secret may hold several comma-separated keys, so a key can be rotated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyResponseAuth {
    pub header_name: String,
    pub secret_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::{AgentSurface, Target};
    use serde_json::json;

    fn api_key() -> serde_json::Value {
        json!({"api_key": {"header_name": "X-Agent-Key", "secret_id": "bravo-key"}})
    }

    #[test]
    fn test_response_auth_api_key_parses_and_round_trips() {
        let parsed: ResponseAuthConfig = serde_json::from_value(api_key()).expect("api_key parses");
        assert_eq!(
            parsed,
            ResponseAuthConfig::ApiKey(ApiKeyResponseAuth {
                header_name: "X-Agent-Key".to_string(),
                secret_id: "bravo-key".to_string(),
            })
        );
        assert_eq!(serde_json::to_value(&parsed).expect("serialises"), api_key());
    }

    #[test]
    fn test_response_auth_mtls_parses_and_round_trips_with_either_trust() {
        let pinned = json!({"mtls": {
            "server_trust": {"type": "pinned", "certificate_ids": ["bravo-cert"]},
            "client_certificate_id": "gateway-cert"
        }});
        let parsed: ResponseAuthConfig = serde_json::from_value(pinned.clone()).expect("pinned parses");
        let ResponseAuthConfig::Mtls(config) = &parsed else {
            panic!("expected mtls, got {parsed:?}");
        };
        assert_eq!(config.trust_certificate_ids(), ["bravo-cert"]);
        assert_eq!(
            config
                .client_certificate_id
                .as_deref(),
            Some("gateway-cert")
        );
        assert_eq!(serde_json::to_value(&parsed).expect("serialises"), pinned);

        let ca = json!({"mtls": {"server_trust": {"type": "ca", "ca_certificate_ids": ["bravo-ca"]}}});
        let parsed: ResponseAuthConfig = serde_json::from_value(ca).expect("ca parses");
        let ResponseAuthConfig::Mtls(config) = &parsed else {
            panic!("expected mtls, got {parsed:?}");
        };
        assert_eq!(config.trust_certificate_ids(), ["bravo-ca"]);
        assert_eq!(config.client_certificate_id, None);
        assert!(
            serde_json::to_value(&parsed).expect("serialises")["mtls"]
                .get("client_certificate_id")
                .is_none()
        );
    }

    #[test]
    fn test_response_auth_mtls_refuses_a_missing_trust_or_unknown_field() {
        for (case, value) in [
            ("no server trust", json!({"mtls": {"client_certificate_id": "gateway-cert"}})),
            (
                "an unknown field",
                json!({"mtls": {"server_trust": {"type": "pinned", "certificate_ids": ["c"]}, "identity_binding": {}}}),
            ),
        ] {
            assert!(serde_json::from_value::<ResponseAuthConfig>(value).is_err(), "{case}");
        }
    }

    #[test]
    fn test_response_auth_refuses_unknown_methods_and_fields() {
        for (case, value) in [
            ("an unknown method", json!({"jwt": {"header_name": "X-Agent-Key", "secret_id": "bravo-key"}})),
            (
                "an unknown field",
                json!({"api_key": {"header_name": "X-Agent-Key", "secret_id": "bravo-key", "header_format": "{value}"}}),
            ),
            ("no secret", json!({"api_key": {"header_name": "X-Agent-Key"}})),
            ("no header", json!({"api_key": {"secret_id": "bravo-key"}})),
            ("two methods", json!({"api_key": {"header_name": "X-Agent-Key", "secret_id": "bravo-key"}, "mtls": {}})),
        ] {
            assert!(serde_json::from_value::<ResponseAuthConfig>(value).is_err(), "{case}");
        }
    }

    #[test]
    fn test_target_keeps_its_response_auth_and_omits_it_when_unset() {
        let target: Target =
            serde_json::from_value(json!({"endpoint": "https://bravo.example", "response_auth": api_key()}))
                .expect("target parses");
        assert!(matches!(target.response_auth, Some(ResponseAuthConfig::ApiKey(_))));
        assert_eq!(serde_json::to_value(&target).expect("serialises")["response_auth"], api_key());

        let plain: Target = serde_json::from_value(json!({"endpoint": "https://bravo.example"})).expect("parses");
        assert_eq!(plain.response_auth, None);
        assert!(
            serde_json::to_value(&plain)
                .expect("serialises")
                .get("response_auth")
                .is_none()
        );
    }

    #[test]
    fn test_target_refuses_a_misspelled_response_auth() {
        let misspelled = json!({"endpoint": "https://bravo.example", "response_authentication": api_key()});
        assert!(serde_json::from_value::<Target>(misspelled).is_err());
    }

    fn surface_with_variant(overrides: serde_json::Value) -> AgentSurface {
        serde_json::from_value(json!({
            "name": "s",
            "access_point": {"listen_address": "0.0.0.0:8443", "route": "/s", "protocol": "a2a"},
            "target": {"endpoint": "https://bravo.example", "response_auth": api_key()},
            "variants": [{"id": "beta-id", "alias": "beta", "name": "Beta", "overrides": overrides}]
        }))
        .expect("surface parses")
    }

    #[test]
    fn test_variant_inherits_overrides_or_clears_the_response_auth_like_target_auth() {
        let other = json!({"api_key": {"header_name": "X-Beta-Key", "secret_id": "beta-key"}});
        let resolved = |overrides: serde_json::Value| {
            surface_with_variant(overrides)
                .resolve_variant(Some("beta"))
                .expect("variant resolves")
                .target
                .response_auth
                .map(|config| serde_json::to_value(config).expect("serialises"))
        };

        assert_eq!(resolved(json!({"target": {"endpoint": "https://beta.example"}})), Some(api_key()), "inherited");
        assert_eq!(resolved(json!({"target": {"response_auth": other.clone()}})), Some(other.clone()), "overridden");
        assert_eq!(
            resolved(json!({"complete": true, "target": {"endpoint": "https://beta.example"}})),
            None,
            "a complete variant that sets none has none"
        );
        assert_eq!(resolved(json!({"complete": true, "target": {"response_auth": other.clone()}})), Some(other));
    }
}
