use std::collections::HashMap;

use serde_json::{Value as JsonValue, json};

use super::types::{A2aProxy, A2aProxyAgentIdentityType};
use crate::proxy::backend_identity::ProtectedAgentIdentity;

pub fn build_identity_fields(proxy: &A2aProxy) -> HashMap<String, JsonValue> {
    match proxy
        .agent_identity
        .as_ref()
        .map(|identity| &identity.identity_type)
    {
        Some(A2aProxyAgentIdentityType::EntraAgent) => {
            let identity = proxy
                .agent_identity
                .as_ref()
                .expect("identity type came from agent_identity");
            HashMap::from([
                (
                    "entra_agent_id".to_string(),
                    json!(
                        identity
                            .entra_agent_id
                            .as_deref()
                            .unwrap_or_default()
                            .trim()
                    ),
                ),
                (
                    "client_tenant_id".to_string(),
                    json!(
                        identity
                            .client_tenant_id
                            .as_deref()
                            .unwrap_or_default()
                            .trim()
                    ),
                ),
            ])
        }
        _ => build_proxy_subject_identity_fields(proxy),
    }
}

pub fn identity_hash(proxy: &A2aProxy) -> String {
    let identity_fields = build_identity_fields(proxy);
    if proxy
        .agent_identity
        .as_ref()
        .is_some_and(|identity| matches!(identity.identity_type, A2aProxyAgentIdentityType::EntraAgent))
    {
        crate::identity::compute_canonical_identity_hash(&identity_fields)
    } else {
        let subject = proxy
            .agent_identity
            .as_ref()
            .map(|identity| identity.subject_or_proxy_id(&proxy.id))
            .unwrap_or(&proxy.id);
        crate::identity::credential_identity::hash_credential(&[
            ("credential_type", "a2a_proxy"),
            ("proxy_id", proxy.id.as_str()),
            ("backend_kind", proxy.backend.kind_label()),
            ("subject", subject),
        ])
    }
}

fn build_proxy_subject_identity_fields(proxy: &A2aProxy) -> HashMap<String, JsonValue> {
    let subject = proxy
        .agent_identity
        .as_ref()
        .map(|identity| identity.subject_or_proxy_id(&proxy.id))
        .unwrap_or(&proxy.id)
        .to_string();

    HashMap::from([
        ("credential_type".to_string(), json!("a2a_proxy")),
        ("proxy_id".to_string(), json!(proxy.id.clone())),
        ("backend_kind".to_string(), json!(proxy.backend.kind_label())),
        ("subject".to_string(), json!(subject)),
    ])
}

pub async fn resolve_synthetic_identity(
    proxy: &A2aProxy,
    surface: &crate::config::agent_surface::AgentSurface,
    vc_issuer: Option<&std::sync::Arc<crate::identity::VCIssuer>>,
) -> anyhow::Result<Option<ProtectedAgentIdentity>> {
    let Some(vc_issuer) = vc_issuer else {
        return Ok(None);
    };

    if let Some(identity) = &proxy.agent_identity {
        identity
            .validate()
            .map_err(|e| anyhow::anyhow!("A2A Proxy identity configuration is invalid: {e}"))?;
    }

    let identity_fields = build_identity_fields(proxy);
    let response = vc_issuer
        .issue_or_get_credential(
            identity_fields.clone(),
            Some(identity_hash(proxy)),
            Some(surface.surface_id.clone()),
            surface.issuer_id.clone(),
        )
        .await?;

    Ok(Some(ProtectedAgentIdentity::Managed {
        did: response.did,
        identity_fields,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::a2a_proxies::types::{
        A2aProxyAgentIdentity, A2aProxyAgentIdentityType, A2aProxyBackend, CopilotDirectLineBackend,
        DEFAULT_DIRECT_LINE_BASE_URL, DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS, DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS,
        DEFAULT_DIRECT_LINE_TIMEOUT_SECS, DirectLineCredentialMode,
    };

    fn proxy(subject: Option<&str>) -> A2aProxy {
        let mut proxy = A2aProxy::new(
            "Copilot Worker".to_string(),
            "Fake Direct Line worker".to_string(),
            A2aProxyBackend::CopilotDirectLine(CopilotDirectLineBackend {
                secret_id: "direct-line-secret".to_string(),
                credential_mode: DirectLineCredentialMode::Secret,
                base_url: DEFAULT_DIRECT_LINE_BASE_URL.to_string(),
                timeout_secs: DEFAULT_DIRECT_LINE_TIMEOUT_SECS,
                poll_interval_ms: DEFAULT_DIRECT_LINE_POLL_INTERVAL_MS,
                max_poll_attempts: DEFAULT_DIRECT_LINE_MAX_POLL_ATTEMPTS,
            }),
            None,
        );
        proxy.id = "worker-proxy".to_string();
        proxy.agent_identity = Some(A2aProxyAgentIdentity {
            identity_type: A2aProxyAgentIdentityType::ProxySubject,
            subject: subject.map(str::to_string),
            entra_agent_id: None,
            client_tenant_id: None,
        });
        proxy
    }

    fn entra_proxy() -> A2aProxy {
        let mut proxy = proxy(Some("should-not-affect-entra"));
        proxy.agent_identity = Some(A2aProxyAgentIdentity {
            identity_type: A2aProxyAgentIdentityType::EntraAgent,
            subject: Some("should-not-affect-entra".to_string()),
            entra_agent_id: Some("entra-agent-123".to_string()),
            client_tenant_id: Some("tenant-456".to_string()),
        });
        proxy
    }

    #[test]
    fn fallback_identity_uses_proxy_id_as_subject() {
        let fields = build_identity_fields(&proxy(None));
        assert_eq!(fields.get("credential_type"), Some(&json!("a2a_proxy")));
        assert_eq!(fields.get("proxy_id"), Some(&json!("worker-proxy")));
        assert_eq!(fields.get("backend_kind"), Some(&json!("copilot_direct_line")));
        assert_eq!(fields.get("subject"), Some(&json!("worker-proxy")));
    }

    #[test]
    fn configured_subject_changes_identity_hash() {
        let fallback = identity_hash(&proxy(None));
        let configured = identity_hash(&proxy(Some("copilot-orchestrator-prod")));
        assert_ne!(fallback, configured);
        assert_eq!(identity_hash(&proxy(Some("copilot-orchestrator-prod"))), configured);
    }

    #[test]
    fn identity_fields_do_not_contain_direct_line_secret_material() {
        let fields = build_identity_fields(&proxy(Some("copilot-orchestrator-prod")));
        let serialized = serde_json::to_string(&fields).expect("identity fields JSON");
        assert!(!serialized.contains("direct-line-secret"));
        assert!(!serialized.contains("test-direct-line-secret"));
    }

    #[test]
    fn entra_identity_fields_match_header_metadata_identity_shape() {
        let fields = build_identity_fields(&entra_proxy());
        assert_eq!(fields.len(), 2);
        assert_eq!(fields.get("entra_agent_id"), Some(&json!("entra-agent-123")));
        assert_eq!(fields.get("client_tenant_id"), Some(&json!("tenant-456")));
        assert!(!fields.contains_key("credential_type"));
        assert!(!fields.contains_key("proxy_id"));
        assert!(!fields.contains_key("backend_kind"));
        assert!(!fields.contains_key("subject"));
    }

    #[test]
    fn entra_identity_hash_matches_header_metadata_canonical_hash() {
        let fields = build_identity_fields(&entra_proxy());
        assert_eq!(identity_hash(&entra_proxy()), crate::identity::compute_canonical_identity_hash(&fields));
    }

    #[test]
    fn entra_identity_fields_do_not_contain_proxy_or_direct_line_material() {
        let fields = build_identity_fields(&entra_proxy());
        let serialized = serde_json::to_string(&fields).expect("identity fields JSON");
        assert!(!serialized.contains("worker-proxy"));
        assert!(!serialized.contains("copilot_direct_line"));
        assert!(!serialized.contains("direct-line-secret"));
        assert!(!serialized.contains("should-not-affect-entra"));
    }
}
