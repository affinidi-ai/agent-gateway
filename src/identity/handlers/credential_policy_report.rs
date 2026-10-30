//! Startup and reload report of the credential providers and surfaces that break a
//! `[credential_policy]` rule. Log lines only: ids, tenants and rule names, never a secret value.

use std::collections::HashMap;

use tracing::{info, warn};

use super::surface_tenancy::collect_surface_reference_keys;
use crate::config::agent_surface::AgentSurface;
use crate::credential_providers::{CredentialProvider, CredentialProviderType};
use crate::delegation_vault::oauth::TokenEgress;
use crate::identity::state::IdentityApiState;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::ResourceKind;

const RULE_TOKEN_ENDPOINT_HTTPS: &str = "token_endpoint_https";
const RULE_TENANT_CREDENTIAL_ISOLATION: &str = "tenant_credential_isolation";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyBreach {
    pub subject: &'static str,
    pub id: String,
    pub tenant_id: Option<String>,
    pub rule: &'static str,
}

/// Does an OAuth provider's token endpoint fail the https rule its token requests are held to?
fn token_endpoint_breaks_https(
    provider: &CredentialProvider,
    egress: &TokenEgress,
) -> bool {
    provider.provider_type != CredentialProviderType::ApiKey
        && provider
            .token_endpoint
            .as_deref()
            .is_some_and(|endpoint| !egress.permits_token_endpoint(endpoint))
}

/// Does a tenant provider name an appliance-wide secret? A secret that no longer exists
/// is not a breach.
fn provider_breaks_isolation(
    provider: &CredentialProvider,
    secret_tenants: &HashMap<&str, Option<&str>>,
) -> bool {
    provider.tenant_id.is_some()
        && provider
            .secret_refs()
            .into_iter()
            .any(|secret_ref| secret_tenants.get(secret_ref) == Some(&None))
}

/// Does a tenant surface send an appliance-wide secret or credential provider upstream?
/// A reference that no longer resolves is not a breach.
fn surface_breaks_isolation(
    surface: &AgentSurface,
    secret_tenants: &HashMap<&str, Option<&str>>,
    providers: &HashMap<&str, &CredentialProvider>,
) -> bool {
    let Some(tenant_id) = surface.tenant_id.as_deref() else {
        return false;
    };
    let Ok(references) = collect_surface_reference_keys(surface) else {
        return false;
    };
    references
        .iter()
        .any(|reference| match reference.kind {
            ResourceKind::Secrets => reference.same_tenant && secret_tenants.get(reference.id.as_str()) == Some(&None),
            ResourceKind::CredentialProviders => providers
                .get(reference.id.as_str())
                .is_some_and(|provider| provider.breaks_tenant_isolation_for(Some(tenant_id))),
            _ => false,
        })
}

pub(crate) fn find_breaches(
    providers: &[CredentialProvider],
    surfaces: &[AgentSurface],
    secret_tenants: &HashMap<&str, Option<&str>>,
    egress: &TokenEgress,
) -> Vec<PolicyBreach> {
    let by_id: HashMap<&str, &CredentialProvider> = providers
        .iter()
        .map(|provider| (provider.id.as_str(), provider))
        .collect();
    let mut breaches = Vec::new();
    for provider in providers {
        let mut breach = |rule| {
            breaches.push(PolicyBreach {
                subject: "credential_provider",
                id: provider.id.clone(),
                tenant_id: provider.tenant_id.clone(),
                rule,
            })
        };
        if token_endpoint_breaks_https(provider, egress) {
            breach(RULE_TOKEN_ENDPOINT_HTTPS);
        }
        if provider_breaks_isolation(provider, secret_tenants) {
            breach(RULE_TENANT_CREDENTIAL_ISOLATION);
        }
    }
    for surface in surfaces {
        if surface_breaks_isolation(surface, secret_tenants, &by_id) {
            breaches.push(PolicyBreach {
                subject: "surface",
                id: surface.surface_id.clone(),
                tenant_id: surface.tenant_id.clone(),
                rule: RULE_TENANT_CREDENTIAL_ISOLATION,
            });
        }
    }
    breaches
}

/// Log one warning per credential provider or surface that breaks a credential policy rule.
pub(crate) async fn report_credential_policy(state: &IdentityApiState) {
    let egress = TokenEgress::from_environment();
    let policy = &egress.policy;
    let providers = match &state.credential_provider_store {
        Some(store) => match store.list().await {
            Ok(providers) => providers,
            Err(error) => {
                warn!("Credential policy report skipped: listing credential providers failed: {error}");
                return;
            }
        },
        None => return,
    };
    let secrets = match &state.secrets_store {
        Some(store) => match store.list_all().await {
            Ok(secrets) => secrets,
            Err(error) => {
                warn!("Credential policy report skipped: listing secrets failed: {error}");
                return;
            }
        },
        None => Vec::new(),
    };
    let surfaces = match &state.agent_surface_store {
        Some(store) => match store.list_all().await {
            Ok(surfaces) => surfaces,
            Err(error) => {
                warn!("Credential policy report skipped: listing surfaces failed: {error}");
                return;
            }
        },
        None => Vec::new(),
    };
    let secret_tenants: HashMap<&str, Option<&str>> = secrets
        .iter()
        .map(|secret| (secret.secret_id.as_str(), secret.tenant_id.as_deref()))
        .collect();

    let breaches = find_breaches(&providers, &surfaces, &secret_tenants, &egress);
    for breach in &breaches {
        let mode = if breach.rule == RULE_TOKEN_ENDPOINT_HTTPS {
            policy.token_endpoint_https
        } else {
            policy.tenant_credential_isolation
        };
        warn!(
            subject = breach.subject,
            id = %breach.id,
            tenant = breach.tenant_id.as_deref().unwrap_or("appliance"),
            rule = breach.rule,
            enforced = mode.is_enforced(),
            "Stored configuration breaks a credential policy rule"
        );
    }
    if breaches.is_empty() {
        info!("Credential policy report: no credential provider or surface breaks a rule");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credential_policy::CredentialPolicyConfig;
    use crate::config::types::{TargetAuthConfig, TargetAuthMethod};
    use chrono::Utc;

    fn provider(
        id: &str,
        tenant: Option<&str>,
        endpoint: Option<&str>,
        client_secret: Option<&str>,
    ) -> CredentialProvider {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "tenant_id": tenant,
            "name": id,
            "provider_id": id,
            "provider_type": "oauth2_client_credentials",
            "token_endpoint": endpoint,
            "client_secret_secret_ref": client_secret,
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
        }))
        .unwrap()
    }

    fn egress(policy: CredentialPolicyConfig) -> TokenEgress {
        TokenEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: None,
            policy,
        }
    }

    fn breaches_of(
        providers: &[CredentialProvider],
        secrets: &[(&'static str, Option<&'static str>)],
        policy: CredentialPolicyConfig,
    ) -> Vec<(String, &'static str)> {
        let secret_tenants: HashMap<&str, Option<&str>> = secrets
            .iter()
            .copied()
            .collect();
        find_breaches(providers, &[], &secret_tenants, &egress(policy))
            .into_iter()
            .map(|breach| (breach.id, breach.rule))
            .collect()
    }

    #[test]
    fn an_oauth_providers_http_token_endpoint_is_reported_unless_listed() {
        let providers = [
            provider("plain", None, Some("http://idp.internal/token"), None),
            provider("listed", None, Some("http://idp.example/token"), None),
            provider("secure", None, Some("https://idp.example/token"), None),
            provider("none", None, None, None),
            provider("garbled", None, Some("not a url"), None),
            CredentialProvider {
                provider_type: CredentialProviderType::ApiKey,
                ..provider("api-key", None, Some("http://idp.internal/token"), None)
            },
        ];
        let policy = CredentialPolicyConfig {
            insecure_token_endpoints: vec!["http://idp.example/token".to_string()],
            ..Default::default()
        };
        assert_eq!(
            breaches_of(&providers, &[], policy),
            vec![("plain".to_string(), RULE_TOKEN_ENDPOINT_HTTPS), ("garbled".to_string(), RULE_TOKEN_ENDPOINT_HTTPS),]
        );
    }

    #[test]
    fn a_tenant_provider_with_an_appliance_wide_secret_is_reported() {
        let providers = [
            provider("wide-secret", Some("t1"), Some("https://idp/token"), Some("S_WIDE")),
            provider("own-secret", Some("t1"), Some("https://idp/token"), Some("S_OWN")),
            provider("appliance", None, Some("https://idp/token"), Some("S_WIDE")),
            provider("missing", Some("t1"), Some("https://idp/token"), Some("S_GONE")),
        ];
        let secrets = [("S_WIDE", None), ("S_OWN", Some("t1"))];
        assert_eq!(
            breaches_of(&providers, &secrets, CredentialPolicyConfig::default()),
            vec![("wide-secret".to_string(), RULE_TENANT_CREDENTIAL_ISOLATION)]
        );
    }

    #[test]
    fn a_tenant_surface_using_an_appliance_wide_credential_is_reported() {
        let providers = [
            provider("wide", None, Some("https://idp/token"), None),
            provider("own", Some("t1"), Some("https://idp/token"), None),
        ];
        let secret_tenants: HashMap<&str, Option<&str>> = [("S_WIDE", None), ("S_OWN", Some("t1"))]
            .into_iter()
            .collect();
        let surface_with = |tenant: Option<&str>, method: TargetAuthMethod| -> AgentSurface {
            let mut surface = AgentSurface {
                surface_id: "s".to_string(),
                tenant_id: tenant.map(String::from),
                ..Default::default()
            };
            surface.target.auth = Some(TargetAuthConfig {
                method,
                auth_type: None,
                target_identifier: None,
                fallback: Default::default(),
            });
            surface
        };
        let secret_auth = |id: &str| TargetAuthMethod::StaticSecret {
            secret_id: id.to_string(),
            header_name: "Authorization".to_string(),
            header_format: "{value}".to_string(),
        };
        let provider_auth = |id: &str| TargetAuthMethod::CredentialProvider {
            provider_id: id.to_string(),
            header_name: "Authorization".to_string(),
            header_format: "{value}".to_string(),
            scopes: Vec::new(),
        };
        let surfaces = [
            surface_with(Some("t1"), secret_auth("S_WIDE")),
            surface_with(Some("t1"), secret_auth("S_OWN")),
            surface_with(Some("t1"), provider_auth("wide")),
            surface_with(Some("t1"), provider_auth("own")),
            surface_with(None, secret_auth("S_WIDE")),
            surface_with(None, provider_auth("wide")),
        ];
        let reported: Vec<bool> = surfaces
            .iter()
            .map(|surface| {
                !find_breaches(
                    &providers,
                    std::slice::from_ref(surface),
                    &secret_tenants,
                    &egress(CredentialPolicyConfig::default()),
                )
                .iter()
                .filter(|breach| breach.subject == "surface")
                .collect::<Vec<_>>()
                .is_empty()
            })
            .collect();
        assert_eq!(reported, vec![true, false, true, false, false, false]);
        let breach =
            find_breaches(&providers, &surfaces[..1], &secret_tenants, &egress(CredentialPolicyConfig::default()))
                .into_iter()
                .find(|breach| breach.subject == "surface")
                .unwrap();
        assert_eq!(breach.id, "s");
        assert_eq!(breach.tenant_id.as_deref(), Some("t1"));
        assert_eq!(breach.rule, RULE_TENANT_CREDENTIAL_ISOLATION);
    }
}
