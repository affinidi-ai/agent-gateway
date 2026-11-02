//! Startup and reload report of the credential providers and surfaces that break a
//! `[credential_policy]` rule. Log lines only: ids, tenants and rule names, never a secret value.

use std::collections::HashMap;

use tracing::{info, warn};

use super::surface_tenancy::collect_surface_reference_keys;
use super::surfaces::SurfaceApiError;
use crate::config::agent_surface::AgentSurface;
use crate::config::credential_policy::CredentialPolicyConfig;
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

/// Does a tenant surface send an appliance-wide secret or credential provider upstream, or the
/// gateway credential of a provider holding a secret outside the provider's tenant? A reference
/// that no longer resolves is not a breach; a surface whose references cannot be collected is an
/// error.
fn surface_breaks_isolation(
    surface: &AgentSurface,
    secret_tenants: &HashMap<&str, Option<&str>>,
    providers: &HashMap<&str, &CredentialProvider>,
) -> Result<bool, SurfaceApiError> {
    let Some(tenant_id) = surface.tenant_id.as_deref() else {
        return Ok(false);
    };
    Ok(collect_surface_reference_keys(surface)?
        .iter()
        .any(|reference| match reference.kind {
            ResourceKind::Secrets => reference.same_tenant && secret_tenants.get(reference.id.as_str()) == Some(&None),
            ResourceKind::CredentialProviders => providers
                .get(reference.id.as_str())
                .is_some_and(|provider| {
                    provider.breaks_tenant_isolation_for(Some(tenant_id))
                        || provider
                            .provider_type
                            .sends_gateway_credential()
                            && provider.uses_secret_outside_tenant(secret_tenants)
                }),
            _ => false,
        }))
}

/// A surface whose references could not be collected, so it was not checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkippedSurface {
    pub id: String,
    pub tenant_id: Option<String>,
    pub error: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Findings {
    pub breaches: Vec<PolicyBreach>,
    pub skipped: Vec<SkippedSurface>,
}

pub(crate) fn find_breaches(
    providers: &[CredentialProvider],
    surfaces: &[AgentSurface],
    secret_tenants: &HashMap<&str, Option<&str>>,
    egress: &TokenEgress,
) -> Findings {
    let by_id: HashMap<&str, &CredentialProvider> = providers
        .iter()
        .map(|provider| (provider.id.as_str(), provider))
        .collect();
    let mut findings = Findings::default();
    for provider in providers {
        let mut breach = |rule| {
            findings
                .breaches
                .push(PolicyBreach {
                    subject: "credential_provider",
                    id: provider.id.clone(),
                    tenant_id: provider.tenant_id.clone(),
                    rule,
                })
        };
        if token_endpoint_breaks_https(provider, egress) {
            breach(RULE_TOKEN_ENDPOINT_HTTPS);
        }
        if provider.uses_secret_outside_tenant(secret_tenants) {
            breach(RULE_TENANT_CREDENTIAL_ISOLATION);
        }
    }
    for surface in surfaces {
        match surface_breaks_isolation(surface, secret_tenants, &by_id) {
            Ok(true) => findings
                .breaches
                .push(PolicyBreach {
                    subject: "surface",
                    id: surface.surface_id.clone(),
                    tenant_id: surface.tenant_id.clone(),
                    rule: RULE_TENANT_CREDENTIAL_ISOLATION,
                }),
            Ok(false) => {}
            Err(error) => findings
                .skipped
                .push(SkippedSurface {
                    id: surface.surface_id.clone(),
                    tenant_id: surface.tenant_id.clone(),
                    error: format!("{error:?}"),
                }),
        }
    }
    findings
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

    log_findings(&find_breaches(&providers, &surfaces, &secret_tenants, &egress), policy);
}

fn log_findings(
    findings: &Findings,
    policy: &CredentialPolicyConfig,
) {
    for breach in &findings.breaches {
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
    for skipped in &findings.skipped {
        warn!(
            id = %skipped.id,
            tenant = skipped.tenant_id.as_deref().unwrap_or("appliance"),
            error = %skipped.error,
            "Credential policy report could not inspect a surface"
        );
    }
    if !findings.breaches.is_empty() {
        return;
    }
    if findings.skipped.is_empty() {
        info!("Credential policy report: no credential provider or surface breaks a rule");
    } else {
        info!(
            skipped = findings.skipped.len(),
            "Credential policy report: no other credential provider or surface breaks a rule, but {} surfaces could not be inspected",
            findings.skipped.len()
        );
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
            .breaches
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
            provider("other-tenant-secret", Some("t1"), Some("https://idp/token"), Some("S_OTHER")),
            provider("wide-with-tenant-secret", None, Some("https://idp/token"), Some("S_OWN")),
            provider("wide-with-other-tenant-secret", None, Some("https://idp/token"), Some("S_OTHER")),
        ];
        let secrets = [("S_WIDE", None), ("S_OWN", Some("t1")), ("S_OTHER", Some("t2"))];
        assert_eq!(
            breaches_of(&providers, &secrets, CredentialPolicyConfig::default()),
            vec![
                ("wide-secret".to_string(), RULE_TENANT_CREDENTIAL_ISOLATION),
                ("other-tenant-secret".to_string(), RULE_TENANT_CREDENTIAL_ISOLATION),
                ("wide-with-tenant-secret".to_string(), RULE_TENANT_CREDENTIAL_ISOLATION),
                ("wide-with-other-tenant-secret".to_string(), RULE_TENANT_CREDENTIAL_ISOLATION),
            ]
        );
    }

    #[test]
    fn a_tenant_surface_using_an_appliance_wide_credential_is_reported() {
        let providers = [
            provider("wide", None, Some("https://idp/token"), None),
            provider("own", Some("t1"), Some("https://idp/token"), None),
            provider("own-with-wide-secret", Some("t1"), Some("https://idp/token"), Some("S_WIDE")),
            CredentialProvider {
                provider_type: CredentialProviderType::OAuth2AuthorizationCode,
                ..provider("consent-with-wide-secret", Some("t1"), Some("https://idp/token"), Some("S_WIDE"))
            },
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
            surface_with(Some("t1"), provider_auth("own-with-wide-secret")),
            surface_with(Some("t1"), provider_auth("consent-with-wide-secret")),
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
                .breaches
                .iter()
                .filter(|breach| breach.subject == "surface")
                .collect::<Vec<_>>()
                .is_empty()
            })
            .collect();
        assert_eq!(reported, vec![true, false, true, false, false, false, true, false]);
        let breach =
            find_breaches(&providers, &surfaces[..1], &secret_tenants, &egress(CredentialPolicyConfig::default()))
                .breaches
                .into_iter()
                .find(|breach| breach.subject == "surface")
                .unwrap();
        assert_eq!(breach.id, "s");
        assert_eq!(breach.tenant_id.as_deref(), Some("t1"));
        assert_eq!(breach.rule, RULE_TENANT_CREDENTIAL_ISOLATION);
    }

    fn surface_that_cannot_be_inspected(id: &str) -> AgentSurface {
        let variant = |variant_id: &str, enabled: bool| serde_json::json!({"id": variant_id, "alias": "same", "name": variant_id, "enabled": enabled});
        let mut surface = AgentSurface {
            surface_id: id.to_string(),
            tenant_id: Some("t1".to_string()),
            ..Default::default()
        };
        surface.variants =
            serde_json::from_value(serde_json::json!([variant("a", false), variant("b", true)])).unwrap();
        surface
    }

    #[test]
    fn a_surface_that_cannot_be_inspected_is_skipped_and_counted() {
        let secret_tenants = HashMap::new();
        let healthy = AgentSurface {
            surface_id: "healthy".to_string(),
            tenant_id: Some("t1".to_string()),
            ..Default::default()
        };
        let surfaces = [surface_that_cannot_be_inspected("broken"), healthy];
        let findings = find_breaches(&[], &surfaces, &secret_tenants, &egress(CredentialPolicyConfig::default()));
        assert_eq!(findings.breaches, vec![]);
        assert_eq!(findings.skipped.len(), 1);
        assert_eq!(findings.skipped[0].id, "broken");
        assert_eq!(
            findings.skipped[0]
                .tenant_id
                .as_deref(),
            Some("t1")
        );
        assert!(
            findings.skipped[0]
                .error
                .contains("Variant 'same' references could not be resolved"),
            "{}",
            findings.skipped[0].error
        );
    }

    #[test]
    fn the_clean_line_is_logged_only_when_nothing_was_skipped() {
        let policy = CredentialPolicyConfig::default();
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        log_findings(&Findings::default(), &policy);
        let text = logs.text();
        assert!(text.contains("no credential provider or surface breaks a rule"), "{text}");
        assert!(!text.contains("could not be inspected"), "{text}");

        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let skipped = SkippedSurface {
            id: "broken".to_string(),
            tenant_id: Some("t1".to_string()),
            error: "BadRequest(\"reason\")".to_string(),
        };
        log_findings(
            &Findings {
                breaches: vec![],
                skipped: vec![skipped.clone()],
            },
            &policy,
        );
        let text = logs.text();
        assert!(!text.contains("no credential provider or surface breaks a rule"), "{text}");
        assert!(text.contains("could not inspect a surface"), "{text}");
        assert!(text.contains("broken") && text.contains("t1") && text.contains("reason"), "{text}");
        assert!(text.contains("1 surfaces could not be inspected"), "{text}");

        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        log_findings(
            &Findings {
                breaches: vec![PolicyBreach {
                    subject: "surface",
                    id: "leaky".to_string(),
                    tenant_id: None,
                    rule: RULE_TENANT_CREDENTIAL_ISOLATION,
                }],
                skipped: vec![skipped],
            },
            &policy,
        );
        let text = logs.text();
        assert!(text.contains("Stored configuration breaks a credential policy rule"), "{text}");
        assert!(text.contains("could not inspect a surface"), "{text}");
        assert!(!text.contains("could not be inspected"), "{text}");
    }

    #[test]
    fn a_tenant_surface_naming_an_appliance_wide_secret_in_custom_metadata_is_reported() {
        let secret_tenants: HashMap<&str, Option<&str>> = [("S_WIDE", None), ("S_OWN", Some("t1"))]
            .into_iter()
            .collect();
        let reported = |tenant: Option<&str>, secret_id: &str| {
            let mut surface = AgentSurface {
                surface_id: "s".to_string(),
                tenant_id: tenant.map(String::from),
                ..Default::default()
            };
            surface
                .target
                .response_custom_metadata = Some(
                serde_json::from_value(serde_json::json!({"payload": {"key": format!("$SECRET:{secret_id}")}}))
                    .unwrap(),
            );
            find_breaches(&[], &[surface], &secret_tenants, &egress(CredentialPolicyConfig::default()))
                .breaches
                .iter()
                .any(|breach| breach.subject == "surface" && breach.rule == RULE_TENANT_CREDENTIAL_ISOLATION)
        };

        assert!(reported(Some("t1"), "S_WIDE"));
        assert!(!reported(Some("t1"), "S_OWN"));
        assert!(!reported(Some("t1"), "S_GONE"));
        assert!(!reported(None, "S_WIDE"));
    }
}
