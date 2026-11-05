//! Startup and reload report of the credential providers and surfaces that break a
//! `[credential_policy]` rule. Log lines only: ids, tenants and rule names, never a secret value.

use std::collections::HashMap;

use tracing::{info, warn};

use super::surface_tenancy::{
    ProviderKeyIssue, collect_surface_reference_keys, provider_key_owners, provider_key_verdict,
};
use super::surfaces::SurfaceApiError;
use crate::config::agent_surface::AgentSurface;
use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode};
use crate::config::target_auth_rules::TargetCredentialRule;
use crate::credential_providers::{CredentialProvider, CredentialProviderType};
use crate::delegation_vault::oauth::TokenEgress;
use crate::identity::provider_key_gate::PROVIDER_KEY_TENANT_RULE;
use crate::identity::state::IdentityApiState;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::ResourceKind;

const RULE_TOKEN_ENDPOINT_HTTPS: &str = "token_endpoint_https";
const RULE_TENANT_CREDENTIAL_ISOLATION: &str = "tenant_credential_isolation";
const RULE_JWT_SUBJECT: &str = "jwt_subject";
const RULE_TARGET_HTTPS: &str = TargetCredentialRule::Https.key();
const RULE_TARGET_SOURCE_AUTH: &str = TargetCredentialRule::SourceAuth.key();

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
        && egress.insecure_endpoint(
            provider
                .token_endpoint
                .as_deref(),
        )
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

/// An API Key Provider key id a stored surface derives a DID from that it may not use, or whose
/// key or owning surface is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderKeyFinding {
    pub surface_id: String,
    pub tenant_id: Option<String>,
    pub issue: ProviderKeyIssue,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Findings {
    pub breaches: Vec<PolicyBreach>,
    pub provider_keys: Vec<ProviderKeyFinding>,
    pub skipped: Vec<SkippedSurface>,
}

pub(crate) fn find_breaches(
    providers: &[CredentialProvider],
    surfaces: &[AgentSurface],
    secret_tenants: &HashMap<&str, Option<&str>>,
    key_owners: Option<&HashMap<String, Vec<String>>>,
    egress: &TokenEgress,
) -> Findings {
    let surface_tenants: HashMap<&str, Option<&str>> = surfaces
        .iter()
        .map(|surface| (surface.surface_id.as_str(), surface.tenant_id.as_deref()))
        .collect();
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
        if provider.lacks_jwt_subject() {
            breach(RULE_JWT_SUBJECT);
        }
    }
    for surface in surfaces {
        let mut rules = Vec::new();
        let verdict = surface_breaks_isolation(surface, secret_tenants, &by_id).and_then(|breaks| {
            provider_key_verdict(
                surface,
                key_owners,
                &surface_tenants,
                egress
                    .policy
                    .tenant_credential_isolation,
            )
            .map(|issues| (breaks, issues))
        });
        let verdict = verdict.and_then(|(breaks, issues)| {
            super::surface_target_auth::broken_target_rules(surface).map(|target_rules| (breaks, issues, target_rules))
        });
        match verdict {
            Ok((breaks, issues, target_rules)) => {
                findings.provider_keys.extend(
                    issues
                        .into_iter()
                        .map(|issue| ProviderKeyFinding {
                            surface_id: surface.surface_id.clone(),
                            tenant_id: surface.tenant_id.clone(),
                            issue,
                        }),
                );
                if breaks {
                    rules.push(RULE_TENANT_CREDENTIAL_ISOLATION);
                }
                for rule in [TargetCredentialRule::Https, TargetCredentialRule::SourceAuth] {
                    if target_rules.contains(&rule) {
                        rules.push(rule.key());
                    }
                }
            }
            Err(error) => findings
                .skipped
                .push(SkippedSurface {
                    id: surface.surface_id.clone(),
                    tenant_id: surface.tenant_id.clone(),
                    error: format!("{error:?}"),
                }),
        }
        findings.breaches.extend(
            rules
                .into_iter()
                .map(|rule| PolicyBreach {
                    subject: "surface",
                    id: surface.surface_id.clone(),
                    tenant_id: surface.tenant_id.clone(),
                    rule,
                }),
        );
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
    let key_owners = provider_key_owners(state)
        .await
        .ok();

    log_findings(&find_breaches(&providers, &surfaces, &secret_tenants, key_owners.as_ref(), &egress), policy);
}

/// The mode a rule runs in; `jwt_subject` has no setting and only warns.
fn rule_mode(
    rule: &str,
    policy: &CredentialPolicyConfig,
) -> RuleMode {
    match rule {
        RULE_TOKEN_ENDPOINT_HTTPS => policy.token_endpoint_https,
        RULE_JWT_SUBJECT => RuleMode::Warn,
        RULE_TARGET_HTTPS => policy.target_https,
        RULE_TARGET_SOURCE_AUTH => policy.target_source_auth,
        _ => policy.tenant_credential_isolation,
    }
}

fn log_findings(
    findings: &Findings,
    policy: &CredentialPolicyConfig,
) {
    for breach in &findings.breaches {
        let mode = rule_mode(breach.rule, policy);
        warn!(
            subject = breach.subject,
            id = %breach.id,
            tenant = breach.tenant_id.as_deref().unwrap_or("appliance"),
            rule = breach.rule,
            enforced = mode.is_enforced(),
            "Stored configuration breaks a credential policy rule"
        );
    }
    for finding in &findings.provider_keys {
        warn!(
            subject = "surface",
            id = %finding.surface_id,
            tenant = finding.tenant_id.as_deref().unwrap_or("appliance"),
            rule = PROVIDER_KEY_TENANT_RULE,
            api_key_id = %finding.issue.key_id,
            issue = finding.issue.kind.as_str(),
            not_ready = finding.issue.kind.is_breach(),
            "Stored surface derives a DID from an API key it may not use, or whose key or surface is gone"
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
    if !findings.breaches.is_empty()
        || !findings
            .provider_keys
            .is_empty()
    {
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

    #[test]
    fn the_jwt_subject_rule_only_warns_whatever_the_other_rules_enforce() {
        let policy = CredentialPolicyConfig {
            token_endpoint_https: RuleMode::Enforce,
            tenant_credential_isolation: RuleMode::Enforce,
            ..CredentialPolicyConfig::default()
        };
        assert!(!rule_mode(RULE_JWT_SUBJECT, &policy).is_enforced());
        assert!(rule_mode(RULE_TOKEN_ENDPOINT_HTTPS, &policy).is_enforced());
        assert!(rule_mode(RULE_TENANT_CREDENTIAL_ISOLATION, &policy).is_enforced());
    }

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
            policy: std::borrow::Cow::Owned(policy),
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
        find_breaches(providers, &[], &secret_tenants, None, &egress(policy))
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
    fn a_jwt_bearer_provider_without_a_subject_is_reported() {
        let jwt_bearer = |id: &str, subject: Option<&str>| {
            let mut provider = CredentialProvider {
                provider_type: CredentialProviderType::OAuth2JwtBearer,
                ..provider(id, None, Some("https://idp.example/token"), None)
            };
            provider.jwt.jwt_subject = subject.map(str::to_string);
            provider
        };
        let providers = [
            jwt_bearer("no-subject", None),
            jwt_bearer("blank-subject", Some("  ")),
            jwt_bearer("with-subject", Some("svc@example")),
            provider("client-credentials", None, Some("https://idp.example/token"), None),
        ];
        assert_eq!(
            breaches_of(&providers, &[], CredentialPolicyConfig::default()),
            vec![("no-subject".to_string(), RULE_JWT_SUBJECT), ("blank-subject".to_string(), RULE_JWT_SUBJECT)]
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
                    None,
                    &egress(CredentialPolicyConfig::default()),
                )
                .breaches
                .iter()
                .filter(|breach| breach.subject == "surface" && breach.rule == RULE_TENANT_CREDENTIAL_ISOLATION)
                .collect::<Vec<_>>()
                .is_empty()
            })
            .collect();
        assert_eq!(reported, vec![true, false, true, false, false, false, true, false]);
        let breach = find_breaches(
            &providers,
            &surfaces[..1],
            &secret_tenants,
            None,
            &egress(CredentialPolicyConfig::default()),
        )
        .breaches
        .into_iter()
        .find(|breach| breach.subject == "surface" && breach.rule == RULE_TENANT_CREDENTIAL_ISOLATION)
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
        let findings = find_breaches(&[], &surfaces, &secret_tenants, None, &egress(CredentialPolicyConfig::default()));
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
                provider_keys: vec![],
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
                provider_keys: vec![],
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
            find_breaches(&[], &[surface], &secret_tenants, None, &egress(CredentialPolicyConfig::default()))
                .breaches
                .iter()
                .any(|breach| breach.subject == "surface" && breach.rule == RULE_TENANT_CREDENTIAL_ISOLATION)
        };

        assert!(reported(Some("t1"), "S_WIDE"));
        assert!(!reported(Some("t1"), "S_OWN"));
        assert!(!reported(Some("t1"), "S_GONE"));
        assert!(!reported(None, "S_WIDE"));
    }

    fn target_surface(
        endpoint: &str,
        method: Option<TargetAuthMethod>,
        source_auth: bool,
    ) -> AgentSurface {
        let mut surface = AgentSurface {
            surface_id: "s".to_string(),
            ..Default::default()
        };
        surface.target.endpoint = endpoint.to_string();
        surface.target.auth = method.map(|method| TargetAuthConfig {
            method,
            auth_type: None,
            target_identifier: None,
            fallback: Default::default(),
        });
        if source_auth {
            surface
                .access_point
                .caller_authentication = Some(crate::config::agent_surface::CallerAuthentication {
                methods: vec![crate::source_auth::SourceAuthConfig::ApiKey(
                    crate::source_auth::models::ApiKeyAuthConfig {
                        extraction: crate::source_auth::models::CredentialExtraction::HttpHeader {
                            field: "X-Caller".to_string(),
                        },
                        secret_id: "caller-keys".to_string(),
                    },
                )],
                protected_resource: None,
                on_failure: Default::default(),
            });
        }
        surface
    }

    fn static_secret() -> TargetAuthMethod {
        TargetAuthMethod::StaticSecret {
            secret_id: "S".to_string(),
            header_name: "Authorization".to_string(),
            header_format: "{value}".to_string(),
        }
    }

    fn provider_method() -> TargetAuthMethod {
        TargetAuthMethod::CredentialProvider {
            provider_id: "p".to_string(),
            header_name: "Authorization".to_string(),
            header_format: "{value}".to_string(),
            scopes: Vec::new(),
        }
    }

    fn surface_rules(surface: &AgentSurface) -> Vec<&'static str> {
        find_breaches(
            &[],
            std::slice::from_ref(surface),
            &HashMap::new(),
            None,
            &egress(CredentialPolicyConfig::default()),
        )
        .breaches
        .into_iter()
        .map(|breach| breach.rule)
        .collect()
    }

    fn transit_point(
        endpoint: &str,
        method: Option<TargetAuthMethod>,
        require_transit_token: bool,
    ) -> crate::config::agent_surface::TransitPoint {
        serde_json::from_value(serde_json::json!({
            "alias": "tp",
            "target_endpoint": endpoint,
            "require_transit_token": require_transit_token,
            "target_auth": method.map(|method| serde_json::to_value(TargetAuthConfig {
                method,
                auth_type: None,
                target_identifier: None,
                fallback: Default::default(),
            }).unwrap()),
        }))
        .unwrap()
    }

    fn transit_config(
        points: Vec<crate::config::agent_surface::TransitPoint>
    ) -> crate::config::agent_surface::TransitConfig {
        serde_json::from_value(serde_json::json!({ "points": points })).unwrap()
    }

    #[test]
    fn a_target_credential_on_a_non_https_target_is_reported() {
        for method in [static_secret, provider_method] {
            for (endpoint, reported) in [
                ("http://upstream.internal/mcp", true),
                ("fabric://gw/surface", true),
                ("a2a-proxy://agent", true),
                ("https://upstream.example/mcp", false),
                ("HTTPS://upstream.example/mcp", false),
            ] {
                let rules = surface_rules(&target_surface(endpoint, Some(method()), true));
                assert_eq!(rules.contains(&RULE_TARGET_HTTPS), reported, "{endpoint}");
            }
        }
        assert!(surface_rules(&target_surface("http://upstream.internal", None, true)).is_empty());
    }

    #[test]
    fn a_transit_point_credential_on_a_non_https_endpoint_is_reported() {
        let mut surface = target_surface("https://upstream.example", None, true);
        surface.transit = Some(transit_config(vec![transit_point("http://tp.internal", Some(static_secret()), true)]));
        assert_eq!(surface_rules(&surface), vec![RULE_TARGET_HTTPS]);
        surface.transit = Some(transit_config(vec![transit_point("https://tp.example", Some(static_secret()), true)]));
        assert!(surface_rules(&surface).is_empty());
    }

    #[test]
    fn a_target_credential_without_access_point_source_auth_is_reported() {
        let without = surface_rules(&target_surface("https://upstream.example", Some(static_secret()), false));
        assert_eq!(without, vec![RULE_TARGET_SOURCE_AUTH]);
        let with = surface_rules(&target_surface("https://upstream.example", Some(provider_method()), true));
        assert!(with.is_empty());
        let no_credential = surface_rules(&target_surface("https://upstream.example", None, false));
        assert!(no_credential.is_empty());
    }

    #[test]
    fn a_transit_point_credential_needs_a_transit_point_that_checks_its_callers() {
        let with_points = |access_point_checks: bool, token: bool| {
            let mut surface = target_surface("https://upstream.example", None, access_point_checks);
            surface.transit =
                Some(transit_config(vec![transit_point("https://tp.example", Some(static_secret()), token)]));
            surface
        };
        assert_eq!(surface_rules(&with_points(false, false)), vec![RULE_TARGET_SOURCE_AUTH]);
        assert_eq!(surface_rules(&with_points(true, false)), vec![RULE_TARGET_SOURCE_AUTH]);
        assert!(surface_rules(&with_points(false, true)).is_empty());
    }

    #[test]
    fn an_a2a_proxy_target_is_held_to_target_source_auth_only() {
        assert_eq!(surface_rules(&target_surface("a2a-proxy://agent", None, false)), vec![RULE_TARGET_SOURCE_AUTH]);
        assert!(surface_rules(&target_surface("a2a-proxy://agent", None, true)).is_empty());
        let mut mcp = target_surface("a2a-proxy://agent", None, false);
        mcp.access_point.protocol = crate::config::agent_surface::SurfaceProtocol::Mcp;
        assert!(surface_rules(&mcp).is_empty(), "only an A2A or AP2 surface dispatches to an A2A proxy");
        assert!(surface_rules(&target_surface("https://upstream.example", None, false)).is_empty());
    }

    /// `target_surface` whose Access Point has an API key and a JWT Bearer method.
    fn two_method_surface(
        endpoint: &str,
        method: Option<TargetAuthMethod>,
    ) -> AgentSurface {
        let mut surface = target_surface(endpoint, method, false);
        surface
            .access_point
            .caller_authentication = Some(
            serde_json::from_value(serde_json::json!({"methods": [
                {"type": "api_key", "secret_id": "caller-keys",
                 "extraction": {"source": "http_header", "field": "X-Caller"}},
                {"type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": []}
            ]}))
            .unwrap(),
        );
        surface
    }

    #[test]
    fn an_access_point_with_several_methods_checks_the_targets_callers_but_not_a_transit_points() {
        assert!(surface_rules(&two_method_surface("https://upstream.example", Some(static_secret()))).is_empty());
        assert!(surface_rules(&two_method_surface("a2a-proxy://agent", None)).is_empty());

        let mut variant = two_method_surface("https://upstream.example", Some(provider_method()));
        variant.variants = serde_json::from_value(serde_json::json!([{
            "id": "open-id", "alias": "open", "name": "Open",
            "overrides": {"access_point": {"caller_authentication": {"methods": []}}}
        }]))
        .unwrap();
        assert_eq!(surface_rules(&variant), vec![RULE_TARGET_SOURCE_AUTH], "a variant without a method");

        let mut open_point = two_method_surface("https://upstream.example", None);
        let mut point = transit_point("https://tp.example", Some(static_secret()), false);
        point.allow_unauthenticated_callers = true;
        open_point.transit = Some(transit_config(vec![point]));
        assert_eq!(surface_rules(&open_point), vec![RULE_TARGET_SOURCE_AUTH]);
    }

    #[test]
    fn a_surface_that_cannot_be_inspected_is_not_reported_for_the_target_rules_of_its_other_views() {
        let mut surface = surface_that_cannot_be_inspected("broken");
        surface.target = target_surface("http://upstream.example", Some(static_secret()), false).target;
        let healthy = target_surface("http://upstream.example", Some(static_secret()), true);
        let findings =
            find_breaches(&[], &[surface, healthy], &HashMap::new(), None, &egress(CredentialPolicyConfig::default()));
        assert_eq!(
            findings
                .breaches
                .iter()
                .map(|breach| (breach.id.as_str(), breach.rule))
                .collect::<Vec<_>>(),
            vec![("s", RULE_TARGET_HTTPS)]
        );
        assert_eq!(findings.skipped.len(), 1);
        assert_eq!(findings.skipped[0].id, "broken");
    }

    #[test]
    fn a_resource_access_token_counts_as_checking_the_targets_callers() {
        let mut surface = target_surface("https://upstream.example", Some(static_secret()), false);
        surface.mcp_http = Some(
            serde_json::from_value(serde_json::json!({"authorization": {"resource": "https://gateway.example/s"}}))
                .unwrap(),
        );
        assert!(surface_rules(&surface).is_empty());
    }

    fn key_surface(
        id: &str,
        tenant: Option<&str>,
        extra: serde_json::Value,
    ) -> AgentSurface {
        let mut surface = serde_json::to_value(AgentSurface::default()).unwrap();
        surface["surface_id"] = serde_json::json!(id);
        surface["tenant_id"] = serde_json::json!(tenant);
        for (key, value) in extra.as_object().unwrap() {
            surface[key] = value.clone();
        }
        serde_json::from_value(surface).unwrap()
    }

    fn naming(
        id: &str,
        tenant: Option<&str>,
        key_id: &str,
    ) -> AgentSurface {
        key_surface(
            id,
            tenant,
            serde_json::json!({"identity_slots": {"protected": {"type": "from_api_key", "api_key_id": key_id}}}),
        )
    }

    fn legacy_caller(
        id: &str,
        tenant: Option<&str>,
        secret_id: &str,
        inbound_from_api_key: bool,
    ) -> AgentSurface {
        let mut extra = serde_json::json!({"access_point": {
            "listen_address": "http://localhost:1", "route": "/legacy", "protocol": "a2a",
            "caller_authentication": {"methods": [{
                "type": "api_key", "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": secret_id
            }]}
        }});
        if inbound_from_api_key {
            extra["identity_slots"] = serde_json::json!({"inbound": {"type": "from_api_key"}});
        }
        key_surface(id, tenant, extra)
    }

    fn provider_key_findings(
        naming_surfaces: Vec<AgentSurface>,
        owners: Option<&HashMap<String, Vec<String>>>,
        isolation: crate::config::credential_policy::RuleMode,
    ) -> Vec<(String, &'static str, bool)> {
        let mut surfaces = vec![
            key_surface("owner-t1", Some("t1"), serde_json::json!({})),
            key_surface("owner-t2", Some("t2"), serde_json::json!({})),
            key_surface("owner-wide", None, serde_json::json!({})),
        ];
        surfaces.extend(naming_surfaces);
        let policy = CredentialPolicyConfig {
            tenant_credential_isolation: isolation,
            ..Default::default()
        };
        find_breaches(&[], &surfaces, &HashMap::new(), owners, &egress(policy))
            .provider_keys
            .into_iter()
            .map(|finding| (finding.surface_id, finding.issue.kind.as_str(), finding.issue.kind.is_breach()))
            .collect()
    }

    fn key_owners() -> HashMap<String, Vec<String>> {
        [
            ("atgk_t1", "owner-t1"),
            ("atgk_t2", "owner-t2"),
            ("atgk_wide", "owner-wide"),
            ("atgk_orphan", "deleted-owner"),
        ]
        .into_iter()
        .map(|(key, owner)| (key.to_string(), vec![owner.to_string()]))
        .collect()
    }

    #[test]
    fn a_surface_naming_a_provider_key_it_may_not_use_is_reported_under_its_own_rule() {
        use crate::config::credential_policy::RuleMode;
        let owners = key_owners();
        let surfaces = || {
            vec![
                naming("own", Some("t1"), "atgk_t1"),
                naming("cross", Some("t1"), "atgk_t2"),
                naming("tenant-key-wide", None, "atgk_t1"),
                naming("appliance-key", Some("t1"), "atgk_wide"),
                naming("wide-wide", None, "atgk_wide"),
                naming("missing-key", Some("t1"), "atgk_gone"),
                naming("missing-owner", Some("t1"), "atgk_orphan"),
            ]
        };
        let warn = provider_key_findings(surfaces(), Some(&owners), RuleMode::Warn);
        assert_eq!(
            warn,
            vec![
                ("cross".to_string(), "other_tenant", false),
                ("tenant-key-wide".to_string(), "other_tenant", false),
                ("appliance-key".to_string(), "appliance_key", false),
                ("missing-key".to_string(), "missing_key", false),
                ("missing-owner".to_string(), "missing_owner", false),
            ]
        );
        let enforce = provider_key_findings(surfaces(), Some(&owners), RuleMode::Enforce);
        assert_eq!(
            enforce[..3],
            [
                ("cross".to_string(), "other_tenant", true),
                ("tenant-key-wide".to_string(), "other_tenant", true),
                ("appliance-key".to_string(), "appliance_key", true),
            ]
        );
        assert!(
            provider_key_findings(vec![naming("own", Some("t1"), "atgk_t1")], Some(&owners), RuleMode::Enforce)
                .is_empty()
        );
    }

    #[test]
    fn a_surface_naming_a_provider_key_is_reported_not_ready_while_the_key_store_is_unavailable() {
        use crate::config::credential_policy::RuleMode;
        assert_eq!(
            provider_key_findings(
                vec![naming("own", Some("t1"), "atgk_t1"), key_surface("plain", Some("t1"), serde_json::json!({}))],
                None,
                RuleMode::Warn
            ),
            vec![("own".to_string(), "store_unavailable", true)]
        );
    }

    #[test]
    fn a_legacy_caller_secret_shaped_like_a_key_it_may_not_use_is_reported() {
        use crate::config::credential_policy::RuleMode;
        let owners = key_owners();
        assert_eq!(
            provider_key_findings(
                vec![
                    legacy_caller("legacy-cross", Some("t1"), "atgk_t2", true),
                    legacy_caller("legacy-own", Some("t1"), "atgk_t1", true),
                    legacy_caller("legacy-wide", Some("t1"), "atgk_wide", true),
                    legacy_caller("legacy-unowned", Some("t1"), "atgk_gone", true),
                    legacy_caller("legacy-no-identity", Some("t1"), "atgk_t2", false),
                ],
                Some(&owners),
                RuleMode::Enforce
            ),
            vec![
                ("legacy-cross".to_string(), "other_tenant", true),
                ("legacy-wide".to_string(), "appliance_key", true)
            ]
        );
    }

    #[test]
    fn a_provider_key_finding_logs_its_rule_and_key_id_and_no_secret() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let owners = key_owners();
        let mut surface = naming("cross", Some("t1"), "atgk_t2");
        surface.target.auth = Some(TargetAuthConfig {
            method: TargetAuthMethod::StaticSecret {
                secret_id: "S_OWN".to_string(),
                header_name: "Authorization".to_string(),
                header_format: "{value}".to_string(),
            },
            auth_type: None,
            target_identifier: None,
            fallback: Default::default(),
        });
        let findings = find_breaches(
            &[],
            &[key_surface("owner-t2", Some("t2"), serde_json::json!({})), surface],
            &[("S_OWN", Some("t1"))]
                .into_iter()
                .collect(),
            Some(&owners),
            &egress(CredentialPolicyConfig::default()),
        );
        log_findings(&findings, &CredentialPolicyConfig::default());
        let text = logs.text();
        assert!(text.contains(PROVIDER_KEY_TENANT_RULE), "{text}");
        assert!(text.contains("atgk_t2") && text.contains("other_tenant") && text.contains("cross"), "{text}");
        assert!(!text.contains("no credential provider or surface breaks a rule"), "{text}");
        assert!(!text.contains("S_OWN") && !text.contains("atgs_"), "{text}");
    }
}
