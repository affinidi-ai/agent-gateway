//! Save-time rules for Target authentication: the header it sets, the format of its value,
//! and the leg that sends it. The header and format rules always refuse a save; the
//! `target_https` and `target_source_auth` rules refuse it only in `enforce`, and in `warn`
//! the save goes through with a warning. A rule a stored leg already broke, with the same
//! Target authentication and endpoint, does not block a save that keeps it.

use tracing::warn;

use crate::config::agent_surface::AgentSurface;
use crate::config::credential_policy::{RuleMode, credential_policy};
use crate::config::target_auth_rules::{
    HeaderFormatProblem, TargetCredentialRule, broken_target_credential_rules, header_format_problem, is_header_name,
    is_https_target, reserved_header, same_header_name,
};
use crate::config::{TargetAuthConfig, TargetAuthMethod};

use super::surfaces::SurfaceApiError;

/// One leg that sends a Target credential: the Target, or a Transit Point by `id`, of the base
/// surface or of a variant by `id`.
struct Leg<'a> {
    variant_id: Option<&'a str>,
    transit_point_id: Option<&'a str>,
    field: String,
    endpoint: &'a str,
    authentication: &'a TargetAuthConfig,
    checks_callers: bool,
    caller_check: &'static str,
    other_headers: Vec<(String, &'static str)>,
}

/// A rule a leg breaks, with what identifies the leg and its setting, so the same breach on
/// the stored surface can be recognised.
#[derive(PartialEq)]
struct Breach {
    variant_id: Option<String>,
    transit_point_id: Option<String>,
    endpoint: String,
    authentication: serde_json::Value,
    rule: String,
}

/// Refuses the first rule a Target authentication of `surface` breaks that `stored` did not
/// already break on the same leg with the same setting. A new breach of a credential policy
/// rule in `warn` is logged once nothing is refused, and saved.
pub(super) fn validate_target_auth_rules(
    surface: &AgentSurface,
    stored: Option<&AgentSurface>,
) -> Result<(), SurfaceApiError> {
    let kept = match stored {
        Some(stored) => breaches(stored)?
            .into_iter()
            .map(|(breach, ..)| breach)
            .collect(),
        None => Vec::new(),
    };
    let mut warned = Vec::new();
    for (breach, message, policy_rule) in breaches(surface)? {
        if kept.contains(&breach) {
            continue;
        }
        match policy_rule {
            Some(rule) if !rule_mode(rule).is_enforced() => warned.push((rule, message)),
            _ => return Err(SurfaceApiError::BadRequest(message)),
        }
    }
    for (rule, message) in warned {
        warn!(
            surface_id = %surface.surface_id,
            rule = rule.key(),
            "A Target authentication being saved breaks a credential policy rule: {}",
            warning(rule, &message)
        );
    }
    Ok(())
}

/// Each `target_https` or `target_source_auth` breach of a saved `surface`, worded for the save
/// response's `Warning` header: in `warn` the credential is still sent; in `enforce`, which
/// lets a save keep only a breach the stored surface already had, it is withheld.
pub(super) fn target_rule_warnings(surface: &AgentSurface) -> Vec<String> {
    breaches(surface)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, message, policy_rule)| {
            let rule = policy_rule?;
            Some(if rule_mode(rule).is_enforced() {
                format!("{message}; the credential is withheld while credential_policy.{rule} is enforce")
            } else {
                warning(rule, &message)
            })
        })
        .collect()
}

/// Each `target_https` or `target_source_auth` breach of `surface`, on any leg of the base
/// surface or of a variant as it resolves.
pub(super) fn broken_target_rules(surface: &AgentSurface) -> Result<Vec<TargetCredentialRule>, SurfaceApiError> {
    Ok(breaches(surface)?
        .into_iter()
        .filter_map(|(.., policy_rule)| policy_rule)
        .collect())
}

fn warning(
    rule: TargetCredentialRule,
    message: &str,
) -> String {
    format!("{message}; it will be refused once credential_policy.{rule} is enforce")
}

fn rule_mode(rule: TargetCredentialRule) -> RuleMode {
    let policy = credential_policy();
    match rule {
        TargetCredentialRule::Https => policy.target_https,
        TargetCredentialRule::SourceAuth => policy.target_source_auth,
    }
}

/// Each rule a leg of `surface` breaks: the breach, its message, and the credential policy
/// rule it belongs to, if any.
type Found = (Breach, String, Option<TargetCredentialRule>);

fn breaches(surface: &AgentSurface) -> Result<Vec<Found>, SurfaceApiError> {
    let variants = std::iter::once(None).chain(
        surface
            .variants
            .iter()
            .map(Some),
    );
    let mut found = Vec::new();
    for (variant, view) in variants.zip(super::surface_tenancy::resolved_views(surface)?) {
        let variant = variant.map(|variant| (variant.id.as_str(), variant.alias.as_str()));
        found.extend(a2a_proxy_breach(&view, variant));
        for leg in legs(&view, variant) {
            let authentication = serde_json::to_value(leg.authentication).unwrap_or_default();
            for (rule, policy_rule) in broken_rules(&leg) {
                let message = format!("{}{rule}", leg.field);
                found.push((
                    Breach {
                        variant_id: leg
                            .variant_id
                            .map(str::to_string),
                        transit_point_id: leg
                            .transit_point_id
                            .map(str::to_string),
                        endpoint: leg.endpoint.to_string(),
                        authentication: authentication.clone(),
                        rule,
                    },
                    message,
                    policy_rule,
                ));
            }
        }
    }
    Ok(found)
}

/// The A2A proxy behind an `a2a-proxy://` Target of an A2A or AP2 surface sends its backend
/// credential on each caller's request, so the request path holds it to `target_source_auth`
/// as it does a Target credential. It goes to the proxy's own backend, not to the
/// `a2a-proxy://` endpoint, so `target_https` does not apply.
fn a2a_proxy_breach(
    view: &AgentSurface,
    variant: Option<(&str, &str)>,
) -> Option<Found> {
    let breaks = view.dispatches_to_a2a_proxy()
        && broken_target_credential_rules(true, view.authenticates_callers(), false)
            .contains(&TargetCredentialRule::SourceAuth);
    if !breaks {
        return None;
    }
    let prefix = variant
        .map(|(_, alias)| format!("variants['{alias}']."))
        .unwrap_or_default();
    let rule = " is an A2A proxy that sends its backend credential, so it needs source authentication on the \
                Access Point"
        .to_string();
    Some((
        Breach {
            variant_id: variant.map(|(id, _)| id.to_string()),
            transit_point_id: None,
            endpoint: view.target.endpoint.clone(),
            authentication: serde_json::Value::Null,
            rule: rule.clone(),
        },
        format!("{prefix}target{rule}"),
        Some(TargetCredentialRule::SourceAuth),
    ))
}

fn legs<'a>(
    view: &'a AgentSurface,
    variant: Option<(&'a str, &'a str)>,
) -> Vec<Leg<'a>> {
    let prefix = variant
        .map(|(_, alias)| format!("variants['{alias}']."))
        .unwrap_or_default();
    let bindings = view
        .outbound_credentials
        .iter()
        .filter_map(|binding| {
            binding
                .inject_as
                .header_name()
                .map(str::to_string)
        });
    let mut legs = Vec::new();
    if let Some(authentication) = view.target.auth.as_ref() {
        let mut other_headers: Vec<(String, &'static str)> = bindings
            .clone()
            .map(|name| (name, "a credential binding"))
            .collect();
        other_headers.extend(
            forwarded_source_auth_headers(view)
                .into_iter()
                .map(|name| (name, "source authentication")),
        );
        other_headers.extend(mapped_headers(
            view.access_point
                .header_metadata_mapping_if_supported(),
        ));
        legs.push(Leg {
            variant_id: variant.map(|(id, _)| id),
            transit_point_id: None,
            field: format!("{prefix}target.auth"),
            endpoint: &view.target.endpoint,
            authentication,
            checks_callers: view.authenticates_callers(),
            caller_check: "source authentication on the Access Point",
            other_headers,
        });
    }
    for point in view
        .transit
        .iter()
        .flat_map(|transit| transit.points.iter())
    {
        let Some(authentication) = point.target_auth.as_ref() else {
            continue;
        };
        let mut other_headers: Vec<(String, &'static str)> = Vec::new();
        if !point.withholds_delegated_credentials() {
            other_headers.extend(
                bindings
                    .clone()
                    .map(|name| (name, "a credential binding")),
            );
        }
        other_headers.extend(
            point
                .transit_credentials
                .as_ref()
                .and_then(|credentials| transit_binding_header(&credentials.inject_as))
                .map(|name| (name, "a credential binding")),
        );
        other_headers.extend(mapped_headers(point.header_metadata_mapping_if_supported()));
        legs.push(Leg {
            variant_id: variant.map(|(id, _)| id),
            transit_point_id: Some(&point.id),
            field: format!("{prefix}transit.points['{}'].target_auth", point.alias),
            endpoint: &point.target_endpoint,
            authentication,
            checks_callers: point.authenticates_callers(),
            caller_check: "a Transit Point that authenticates its callers",
            other_headers,
        });
    }
    legs
}

/// Each rule `leg` breaks, worded to follow the leg's field name, with the credential policy
/// rule it belongs to, if any.
fn broken_rules(leg: &Leg<'_>) -> Vec<(String, Option<TargetCredentialRule>)> {
    let (header_name, header_format) = match &leg.authentication.method {
        TargetAuthMethod::StaticSecret { header_name, header_format, .. }
        | TargetAuthMethod::CredentialProvider { header_name, header_format, .. } => {
            (header_name.as_str(), header_format.as_str())
        }
        TargetAuthMethod::CredentialLookup => return Vec::new(),
    };
    let mut rules = Vec::new();
    if !is_header_name(header_name) {
        rules.push((".header_name must be an HTTP header name".to_string(), None));
    } else if let Some(reserved) = reserved_header(header_name) {
        rules.push((format!(".header_name must not be the reserved header {reserved}"), None));
    } else if let Some((_, used_by)) = leg
        .other_headers
        .iter()
        .find(|(other, _)| same_header_name(other, header_name))
    {
        rules.push((format!(".header_name {header_name} is already sent by {used_by}"), None));
    }
    match header_format_problem(header_format) {
        Some(HeaderFormatProblem::ControlCharacter) => {
            rules.push((".header_format must not contain CR, LF or NUL".to_string(), None))
        }
        Some(HeaderFormatProblem::PlaceholderCount) => {
            rules.push((".header_format must contain {value} exactly once".to_string(), None))
        }
        None => {}
    }
    if !is_https_target(leg.endpoint) {
        let destination = if leg.transit_point_id.is_some() {
            "target endpoint"
        } else {
            "Target"
        };
        rules.push((
            format!(" sends a credential, so its {destination} must be an https URL"),
            Some(TargetCredentialRule::Https),
        ));
    }
    if !leg.checks_callers {
        rules.push((
            format!(" sends a credential, so it needs {}", leg.caller_check),
            Some(TargetCredentialRule::SourceAuth),
        ));
    }
    rules
}

/// The source-auth headers the Access Point can forward to its Target: those of its JWT Bearer
/// methods with `forward_header`. Every other source-auth header is removed before the Target
/// credential is added, so it cannot collide with it.
fn forwarded_source_auth_headers(view: &AgentSurface) -> Vec<String> {
    if view
        .mcp_http
        .as_ref()
        .is_some_and(|http| http.authorization.is_some())
    {
        return Vec::new();
    }
    view.source_auth_methods()
        .iter()
        .filter_map(|method| match method {
            crate::source_auth::SourceAuthConfig::JwtBearer(config) if config.forward_header => {
                Some(config.token_header.clone())
            }
            _ => None,
        })
        .collect()
}

fn mapped_headers(
    mapping: Option<&crate::config::header_metadata_mapping::HeaderMetadataMappingConfig>
) -> impl Iterator<Item = (String, &'static str)> + '_ {
    mapping
        .into_iter()
        .flat_map(|mapping| mapping.headers.iter())
        .map(|mapped| {
            (
                mapped
                    .header
                    .trim()
                    .to_string(),
                "header metadata mapping",
            )
        })
}

fn transit_binding_header(injection: &crate::config::agent_surface::CredentialInjection) -> Option<String> {
    use crate::config::agent_surface::CredentialInjection;
    match injection {
        CredentialInjection::BearerHeader => Some("Authorization".to_string()),
        CredentialInjection::CustomHeader { name, .. } => Some(name.clone()),
        CredentialInjection::Meta { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn static_secret(
        header_name: &str,
        header_format: &str,
    ) -> Value {
        json!({"method": {"static_secret": {
            "secret_id": "target-key", "header_name": header_name, "header_format": header_format
        }}})
    }

    /// A surface with an API key caller check and an https Target sending `target_auth`.
    fn surface(target_auth: Value) -> Value {
        json!({
            "name": "s",
            "access_point": {
                "listen_address": "0.0.0.0:8443", "route": "/s", "protocol": "a2a",
                "caller_authentication": {"methods": [{
                    "type": "api_key", "secret_id": "caller-key",
                    "extraction": {"source": "http_header", "field": "X-Caller-Key"}
                }]}
            },
            "target": {"endpoint": "https://api.example.com/", "auth": target_auth}
        })
    }

    fn with_transit_point(
        mut body: Value,
        point: Value,
    ) -> Value {
        let mut point_body = json!({
            "id": "partner-id", "alias": "partner", "target_endpoint": "https://partner.example.com/",
            "protocol": "a2a"
        });
        point_body
            .as_object_mut()
            .unwrap()
            .extend(
                point
                    .as_object()
                    .unwrap()
                    .clone(),
            );
        body["transit"] = json!({"points": [point_body]});
        body
    }

    fn policy(
        target_https: RuleMode,
        target_source_auth: RuleMode,
    ) -> &'static crate::config::credential_policy::CredentialPolicyConfig {
        Box::leak(Box::new(crate::config::credential_policy::CredentialPolicyConfig {
            target_https,
            target_source_auth,
            ..Default::default()
        }))
    }

    /// A surface whose Target is plain http and whose Access Point checks no caller.
    fn http_and_unchecked() -> Value {
        let mut body = surface(static_secret("X-Api-Key", "{value}"));
        body["target"]["endpoint"] = json!("http://api.example.com/");
        body["access_point"]
            .as_object_mut()
            .unwrap()
            .remove("caller_authentication");
        body
    }

    #[test]
    fn each_rule_refuses_on_save_only_in_its_own_enforce_mode() {
        let surface: AgentSurface = serde_json::from_value(http_and_unchecked()).unwrap();
        let validate = |https, source_auth| {
            crate::config::credential_policy::TEST_CREDENTIAL_POLICY.sync_scope(policy(https, source_auth), || {
                validate_target_auth_rules(&surface, None).map_err(|error| match error {
                    SurfaceApiError::BadRequest(message) => message,
                    other => panic!("unexpected error {other:?}"),
                })
            })
        };
        assert_eq!(
            validate(RuleMode::Warn, RuleMode::Enforce),
            Err("target.auth sends a credential, so it needs source authentication on the Access Point".to_string())
        );
        assert_eq!(
            validate(RuleMode::Enforce, RuleMode::Warn),
            Err("target.auth sends a credential, so its Target must be an https URL".to_string())
        );
        assert_eq!(validate(RuleMode::Warn, RuleMode::Warn), Ok(()));
    }

    #[test]
    fn a_breach_of_a_target_rule_is_a_save_warning_in_either_mode() {
        let surface: AgentSurface = serde_json::from_value(http_and_unchecked()).unwrap();
        let warnings = |https, source_auth| {
            crate::config::credential_policy::TEST_CREDENTIAL_POLICY
                .sync_scope(policy(https, source_auth), || target_rule_warnings(&surface))
        };
        assert_eq!(
            warnings(RuleMode::Warn, RuleMode::Warn),
            [
                "target.auth sends a credential, so its Target must be an https URL; it will be refused once credential_policy.target_https is enforce",
                "target.auth sends a credential, so it needs source authentication on the Access Point; it will be refused once credential_policy.target_source_auth is enforce",
            ]
        );
        assert_eq!(
            warnings(RuleMode::Enforce, RuleMode::Warn),
            [
                "target.auth sends a credential, so its Target must be an https URL; the credential is withheld while credential_policy.target_https is enforce",
                "target.auth sends a credential, so it needs source authentication on the Access Point; it will be refused once credential_policy.target_source_auth is enforce",
            ]
        );
        assert_eq!(
            warnings(RuleMode::Enforce, RuleMode::Enforce),
            [
                "target.auth sends a credential, so its Target must be an https URL; the credential is withheld while credential_policy.target_https is enforce",
                "target.auth sends a credential, so it needs source authentication on the Access Point; the credential is withheld while credential_policy.target_source_auth is enforce",
            ]
        );
        let mut header_breach = http_and_unchecked();
        header_breach["target"]["endpoint"] = json!("https://api.example.com/");
        header_breach["access_point"]["caller_authentication"] = surface_caller_check();
        header_breach["target"]["auth"] = static_secret("Bad Header", "{value}");
        let header_breach: AgentSurface = serde_json::from_value(header_breach).unwrap();
        assert!(
            crate::config::credential_policy::TEST_CREDENTIAL_POLICY
                .sync_scope(policy(RuleMode::Warn, RuleMode::Warn), || target_rule_warnings(&header_breach))
                .is_empty()
        );
    }

    fn surface_caller_check() -> Value {
        surface(Value::Null)["access_point"]["caller_authentication"].clone()
    }

    /// [`validate_target_auth_rules`] with `target_https` and `target_source_auth` in `enforce`.
    fn check(
        body: &Value,
        stored: Option<&Value>,
    ) -> Result<(), String> {
        check_in(RuleMode::Enforce, body, stored)
    }

    fn check_in(
        mode: RuleMode,
        body: &Value,
        stored: Option<&Value>,
    ) -> Result<(), String> {
        let policy = policy(mode, mode);
        let surface: AgentSurface = serde_json::from_value(body.clone()).unwrap();
        let stored: Option<AgentSurface> = stored.map(|stored| serde_json::from_value(stored.clone()).unwrap());
        crate::config::credential_policy::TEST_CREDENTIAL_POLICY.sync_scope(policy, || {
            validate_target_auth_rules(&surface, stored.as_ref()).map_err(|error| match error {
                SurfaceApiError::BadRequest(message) => message,
                other => panic!("unexpected error {other:?}"),
            })
        })
    }

    #[test]
    fn in_warn_a_new_http_target_or_unchecked_leg_saves_but_header_rules_still_refuse() {
        let mut body = with_transit_point(
            surface(static_secret("X-Api-Key", "{value}")),
            json!({"target_auth": static_secret("X-Partner-Key", "{value}"), "require_transit_token": false,
                   "allow_unauthenticated_callers": true}),
        );
        body["target"]["endpoint"] = json!("http://api.example.com/");
        body["transit"]["points"][0]["target_endpoint"] = json!("fabric://peer/partner");
        body["access_point"]
            .as_object_mut()
            .unwrap()
            .remove("caller_authentication");
        assert_eq!(check_in(RuleMode::Warn, &body, None), Ok(()));
        assert_eq!(
            check_in(RuleMode::Enforce, &body, None),
            Err("target.auth sends a credential, so its Target must be an https URL".to_string())
        );

        for (field, value, refusal) in [
            ("header_name", json!("Bad Header"), "target.auth.header_name must be an HTTP header name"),
            (
                "header_name",
                json!("X-Transit-Token"),
                "target.auth.header_name must not be the reserved header X-Transit-Token",
            ),
            ("header_format", json!("no placeholder"), "target.auth.header_format must contain {value} exactly once"),
        ] {
            let mut broken = body.clone();
            broken["target"]["auth"]["method"]["static_secret"][field] = value;
            assert_eq!(check_in(RuleMode::Warn, &broken, None), Err(refusal.to_string()), "{field}");
        }
    }

    #[test]
    fn a_target_authentication_meeting_every_rule_saves() {
        for target_auth in [
            static_secret("X-Api-Key", "{value}"),
            static_secret("Authorization", "Bearer {value}"),
            json!({"method": {"credential_provider": {"provider_id": "cp"}}}),
        ] {
            assert_eq!(check(&surface(target_auth.clone()), None), Ok(()), "{target_auth}");
        }
        let mut no_auth = surface(Value::Null);
        no_auth["target"]["endpoint"] = json!("http://api.example.com/");
        no_auth["access_point"]
            .as_object_mut()
            .unwrap()
            .remove("caller_authentication");
        assert_eq!(check(&no_auth, None), Ok(()), "a Target without a credential has no rule to meet");
    }

    #[test]
    fn a_header_name_that_is_not_a_token_or_is_reserved_is_refused() {
        for (header_name, message) in [
            ("X Api", "target.auth.header_name must be an HTTP header name"),
            ("X-Api:", "target.auth.header_name must be an HTTP header name"),
            ("", "target.auth.header_name must be an HTTP header name"),
            ("host", "target.auth.header_name must not be the reserved header Host"),
            ("TE", "target.auth.header_name must not be the reserved header TE"),
            ("upgrade", "target.auth.header_name must not be the reserved header Upgrade"),
            ("Proxy-Connection", "target.auth.header_name must not be the reserved header Proxy-Connection"),
        ] {
            assert_eq!(
                check(&surface(static_secret(header_name, "{value}")), None),
                Err(message.to_string()),
                "{header_name}"
            );
        }
    }

    #[test]
    fn a_format_without_exactly_one_placeholder_or_with_a_line_break_or_nul_is_refused() {
        for (format, message) in [
            ("Bearer", "target.auth.header_format must contain {value} exactly once"),
            ("{value}{value}", "target.auth.header_format must contain {value} exactly once"),
            ("Bearer {value}\r", "target.auth.header_format must not contain CR, LF or NUL"),
            ("Bearer {value}\nX-Other: 1", "target.auth.header_format must not contain CR, LF or NUL"),
            ("{value}\0", "target.auth.header_format must not contain CR, LF or NUL"),
        ] {
            assert_eq!(
                check(&surface(static_secret("X-Api-Key", format)), None),
                Err(message.to_string()),
                "{format:?}"
            );
        }
        let provider = json!({"method": {"credential_provider": {"provider_id": "cp", "header_format": "Bearer"}}});
        assert_eq!(
            check(&surface(provider), None),
            Err("target.auth.header_format must contain {value} exactly once".to_string())
        );
    }

    #[test]
    fn a_credential_needs_an_https_target() {
        for endpoint in ["http://api.example.com/", "fabric://gateway-1", "a2a-proxy://proxy-1"] {
            let mut body = surface(static_secret("X-Api-Key", "{value}"));
            body["target"]["endpoint"] = json!(endpoint);
            assert_eq!(
                check(&body, None),
                Err("target.auth sends a credential, so its Target must be an https URL".to_string()),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn a_credential_needs_an_access_point_that_checks_its_callers() {
        let mut body = surface(static_secret("X-Api-Key", "{value}"));
        body["access_point"]
            .as_object_mut()
            .unwrap()
            .remove("caller_authentication");
        assert_eq!(
            check(&body, None),
            Err("target.auth sends a credential, so it needs source authentication on the Access Point".to_string())
        );
        body["access_point"]["protocol"] = json!("mcp");
        body["mcp_http"] = json!({"authorization": {"resource": "https://gateway.example.com/s"}});
        assert_eq!(check(&body, None), Ok(()), "a resource access token checks the caller");
    }

    /// A JWT Bearer method reading `Authorization` and an API key method reading `X-Caller-Key`.
    fn two_methods() -> Value {
        json!({"methods": [
            {"type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": []},
            {"type": "api_key", "secret_id": "caller-key",
             "extraction": {"source": "http_header", "field": "X-Caller-Key"}}
        ]})
    }

    fn warnings_in(
        mode: RuleMode,
        body: &Value,
    ) -> Vec<String> {
        let surface: AgentSurface = serde_json::from_value(body.clone()).unwrap();
        crate::config::credential_policy::TEST_CREDENTIAL_POLICY
            .sync_scope(policy(mode, mode), || target_rule_warnings(&surface))
    }

    #[test]
    fn an_access_point_with_several_methods_checks_its_callers_and_one_with_none_does_not() {
        let mut body = surface(static_secret("X-Api-Key", "{value}"));
        body["access_point"]["caller_authentication"] = two_methods();
        assert_eq!(check(&body, None), Ok(()));
        assert!(warnings_in(RuleMode::Enforce, &body).is_empty());

        const UNCHECKED: &str = "target.auth sends a credential, so it needs source authentication on the Access Point";
        let mut none = body.clone();
        none["access_point"]["caller_authentication"] = json!({"methods": []});
        assert_eq!(check(&none, None), Err(UNCHECKED.to_string()));
        assert_eq!(check_in(RuleMode::Warn, &none, None), Ok(()));
        assert_eq!(
            warnings_in(RuleMode::Warn, &none),
            [format!("{UNCHECKED}; it will be refused once credential_policy.target_source_auth is enforce")]
        );

        let mut variant = body.clone();
        variant["variants"] = json!([{
            "id": "open-id", "alias": "open", "name": "Open",
            "overrides": {"access_point": {"caller_authentication": {"methods": []}}}
        }]);
        assert_eq!(check(&variant, None), Err(format!("variants['open'].{UNCHECKED}")));
    }

    #[test]
    fn a_header_any_forwarding_jwt_method_sends_collides_with_the_credential() {
        let jwt = |token_header: &str, forward_header: bool| {
            json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": [],
                   "token_header": token_header, "forward_header": forward_header})
        };
        let api_key = json!({"type": "api_key", "secret_id": "caller-key",
                             "extraction": {"source": "http_header", "field": "X-Caller-Key"}});
        let with = |methods: Value, header_name: &str| {
            let mut body = surface(static_secret(header_name, "{value}"));
            body["access_point"]["caller_authentication"] = json!({"methods": methods});
            body
        };
        let second_forwards = json!([jwt("Authorization", false), jwt("X-User-Token", true)]);
        for header_name in ["X_User_Token", "x-user-token"] {
            assert_eq!(
                check(&with(second_forwards.clone(), header_name), None),
                Err(format!("target.auth.header_name {header_name} is already sent by source authentication")),
                "{header_name}"
            );
        }
        assert_eq!(
            check(&with(json!([api_key.clone(), jwt("X-User-Token", true)]), "X_User_Token"), None),
            Err("target.auth.header_name X_User_Token is already sent by source authentication".to_string()),
            "a forwarding method after an API key method"
        );
        assert_eq!(
            check(&with(json!([jwt("Authorization", false), jwt("X-User-Token", false)]), "X_User_Token"), None),
            Ok(()),
            "a token that is not forwarded is removed before the credential is added"
        );
        assert_eq!(
            check(&with(json!([api_key, jwt("X-User-Token", true)]), "X-Caller-Key"), None),
            Ok(()),
            "an API key is removed before the credential is added"
        );
    }

    #[test]
    fn an_access_point_with_several_methods_does_not_check_a_transit_points_callers() {
        let mut base = surface(Value::Null);
        base["access_point"]["caller_authentication"] = two_methods();
        let auth = static_secret("X-Partner-Key", "{value}");
        let open = with_transit_point(
            base.clone(),
            json!({"target_auth": auth, "require_transit_token": false, "allow_unauthenticated_callers": true}),
        );
        const UNCHECKED: &str = "transit.points['partner'].target_auth sends a credential, so it needs a Transit \
                                 Point that authenticates its callers";
        assert_eq!(check(&open, None), Err(UNCHECKED.to_string()));
        assert_eq!(check_in(RuleMode::Warn, &open, None), Ok(()));
        assert_eq!(
            warnings_in(RuleMode::Warn, &open),
            [format!("{UNCHECKED}; it will be refused once credential_policy.target_source_auth is enforce")]
        );

        let tokened = with_transit_point(base, json!({"target_auth": auth}));
        assert_eq!(check(&tokened, None), Ok(()));
        assert!(warnings_in(RuleMode::Enforce, &tokened).is_empty());
    }

    #[test]
    fn a_header_another_credential_on_the_leg_sends_is_refused() {
        let mut bound = surface(static_secret("authorization", "Bearer {value}"));
        bound["outbound_credentials"] = json!([{"credential_provider_id": "bound"}]);
        assert_eq!(
            check(&bound, None),
            Err("target.auth.header_name authorization is already sent by a credential binding".to_string())
        );
        bound["target"]["auth"] = static_secret("X-Api-Key", "{value}");
        assert_eq!(check(&bound, None), Ok(()));

        let mut custom = surface(static_secret("X-Github-Token", "{value}"));
        custom["outbound_credentials"] = json!([{
            "credential_provider_id": "bound",
            "inject_as": {"type": "custom_header", "name": "x-github-token", "format": "token {value}"}
        }]);
        assert_eq!(
            check(&custom, None),
            Err("target.auth.header_name X-Github-Token is already sent by a credential binding".to_string())
        );

        let mut mapped = surface(static_secret("X-Tenant", "{value}"));
        mapped["access_point"]["header_metadata_mapping"] = json!({"headers": [{"header": "x-tenant", "field": "t"}]});
        assert_eq!(
            check(&mapped, None),
            Err("target.auth.header_name X-Tenant is already sent by header metadata mapping".to_string())
        );
        mapped["access_point"]["header_metadata_mapping"] = json!({"headers": [{"header": "X-Other", "field": "t"}]});
        assert_eq!(check(&mapped, None), Ok(()));
    }

    #[test]
    fn only_a_forwarded_source_auth_header_collides_with_the_credential() {
        let jwt = |forward_header: bool| {
            let mut body = surface(static_secret("Authorization", "Bearer {value}"));
            body["access_point"]["caller_authentication"] = json!({"methods": [{
                "type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": [],
                "forward_header": forward_header
            }]});
            body
        };
        assert_eq!(check(&jwt(false), None), Ok(()), "the caller's token is removed before the credential is added");
        assert_eq!(
            check(&jwt(true), None),
            Err("target.auth.header_name Authorization is already sent by source authentication".to_string())
        );
    }

    #[test]
    fn a_transit_point_credential_needs_an_https_target_and_a_transit_point_that_checks_callers() {
        let base = surface(Value::Null);
        let auth = static_secret("X-Partner-Key", "{value}");
        let checked = with_transit_point(base.clone(), json!({"target_auth": auth}));
        assert_eq!(check(&checked, None), Ok(()), "a Transit Point requires a transit token by default");

        let open = with_transit_point(
            base.clone(),
            json!({"target_auth": auth, "require_transit_token": false, "allow_unauthenticated_callers": true}),
        );
        assert_eq!(
            check(&open, None),
            Err("transit.points['partner'].target_auth sends a credential, so it needs a Transit Point that \
                 authenticates its callers"
                .to_string())
        );
        let keyed = with_transit_point(
            base.clone(),
            json!({"target_auth": auth, "require_transit_token": false, "source_auth": {
                "type": "api_key", "secret_id": "agent-key",
                "extraction": {"source": "http_header", "field": "X-Agent-Key"}
            }}),
        );
        assert_eq!(check(&keyed, None), Ok(()));

        let plain =
            with_transit_point(base, json!({"target_auth": auth, "target_endpoint": "http://partner.example.com/"}));
        assert_eq!(
            check(&plain, None),
            Err(
                "transit.points['partner'].target_auth sends a credential, so its target endpoint must be an https URL"
                    .to_string()
            )
        );
    }

    #[test]
    fn a_variant_target_is_named_by_its_alias() {
        let mut body = surface(static_secret("X-Api-Key", "{value}"));
        body["variants"] = json!([{
            "id": "staging-id", "alias": "staging", "name": "Staging",
            "overrides": {"target": {"endpoint": "http://staging.example.com/"}}
        }]);
        assert_eq!(
            check(&body, None),
            Err("variants['staging'].target.auth sends a credential, so its Target must be an https URL".to_string())
        );
    }

    #[test]
    fn a_stored_breach_is_kept_while_the_leg_keeps_its_setting_and_endpoint() {
        let mut stored = with_transit_point(
            surface(static_secret("X-Api-Key", "{value}")),
            json!({"target_auth": static_secret("X-Partner-Key", "Bearer"), "require_transit_token": false,
                   "allow_unauthenticated_callers": true}),
        );
        stored["target"]["endpoint"] = json!("http://api.example.com/");
        stored["access_point"]
            .as_object_mut()
            .unwrap()
            .remove("caller_authentication");
        assert!(check(&stored, None).is_err(), "a new surface like it is refused");
        assert_eq!(check(&stored, Some(&stored)), Ok(()));

        let mut renamed = stored.clone();
        renamed["name"] = json!("renamed");
        renamed["transit"]["points"][0]["alias"] = json!("partner-renamed");
        assert_eq!(check(&renamed, Some(&stored)), Ok(()), "renaming a leg keeps it");

        let mut reformatted = stored.clone();
        reformatted["target"]["auth"] = static_secret("X-Api-Key", "Token {value}");
        assert_eq!(
            check(&reformatted, Some(&stored)),
            Err("target.auth sends a credential, so its Target must be an https URL".to_string())
        );

        let mut redirected = stored.clone();
        redirected["transit"]["points"][0]["target_endpoint"] = json!("https://elsewhere.example.com/");
        assert_eq!(
            check(&redirected, Some(&stored)),
            Err("transit.points['partner'].target_auth.header_format must contain {value} exactly once".to_string())
        );

        let mut new_leg = stored.clone();
        new_leg["transit"]["points"][0]["id"] = json!("replacement-id");
        assert!(check(&new_leg, Some(&stored)).is_err(), "a new leg is checked in full");

        let mut newly_mapped = stored.clone();
        newly_mapped["access_point"]["header_metadata_mapping"] =
            json!({"headers": [{"header": "X-Api-Key", "field": "k"}]});
        assert_eq!(
            check(&newly_mapped, Some(&stored)),
            Err("target.auth.header_name X-Api-Key is already sent by header metadata mapping".to_string()),
            "a rule the stored leg met is enforced even though the setting is unchanged"
        );
    }

    /// An A2A surface whose Target is an A2A proxy and whose Access Point checks no caller.
    fn unchecked_a2a_proxy() -> Value {
        let mut body = surface(Value::Null);
        body["target"] = json!({"endpoint": "a2a-proxy://proxy-1"});
        body["access_point"]
            .as_object_mut()
            .unwrap()
            .remove("caller_authentication");
        body
    }

    const A2A_PROXY_UNCHECKED: &str = "target is an A2A proxy that sends its backend credential, so it needs source authentication on the Access Point";

    #[test]
    fn an_a2a_proxy_target_needs_an_access_point_that_checks_its_callers() {
        let body = unchecked_a2a_proxy();
        assert_eq!(check_in(RuleMode::Warn, &body, None), Ok(()));
        assert_eq!(check(&body, None), Err(A2A_PROXY_UNCHECKED.to_string()));
        assert_eq!(check(&body, Some(&body)), Ok(()), "an unchanged stored breach saves");
        let kept: AgentSurface = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(
            crate::config::credential_policy::TEST_CREDENTIAL_POLICY
                .sync_scope(policy(RuleMode::Enforce, RuleMode::Enforce), || target_rule_warnings(&kept)),
            vec![format!(
                "{A2A_PROXY_UNCHECKED}; the credential is withheld while credential_policy.target_source_auth is enforce"
            )],
            "an unchanged stored breach saves with the withheld Warning"
        );

        let mut moved = body.clone();
        moved["target"]["endpoint"] = json!("a2a-proxy://proxy-2");
        assert_eq!(check(&moved, Some(&body)), Err(A2A_PROXY_UNCHECKED.to_string()), "another proxy is a new breach");

        let mut checked = body.clone();
        checked["access_point"]["caller_authentication"] = surface_caller_check();
        assert_eq!(check(&checked, None), Ok(()));

        let mut mcp = body.clone();
        mcp["access_point"]["protocol"] = json!("mcp");
        assert_eq!(check(&mcp, None), Ok(()), "only an A2A or AP2 surface dispatches to an A2A proxy");

        let mut variant = surface(Value::Null);
        variant["access_point"]
            .as_object_mut()
            .unwrap()
            .remove("caller_authentication");
        variant["variants"] = json!([{
            "id": "proxy-id", "alias": "proxied", "name": "Proxied",
            "overrides": {"target": {"endpoint": "a2a-proxy://proxy-1"}}
        }]);
        assert_eq!(check(&variant, None), Err(format!("variants['proxied'].{A2A_PROXY_UNCHECKED}")));
    }

    #[test]
    fn an_a2a_proxy_target_meets_the_rule_with_several_methods_and_breaks_it_with_none() {
        let mut body = unchecked_a2a_proxy();
        body["access_point"]["caller_authentication"] = two_methods();
        assert_eq!(check(&body, None), Ok(()));
        assert!(warnings_in(RuleMode::Enforce, &body).is_empty());

        let mut none = body.clone();
        none["access_point"]["caller_authentication"] = json!({"methods": []});
        assert_eq!(check(&none, None), Err(A2A_PROXY_UNCHECKED.to_string()));
        assert_eq!(check_in(RuleMode::Warn, &none, None), Ok(()));
        assert_eq!(
            warnings_in(RuleMode::Warn, &none),
            [format!("{A2A_PROXY_UNCHECKED}; it will be refused once credential_policy.target_source_auth is enforce")]
        );
    }

    #[test]
    fn an_a2a_proxy_target_is_not_held_to_target_https() {
        let unchecked: AgentSurface = serde_json::from_value(unchecked_a2a_proxy()).unwrap();
        let mut checked_body = unchecked_a2a_proxy();
        checked_body["access_point"]["caller_authentication"] = surface_caller_check();
        let checked: AgentSurface = serde_json::from_value(checked_body).unwrap();
        let under = |https, source_auth, surface: &AgentSurface| {
            crate::config::credential_policy::TEST_CREDENTIAL_POLICY.sync_scope(policy(https, source_auth), || {
                (validate_target_auth_rules(surface, None).is_ok(), target_rule_warnings(surface))
            })
        };
        assert_eq!(under(RuleMode::Enforce, RuleMode::Enforce, &checked), (true, Vec::<String>::new()));
        assert_eq!(under(RuleMode::Enforce, RuleMode::Warn, &checked), (true, Vec::<String>::new()));
        assert_eq!(
            under(RuleMode::Enforce, RuleMode::Warn, &unchecked),
            (
                true,
                vec![format!(
                    "{A2A_PROXY_UNCHECKED}; it will be refused once credential_policy.target_source_auth is enforce"
                )]
            )
        );
        assert_eq!(
            under(RuleMode::Warn, RuleMode::Enforce, &unchecked),
            (
                false,
                vec![format!(
                    "{A2A_PROXY_UNCHECKED}; the credential is withheld while credential_policy.target_source_auth is \
                     enforce"
                )]
            )
        );
    }

    #[test]
    fn a_header_name_spelled_with_underscores_matches_the_same_header() {
        assert_eq!(
            check(&surface(static_secret("X_Transit_Token", "{value}")), None),
            Err("target.auth.header_name must not be the reserved header X-Transit-Token".to_string())
        );

        let mut bound = surface(static_secret("X-Api-Key", "{value}"));
        bound["outbound_credentials"] = json!([{
            "credential_provider_id": "bound",
            "inject_as": {"type": "custom_header", "name": "X_Api_Key", "format": "{value}"}
        }]);
        assert_eq!(
            check(&bound, None),
            Err("target.auth.header_name X-Api-Key is already sent by a credential binding".to_string())
        );
        bound["outbound_credentials"][0]["inject_as"]["name"] = json!("X_Api_Keys");
        assert_eq!(check(&bound, None), Ok(()));

        let jwt = |token_header: &str| {
            let mut body = surface(static_secret("X-User-Token", "{value}"));
            body["access_point"]["caller_authentication"] = json!({"methods": [{
                "type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": [],
                "forward_header": true, "token_header": token_header
            }]});
            body
        };
        assert_eq!(
            check(&jwt("X_User_Token"), None),
            Err("target.auth.header_name X-User-Token is already sent by source authentication".to_string())
        );
        assert_eq!(check(&jwt("X-Caller-Token"), None), Ok(()));
    }
}
