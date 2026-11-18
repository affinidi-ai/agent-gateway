//! Save-time rules for Response authentication (`target.response_auth`), on the surface and
//! each variant as it resolves: only an http or https Target, which a managed agent answers,
//! may set it; its header is held to the Target authentication header rules; its API key secret
//! is none the surface sends to the Target or a Transit Point or accepts from callers, and holds a
//! non-blank key; its certificates are active; and an API key
//! read from an `http://` Target follows `credential_policy.target_https`: saved with a
//! warning in `warn`, refused in `enforce` unless the stored surface already had the same
//! setting on the same Target. mTLS needs an `https://` Target not bound by external consent
//! and certificates of the kind its trust takes. Whether its secret or certificates exist and the surface may use them is
//! checked with the surface's other references.

use tracing::warn;

use crate::certificates::{Certificate, CertificateKind, CertificateStore};
use crate::config::TargetAuthMethod;
use crate::config::agent_surface::AgentSurface;
use crate::config::agent_surface_variants::SurfaceOverrides;
use crate::config::credential_policy::credential_policy;
use crate::config::response_auth::{MtlsResponseAuth, ResponseAuthConfig};
use crate::config::target_auth_rules::{TargetCredentialRule, is_header_name, reserved_header, same_header_name};
use crate::source_auth::SourceAuthConfig;
use crate::source_auth::models::MtlsTrust;

use super::surfaces::SurfaceApiError;

/// The setting on one view of a surface, the base surface or a variant by id, with what
/// identifies it so the same setting on the stored surface can be recognised.
#[derive(PartialEq)]
struct Setting {
    variant_id: Option<String>,
    endpoint: String,
    response_auth: ResponseAuthConfig,
}

/// A view's setting, with the field name it is reported under.
struct Placed {
    field: String,
    view: AgentSurface,
    setting: Setting,
}

/// Refuses the first `target.response_auth` of `surface` that breaks a rule: a Target that is
/// not an http or https URL, mTLS on a Target that is not https ([`mtls_rule`]), a header that
/// is not an HTTP field name, is reserved, has a meaning on the response ([`RESPONSE_HEADERS`])
/// or is already sent to the Target, a key secret the
/// surface also sends to the Target or a Transit Point or accepts from callers ([`shares_a_secret`]),
/// and an API key on
/// an `http://` Target while `credential_policy.target_https` is `enforce`, unless `stored` had
/// the same setting on the same Target. An `http://` Target in `warn` is logged and saved.
pub(super) fn validate_response_auth_rules(
    surface: &AgentSurface,
    stored: Option<&AgentSurface>,
) -> Result<(), SurfaceApiError> {
    let kept: Vec<Setting> = stored
        .and_then(|stored| placed(stored).ok())
        .into_iter()
        .flatten()
        .map(|placed| placed.setting)
        .collect();
    let enforced = credential_policy()
        .target_https
        .is_enforced();
    let mut warned = Vec::new();
    for Placed { field, view, setting } in placed(surface)? {
        if !is_http_url(&setting.endpoint) && !is_https_url(&setting.endpoint) {
            return Err(SurfaceApiError::BadRequest(format!(
                "{field} needs an http or https Target: no managed agent answers a proxy://, a2a-proxy:// or \
                 fabric:// Target"
            )));
        }
        let config = match &setting.response_auth {
            ResponseAuthConfig::ApiKey(config) => config,
            ResponseAuthConfig::Mtls(config) => {
                mtls_rule(&field, &view, &setting.endpoint, config)?;
                continue;
            }
        };
        if let Some(rule) = header_rule(&view, &config.header_name) {
            return Err(SurfaceApiError::BadRequest(format!("{field}.api_key.header_name {rule}")));
        }
        if shares_a_secret(&view, &config.secret_id) {
            return Err(SurfaceApiError::BadRequest(format!(
                "{field}.api_key.secret_id must not be a secret the gateway sends to the Target or a Transit Point \
                 or accepts from callers"
            )));
        }
        if is_http_url(&setting.endpoint) {
            let message = in_clear(&field);
            if enforced && !kept.contains(&setting) {
                return Err(SurfaceApiError::BadRequest(message));
            }
            if !enforced {
                warned.push(message);
            }
        }
    }
    for message in warned {
        warn!(
            surface_id = %surface.surface_id,
            rule = TargetCredentialRule::Https.key(),
            "A Response authentication being saved breaks a credential policy rule: {}",
            will_be_refused(&message)
        );
    }
    Ok(())
}

/// A PUT of the whole surface that leaves out `target.response_auth` keeps the stored one, and
/// so does a variant's `overrides.target` that leaves it out, for a variant of the same id; a
/// `null` removes it. `sent` is the JSON the PUT sent. A variant whose overrides send no
/// `target` is left as sent.
pub(super) fn retain_response_auth(
    surface: &mut AgentSurface,
    existing: &AgentSurface,
    sent: &serde_json::Value,
) {
    if leaves_out_response_auth(sent.get("target")) {
        surface
            .target
            .response_auth
            .clone_from(&existing.target.response_auth);
    }
    for (index, variant) in surface
        .variants
        .iter_mut()
        .enumerate()
    {
        if let Some(stored) = existing
            .variants
            .iter()
            .find(|stored| stored.id == variant.id)
        {
            retain_override_response_auth(
                &mut variant.overrides,
                &stored.overrides,
                sent.pointer(&format!("/variants/{index}/overrides/target")),
            );
        }
    }
}

/// [`retain_response_auth`] for one variant's `overrides`, replacing its `stored` ones, whose
/// `target` the request sent as `sent_target`.
pub(super) fn retain_override_response_auth(
    overrides: &mut SurfaceOverrides,
    stored: &SurfaceOverrides,
    sent_target: Option<&serde_json::Value>,
) {
    if let Some(target) = overrides.target.as_mut()
        && leaves_out_response_auth(sent_target)
    {
        target.response_auth = stored
            .target
            .as_ref()
            .and_then(|target| target.response_auth.clone());
    }
}

fn leaves_out_response_auth(sent_target: Option<&serde_json::Value>) -> bool {
    sent_target.is_some_and(|target| {
        target
            .get("response_auth")
            .is_none()
    })
}

/// Each `target.response_auth` of a saved `surface` that reads its key from an `http://`
/// Target, worded for the save response's `Warning` header by the `target_https` mode.
pub(super) fn response_auth_warnings(surface: &AgentSurface) -> Vec<String> {
    let enforced = credential_policy()
        .target_https
        .is_enforced();
    placed(surface)
        .unwrap_or_default()
        .into_iter()
        .filter(|placed| {
            matches!(placed.setting.response_auth, ResponseAuthConfig::ApiKey(_))
                && is_http_url(&placed.setting.endpoint)
        })
        .map(|placed| {
            let message = in_clear(&placed.field);
            if enforced {
                format!(
                    "{message}; a save that changes it is refused while credential_policy.{} is enforce",
                    TargetCredentialRule::Https
                )
            } else {
                will_be_refused(&message)
            }
        })
        .collect()
}

/// Refuses an mTLS setting on a Target that is not https, on a Target bound by external
/// consent, whose requests go out on the grant's own client, one whose server trust names no
/// certificate, and a CA trust that asks for a CRL or OCSP check, which is not supported.
fn mtls_rule(
    field: &str,
    view: &AgentSurface,
    endpoint: &str,
    config: &MtlsResponseAuth,
) -> Result<(), SurfaceApiError> {
    if !is_https_url(endpoint) {
        return Err(SurfaceApiError::BadRequest(format!(
            "{field}.mtls needs an https Target: only TLS proves the managed agent's certificate"
        )));
    }
    if crate::proxy::target_grant::binds_the_target(view) {
        return Err(SurfaceApiError::BadRequest(format!(
            "{field}: mTLS can't be used with a Target bound by external consent; use the api_key method"
        )));
    }
    if config
        .trust_certificate_ids()
        .is_empty()
    {
        return Err(SurfaceApiError::BadRequest(format!(
            "{field}.mtls.server_trust must name at least one certificate"
        )));
    }
    if let MtlsTrust::Ca { check_crl, require_ocsp, .. } = &config.server_trust
        && (*check_crl || *require_ocsp)
    {
        return Err(SurfaceApiError::BadRequest(format!(
            "{field}.mtls.server_trust cannot check CRLs or OCSP: set check_crl and require_ocsp to false"
        )));
    }
    Ok(())
}

/// Refuses an mTLS `target.response_auth` of `surface`, or of a variant as it resolves, that
/// names a certificate of the wrong kind or an inactive one: `pinned` server trust takes client
/// leaf certificates, `ca` server trust CA certificates, and the client certificate is a client
/// leaf certificate stored with its private key. Whether each certificate exists and the surface may use it is
/// checked with the surface's other references.
pub(super) async fn validate_response_auth_certificates(
    certificates: Option<&dyn CertificateStore>,
    surface: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    for Placed { field, setting, .. } in placed(surface)? {
        let ResponseAuthConfig::Mtls(config) = &setting.response_auth else {
            continue;
        };
        let trust_kind = match &config.server_trust {
            MtlsTrust::Pinned { .. } => CertificateKind::ClientLeaf,
            MtlsTrust::Ca { .. } => CertificateKind::Ca,
        };
        for id in config.trust_certificate_ids() {
            let certificate = stored_certificate(certificates, id).await?;
            if certificate.kind != trust_kind {
                return Err(SurfaceApiError::BadRequest(format!(
                    "{field}.mtls.server_trust certificate {id} must be a {} certificate",
                    kind_name(trust_kind)
                )));
            }
            if !certificate.active {
                return Err(SurfaceApiError::BadRequest(format!(
                    "{field}.mtls.server_trust certificate {id} must be active"
                )));
            }
        }
        let Some(id) = config
            .client_certificate_id
            .as_deref()
        else {
            continue;
        };
        let certificate = stored_certificate(certificates, id).await?;
        if certificate.kind != CertificateKind::ClientLeaf {
            return Err(SurfaceApiError::BadRequest(format!(
                "{field}.mtls.client_certificate_id {id} must be a {} certificate",
                kind_name(CertificateKind::ClientLeaf)
            )));
        }
        if !certificate.active {
            return Err(SurfaceApiError::BadRequest(format!("{field}.mtls.client_certificate_id {id} must be active")));
        }
        if certificate
            .private_key_pem
            .as_deref()
            .is_none_or(|key| key.trim().is_empty())
        {
            return Err(SurfaceApiError::BadRequest(format!(
                "{field}.mtls.client_certificate_id {id} must be stored with its private key"
            )));
        }
    }
    Ok(())
}

/// Refuses an API key `target.response_auth` of `surface`, or of a variant as it resolves, whose
/// secret holds no non-blank key, which the request path could never match. Whether the secret
/// exists and the surface may use it is checked with the surface's other references.
pub(super) async fn validate_response_auth_secrets(
    secrets: Option<&dyn crate::secrets::SecretsStore>,
    surface: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    for Placed { field, setting, .. } in placed(surface)? {
        let ResponseAuthConfig::ApiKey(config) = &setting.response_auth else {
            continue;
        };
        let secret = secrets
            .ok_or_else(|| SurfaceApiError::InternalError("Secrets store is not configured".to_string()))?
            .get_by_secret_id(&config.secret_id)
            .await
            .map_err(|error| super::surface_tenancy::internal("Secret", error))?
            .ok_or_else(|| super::surface_tenancy::inaccessible("Secret"))?;
        if !crate::proxy::response_auth::holds_a_key(&zeroize::Zeroizing::new(secret.value)) {
            return Err(SurfaceApiError::BadRequest(format!(
                "{field}.api_key.secret_id {} must hold at least one non-blank key",
                config.secret_id
            )));
        }
    }
    Ok(())
}

async fn stored_certificate(
    certificates: Option<&dyn CertificateStore>,
    id: &str,
) -> Result<Certificate, SurfaceApiError> {
    certificates
        .ok_or_else(|| SurfaceApiError::InternalError("Certificate store is not configured".to_string()))?
        .get(id)
        .await
        .map_err(|error| super::surface_tenancy::internal("Certificate", error))?
        .ok_or_else(|| super::surface_tenancy::inaccessible("Certificate"))
}

fn kind_name(kind: CertificateKind) -> &'static str {
    match kind {
        CertificateKind::ServerLeaf => "server_leaf",
        CertificateKind::ClientLeaf => "client_leaf",
        CertificateKind::Ca => "ca",
    }
}

fn in_clear(field: &str) -> String {
    format!("{field} receives an API key, so its Target must be an https URL")
}

fn will_be_refused(message: &str) -> String {
    format!("{message}; it will be refused once credential_policy.{} is enforce", TargetCredentialRule::Https)
}

/// The `target.response_auth` of the base surface and of each variant as it resolves.
fn placed(surface: &AgentSurface) -> Result<Vec<Placed>, SurfaceApiError> {
    let variants = std::iter::once(None).chain(
        surface
            .variants
            .iter()
            .map(Some),
    );
    Ok(variants
        .zip(super::surface_tenancy::resolved_views(surface)?)
        .filter_map(|(variant, view)| {
            let response_auth = view
                .target
                .response_auth
                .clone()?;
            let prefix = variant
                .map(|variant| format!("variants['{}'].", variant.alias))
                .unwrap_or_default();
            Some(Placed {
                field: format!("{prefix}target.response_auth"),
                setting: Setting {
                    variant_id: variant.map(|variant| variant.id.clone()),
                    endpoint: view
                        .target
                        .endpoint
                        .trim()
                        .to_string(),
                    response_auth,
                },
                view,
            })
        })
        .collect())
}

/// Response headers the gateway reads from the Target's response or passes on to the caller with
/// a meaning for it, including the payment headers it sets; the key header, removed from every
/// response, must not be one of them.
const RESPONSE_HEADERS: [&str; 21] = [
    "Content-Type",
    "Content-Encoding",
    "Content-Range",
    "Content-Disposition",
    "Location",
    "Set-Cookie",
    "WWW-Authenticate",
    "Cache-Control",
    "ETag",
    "Last-Modified",
    "Vary",
    "Retry-After",
    "Payment-Required",
    "Payment-Response",
    "Payment-Receipt",
    "Payment-Receipt-VC-Fingerprint",
    "Payment-Authorization",
    "Payment-Capture-Deadline",
    "X-Payment-Required",
    "X-Payment-Response",
    "X-Payment-Receipt",
];

/// The header rule `header_name` breaks on `view`, worded to follow the field name.
fn header_rule(
    view: &AgentSurface,
    header_name: &str,
) -> Option<String> {
    if !is_header_name(header_name) {
        return Some("must be an HTTP header name".to_string());
    }
    if let Some(reserved) = reserved_header(header_name) {
        return Some(format!("must not be the reserved header {reserved}"));
    }
    if let Some(meaningful) = RESPONSE_HEADERS
        .into_iter()
        .find(|name| same_header_name(name, header_name))
    {
        return Some(format!("must not be {meaningful}, which the gateway reads or sets on the Target's response"));
    }
    let mut sent = super::surface_target_auth::target_leg_headers(view);
    sent.extend(
        view.target
            .auth
            .as_ref()
            .and_then(|auth| auth.method.header_name())
            .map(|name| (name.to_string(), "Target authentication")),
    );
    sent.extend(
        view.caller_key
            .as_ref()
            .map(|caller_key| (caller_key.header.clone(), "caller_key")),
    );
    sent.iter()
        .find(|(name, _)| same_header_name(name, header_name))
        .map(|(_, used_by)| format!("{header_name} is already sent to the Target by {used_by}"))
}

/// Whether `secret_id` is a secret `view` also sends to its Target, by Target authentication or
/// `caller_key`, sends to a Transit Point by its Target authentication, or accepts from its
/// callers by an API key method, so the managed agent, another agent, or a caller would already
/// hold the key its responses are checked against.
fn shares_a_secret(
    view: &AgentSurface,
    secret_id: &str,
) -> bool {
    fn static_secret(auth: &crate::config::TargetAuthConfig) -> Option<&str> {
        match &auth.method {
            TargetAuthMethod::StaticSecret { secret_id, .. } => Some(secret_id.as_str()),
            _ => None,
        }
    }
    let target_auth = view
        .target
        .auth
        .as_ref()
        .and_then(static_secret);
    let transit_auth = view
        .transit
        .iter()
        .flat_map(|transit| transit.points.iter())
        .filter_map(|point| {
            point
                .target_auth
                .as_ref()
                .and_then(static_secret)
        });
    let caller_key = view
        .caller_key
        .as_ref()
        .map(|caller_key| caller_key.secret_id.as_str());
    let caller_api_keys = view
        .source_auth_methods()
        .iter()
        .filter_map(|method| match method {
            SourceAuthConfig::ApiKey(config) => Some(config.secret_id.as_str()),
            _ => None,
        });
    target_auth
        .into_iter()
        .chain(transit_auth)
        .chain(caller_key)
        .chain(caller_api_keys)
        .any(|used| used == secret_id)
}

fn is_http_url(endpoint: &str) -> bool {
    has_scheme(endpoint, "http")
}

fn is_https_url(endpoint: &str) -> bool {
    has_scheme(endpoint, "https")
}

fn has_scheme(
    endpoint: &str,
    scheme: &str,
) -> bool {
    url::Url::parse(endpoint.trim()).is_ok_and(|url| url.scheme() == scheme && url.host().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::credential_policy::{CredentialPolicyConfig, RuleMode, TEST_CREDENTIAL_POLICY};
    use serde_json::{Value, json};

    fn api_key(header_name: &str) -> Value {
        json!({"api_key": {"header_name": header_name, "secret_id": "bravo-key"}})
    }

    /// A surface whose Target at `endpoint` authenticates its responses by `response_auth`.
    fn surface(
        endpoint: &str,
        response_auth: Value,
    ) -> Value {
        json!({
            "name": "s",
            "access_point": {"listen_address": "0.0.0.0:8443", "route": "/s", "protocol": "a2a"},
            "target": {"endpoint": endpoint, "response_auth": response_auth}
        })
    }

    fn policy(target_https: RuleMode) -> &'static CredentialPolicyConfig {
        Box::leak(Box::new(CredentialPolicyConfig {
            target_https,
            ..Default::default()
        }))
    }

    fn parse(body: &Value) -> AgentSurface {
        serde_json::from_value(body.clone()).expect("surface parses")
    }

    /// [`validate_response_auth_rules`] and [`response_auth_warnings`] for `body`, saved over
    /// `stored`, with `target_https` in `mode`.
    fn save(
        mode: RuleMode,
        body: &Value,
        stored: Option<&Value>,
    ) -> (Result<(), String>, Vec<String>) {
        let surface = parse(body);
        let stored = stored.map(parse);
        TEST_CREDENTIAL_POLICY.sync_scope(policy(mode), || {
            (
                validate_response_auth_rules(&surface, stored.as_ref()).map_err(|error| match error {
                    SurfaceApiError::BadRequest(message) => message,
                    other => panic!("unexpected error {other:?}"),
                }),
                response_auth_warnings(&surface),
            )
        })
    }

    fn check(body: &Value) -> Result<(), String> {
        save(RuleMode::Enforce, body, None).0
    }

    const IN_CLEAR: &str = "target.response_auth receives an API key, so its Target must be an https URL";

    #[test]
    fn test_an_https_target_saves_without_a_warning_in_either_mode() {
        for mode in [RuleMode::Warn, RuleMode::Enforce] {
            assert_eq!(save(mode, &surface("https://bravo.example", api_key("X-Agent-Key")), None), (Ok(()), vec![]));
        }
        let mut plain = surface("http://bravo.example", Value::Null);
        plain["target"]
            .as_object_mut()
            .expect("target")
            .remove("response_auth");
        assert_eq!(save(RuleMode::Enforce, &plain, None), (Ok(()), vec![]), "no setting, no rule");
    }

    #[test]
    fn test_a_target_no_managed_agent_answers_is_refused() {
        for endpoint in ["proxy://weather", "a2a-proxy://proxy-1", "fabric://peer/surface", "bravo.example"] {
            assert_eq!(
                check(&surface(endpoint, api_key("X-Agent-Key"))),
                Err("target.response_auth needs an http or https Target: no managed agent answers a proxy://, \
                     a2a-proxy:// or fabric:// Target"
                    .to_string()),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn test_an_http_target_warns_in_warn_and_is_refused_in_enforce() {
        let http = surface("http://bravo.example", api_key("X-Agent-Key"));
        assert_eq!(
            save(RuleMode::Warn, &http, None),
            (Ok(()), vec![format!("{IN_CLEAR}; it will be refused once credential_policy.target_https is enforce")])
        );
        assert_eq!(save(RuleMode::Enforce, &http, None).0, Err(IN_CLEAR.to_string()));
    }

    #[test]
    fn test_a_stored_http_setting_is_kept_in_enforce_until_it_or_its_target_changes() {
        let stored = surface("http://bravo.example", api_key("X-Agent-Key"));
        assert_eq!(
            save(RuleMode::Enforce, &stored, Some(&stored)),
            (
                Ok(()),
                vec![format!(
                    "{IN_CLEAR}; a save that changes it is refused while credential_policy.target_https is enforce"
                )]
            )
        );

        let mut renamed = stored.clone();
        renamed["name"] = json!("renamed");
        assert_eq!(save(RuleMode::Enforce, &renamed, Some(&stored)).0, Ok(()), "an unrelated edit keeps it");

        let moved = surface("http://elsewhere.example", api_key("X-Agent-Key"));
        assert_eq!(save(RuleMode::Enforce, &moved, Some(&stored)).0, Err(IN_CLEAR.to_string()));

        let rekeyed = surface("http://bravo.example", api_key("X-Other-Key"));
        assert_eq!(save(RuleMode::Enforce, &rekeyed, Some(&stored)).0, Err(IN_CLEAR.to_string()));
    }

    #[test]
    fn test_a_header_that_is_not_a_field_name_or_is_reserved_is_refused_in_either_mode() {
        for (header_name, rule) in [
            ("X Agent", "must be an HTTP header name"),
            ("", "must be an HTTP header name"),
            ("X-Agent:", "must be an HTTP header name"),
            ("content-length", "must not be the reserved header Content-Length"),
            ("X_Transit_Token", "must not be the reserved header X-Transit-Token"),
            ("Mcp-Session-Id", "must not be the reserved header Mcp-Session-Id"),
        ] {
            for mode in [RuleMode::Warn, RuleMode::Enforce] {
                assert_eq!(
                    save(mode, &surface("https://bravo.example", api_key(header_name)), None).0,
                    Err(format!("target.response_auth.api_key.header_name {rule}")),
                    "{header_name:?} {mode:?}"
                );
            }
        }
    }

    #[test]
    fn test_a_header_the_gateway_reads_or_sets_on_the_response_is_refused_on_the_surface_and_a_variant() {
        for (header_name, name) in [("content_type", "Content-Type"), ("PAYMENT-RESPONSE", "Payment-Response")] {
            let rule = format!("must not be {name}, which the gateway reads or sets on the Target's response");
            assert_eq!(
                check(&surface("https://bravo.example", api_key(header_name))),
                Err(format!("target.response_auth.api_key.header_name {rule}")),
                "{header_name}"
            );
            let mut variant = surface("https://bravo.example", api_key("X-Agent-Key"));
            variant["variants"] = json!([{"id": "beta-id", "alias": "beta", "name": "Beta",
                "overrides": {"target": {"response_auth": api_key(header_name)}}}]);
            assert_eq!(
                check(&variant),
                Err(format!("variants['beta'].target.response_auth.api_key.header_name {rule}")),
                "{header_name} on a variant"
            );
        }
    }

    #[test]
    fn test_a_header_of_its_own_that_resembles_a_response_header_saves() {
        for header_name in ["X-Agent-Content-Type", "Payment-Agent-Key"] {
            assert_eq!(check(&surface("https://bravo.example", api_key(header_name))), Ok(()), "{header_name}");
        }
    }

    #[test]
    fn test_a_header_another_credential_sends_to_the_target_is_refused() {
        let mut target_auth = surface("https://bravo.example", api_key("x_api_key"));
        target_auth["target"]["auth"] = json!({"method": {"static_secret": {
            "secret_id": "target-key", "header_name": "X-Api-Key", "header_format": "{value}"
        }}});
        let mut binding = surface("https://bravo.example", api_key("X-Github-Token"));
        binding["outbound_credentials"] = json!([{
            "credential_provider_id": "bound",
            "inject_as": {"type": "custom_header", "name": "x-github-token", "format": "{value}"}
        }]);
        let mut mapped = surface("https://bravo.example", api_key("X-Tenant"));
        mapped["access_point"]["header_metadata_mapping"] = json!({"headers": [{"header": "x-tenant", "field": "t"}]});
        let mut forwarded = surface("https://bravo.example", api_key("Authorization"));
        forwarded["access_point"]["caller_authentication"] = json!({"methods": [{
            "type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": ["a"],
            "forward_header": true
        }]});
        let mut keyed = surface("https://bravo.example", api_key("X-Caller-Key"));
        keyed["caller_key"] = json!({"secret_id": "caller-keys"});

        for (case, body, refusal) in [
            ("Target authentication", target_auth, "x_api_key is already sent to the Target by Target authentication"),
            ("a credential binding", binding, "X-Github-Token is already sent to the Target by a credential binding"),
            ("header metadata mapping", mapped, "X-Tenant is already sent to the Target by header metadata mapping"),
            (
                "a forwarded caller token",
                forwarded,
                "Authorization is already sent to the Target by source authentication",
            ),
            ("caller_key", keyed, "X-Caller-Key is already sent to the Target by caller_key"),
        ] {
            assert_eq!(check(&body), Err(format!("target.response_auth.api_key.header_name {refusal}")), "{case}");
        }
    }

    const SHARED_SECRET: &str = "target.response_auth.api_key.secret_id must not be a secret the gateway sends to \
                                 the Target or a Transit Point or accepts from callers";

    fn target_auth_with(secret_id: &str) -> Value {
        json!({"method": {"static_secret": {
            "secret_id": secret_id, "header_name": "X-Api-Key", "header_format": "{value}"
        }}})
    }

    fn caller_api_key_with(secret_id: &str) -> Value {
        json!({"methods": [{"type": "api_key",
            "extraction": {"source": "http_header", "field": "X-Caller-Api-Key"}, "secret_id": secret_id}]})
    }

    #[test]
    fn test_a_key_secret_the_gateway_sends_or_accepts_is_refused() {
        let mut target_auth = surface("https://bravo.example", api_key("X-Agent-Key"));
        target_auth["target"]["auth"] = target_auth_with("bravo-key");
        let mut keyed = surface("https://bravo.example", api_key("X-Agent-Key"));
        keyed["caller_key"] = json!({"secret_id": "bravo-key"});
        let mut caller_api_key = surface("https://bravo.example", api_key("X-Agent-Key"));
        caller_api_key["access_point"]["caller_authentication"] = caller_api_key_with("bravo-key");

        for (case, body) in
            [("Target authentication", target_auth), ("caller_key", keyed), ("a caller API key", caller_api_key)]
        {
            assert_eq!(check(&body), Err(SHARED_SECRET.to_string()), "{case}");
        }
    }

    fn transit_point_with(secret_id: &str) -> Value {
        json!({"id": "tp-1", "alias": "partner", "target_endpoint": "https://partner.example/agent",
            "target_auth": target_auth_with(secret_id)})
    }

    #[test]
    fn test_a_key_secret_a_transit_point_sends_is_refused_on_the_surface_and_a_variant() {
        let mut base = surface("https://bravo.example", api_key("X-Agent-Key"));
        base["transit"] = json!({"points": [transit_point_with("bravo-key")]});
        assert_eq!(check(&base), Err(SHARED_SECRET.to_string()));

        let mut variant = surface("https://bravo.example", api_key("X-Agent-Key"));
        variant["variants"] = json!([{"id": "beta-id", "alias": "beta", "name": "Beta",
            "overrides": {"transit": {"points": [transit_point_with("bravo-key")]}}}]);
        assert_eq!(check(&variant), Err(format!("variants['beta'].{SHARED_SECRET}")));

        let mut distinct = surface("https://bravo.example", api_key("X-Agent-Key"));
        distinct["transit"] = json!({"points": [transit_point_with("partner-key")]});
        assert_eq!(check(&distinct), Ok(()), "a Transit Point secret of its own");
    }

    #[test]
    fn test_a_key_secret_of_its_own_saves_beside_the_others() {
        let mut distinct = surface("https://bravo.example", api_key("X-Agent-Key"));
        distinct["target"]["auth"] = target_auth_with("target-key");
        distinct["caller_key"] = json!({"secret_id": "caller-keys"});
        distinct["access_point"]["caller_authentication"] = caller_api_key_with("caller-api-key");
        assert_eq!(check(&distinct), Ok(()));
    }

    #[test]
    fn test_a_variant_whose_key_secret_the_gateway_sends_is_refused_by_its_alias() {
        let mut body = surface("https://bravo.example", api_key("X-Agent-Key"));
        body["variants"] = json!([{"id": "beta-id", "alias": "beta", "name": "Beta",
            "overrides": {"target": {"auth": target_auth_with("bravo-key")}}}]);
        assert_eq!(check(&body), Err(format!("variants['beta'].{SHARED_SECRET}")));
    }

    #[test]
    fn test_each_variant_is_held_to_the_rules_by_its_alias() {
        let variant = |overrides: Value| {
            let mut body = surface("https://bravo.example", api_key("X-Agent-Key"));
            body["variants"] = json!([{"id": "beta-id", "alias": "beta", "name": "Beta", "overrides": overrides}]);
            body
        };
        assert_eq!(
            check(&variant(json!({"target": {"endpoint": "a2a-proxy://proxy-1"}}))),
            Err("variants['beta'].target.response_auth needs an http or https Target: no managed agent answers a \
                 proxy://, a2a-proxy:// or fabric:// Target"
                .to_string()),
            "an inherited setting"
        );
        assert_eq!(
            check(&variant(json!({"target": {"response_auth": api_key("Host")}}))),
            Err("variants['beta'].target.response_auth.api_key.header_name must not be the reserved header Host"
                .to_string()),
            "a variant's own setting"
        );
        let http = variant(json!({"target": {"endpoint": "http://beta.example"}}));
        assert_eq!(check(&http), Err(format!("variants['beta'].{IN_CLEAR}")));
        assert_eq!(
            save(RuleMode::Warn, &http, None),
            (
                Ok(()),
                vec![format!(
                    "variants['beta'].{IN_CLEAR}; it will be refused once credential_policy.target_https is enforce"
                )]
            )
        );
        assert_eq!(
            check(&variant(json!({"complete": true, "target": {"endpoint": "a2a-proxy://proxy-1"}}))),
            Ok(()),
            "a complete variant that sets none has none"
        );
    }

    /// `sent` as a PUT saves it over `stored`, with the `target.response_auth` it then holds and
    /// that of its variant `beta-id`'s target overrides.
    fn put(
        stored: &Value,
        sent: &Value,
    ) -> (Option<ResponseAuthConfig>, Option<ResponseAuthConfig>) {
        let mut surface = parse(sent);
        retain_response_auth(&mut surface, &parse(stored), sent);
        let variant = surface
            .variants
            .first()
            .and_then(|variant| {
                variant
                    .overrides
                    .target
                    .as_ref()
            })
            .and_then(|target| target.response_auth.clone());
        (surface.target.response_auth, variant)
    }

    fn setting(value: Value) -> Option<ResponseAuthConfig> {
        Some(serde_json::from_value(value).expect("setting parses"))
    }

    fn with_variant(
        mut body: Value,
        target: Value,
    ) -> Value {
        body["variants"] = json!([{"id": "beta-id", "alias": "beta", "name": "Beta", "overrides": {"target": target}}]);
        body
    }

    fn leave_out_response_auth(mut body: Value) -> Value {
        body["target"]
            .as_object_mut()
            .expect("target")
            .remove("response_auth");
        body
    }

    #[test]
    fn test_a_put_that_leaves_out_response_auth_keeps_the_stored_one() {
        let stored = with_variant(
            surface("https://bravo.example", api_key("X-Agent-Key")),
            json!({"endpoint": "https://beta.example", "response_auth": api_key("X-Beta-Key")}),
        );
        let sent = with_variant(
            leave_out_response_auth(surface("https://bravo.example", Value::Null)),
            json!({"endpoint": "https://beta.example"}),
        );
        assert_eq!(put(&stored, &sent), (setting(api_key("X-Agent-Key")), setting(api_key("X-Beta-Key"))));
    }

    #[test]
    fn test_a_put_with_a_null_response_auth_removes_it() {
        let stored = with_variant(
            surface("https://bravo.example", api_key("X-Agent-Key")),
            json!({"endpoint": "https://beta.example", "response_auth": api_key("X-Beta-Key")}),
        );
        let sent = with_variant(
            surface("https://bravo.example", Value::Null),
            json!({"endpoint": "https://beta.example", "response_auth": null}),
        );
        assert_eq!(put(&stored, &sent), (None, None));
    }

    #[test]
    fn test_a_put_with_a_new_response_auth_replaces_the_stored_one() {
        let stored = with_variant(
            surface("https://bravo.example", api_key("X-Agent-Key")),
            json!({"endpoint": "https://beta.example", "response_auth": api_key("X-Beta-Key")}),
        );
        let sent = with_variant(
            surface("https://bravo.example", mtls(pinned())),
            json!({"endpoint": "https://beta.example", "response_auth": api_key("X-Other-Key")}),
        );
        assert_eq!(put(&stored, &sent), (setting(mtls(pinned())), setting(api_key("X-Other-Key"))));
    }

    #[test]
    fn test_a_new_variant_or_one_sent_without_target_overrides_keeps_nothing() {
        let stored = with_variant(
            surface("https://bravo.example", api_key("X-Agent-Key")),
            json!({"endpoint": "https://beta.example", "response_auth": api_key("X-Beta-Key")}),
        );
        let mut new_variant = with_variant(
            surface("https://bravo.example", api_key("X-Agent-Key")),
            json!({"endpoint": "https://beta.example"}),
        );
        new_variant["variants"][0]["id"] = json!("gamma-id");
        assert_eq!(put(&stored, &new_variant).1, None, "a variant the stored surface does not have");

        let mut no_target = surface("https://bravo.example", api_key("X-Agent-Key"));
        no_target["variants"] = json!([{"id": "beta-id", "alias": "beta", "name": "Beta", "overrides": {}}]);
        assert_eq!(put(&stored, &no_target).1, None, "overrides that send no target");
    }

    #[test]
    fn test_a_variant_put_keeps_removes_or_replaces_the_stored_response_auth() {
        let stored: SurfaceOverrides = serde_json::from_value(
            json!({"target": {"endpoint": "https://beta.example", "response_auth": api_key("X-Beta-Key")}}),
        )
        .expect("overrides parse");
        for (case, sent_target, kept) in [
            ("left out", json!({"endpoint": "https://beta.example"}), setting(api_key("X-Beta-Key"))),
            ("null", json!({"endpoint": "https://beta.example", "response_auth": null}), None),
            (
                "a new one",
                json!({"endpoint": "https://beta.example", "response_auth": api_key("X-Other-Key")}),
                setting(api_key("X-Other-Key")),
            ),
        ] {
            let sent = json!({"overrides": {"target": sent_target}});
            let mut overrides: SurfaceOverrides =
                serde_json::from_value(sent["overrides"].clone()).expect("overrides parse");
            retain_override_response_auth(&mut overrides, &stored, sent.pointer("/overrides/target"));
            assert_eq!(
                overrides
                    .target
                    .and_then(|target| target.response_auth),
                kept,
                "{case}"
            );
        }
    }

    fn mtls(server_trust: Value) -> Value {
        json!({"mtls": {"server_trust": server_trust, "client_certificate_id": "gateway-cert"}})
    }

    fn pinned() -> Value {
        json!({"type": "pinned", "certificate_ids": ["bravo-cert"]})
    }

    #[test]
    fn test_mtls_on_an_https_target_saves_without_a_warning() {
        for mode in [RuleMode::Warn, RuleMode::Enforce] {
            assert_eq!(save(mode, &surface("https://bravo.example", mtls(pinned())), None), (Ok(()), vec![]));
        }
    }

    #[test]
    fn test_mtls_on_an_http_target_is_refused_in_either_mode() {
        for mode in [RuleMode::Warn, RuleMode::Enforce] {
            assert_eq!(
                save(mode, &surface("http://bravo.example", mtls(pinned())), None),
                (
                    Err("target.response_auth.mtls needs an https Target: only TLS proves the managed agent's \
                         certificate"
                        .to_string()),
                    vec![]
                ),
                "{mode:?}"
            );
        }
        let mut variant = surface("https://bravo.example", mtls(pinned()));
        variant["variants"] = json!([{"id": "beta-id", "alias": "beta", "name": "Beta",
            "overrides": {"target": {"endpoint": "http://beta.example"}}}]);
        assert_eq!(
            check(&variant),
            Err("variants['beta'].target.response_auth.mtls needs an https Target: only TLS proves the managed \
                 agent's certificate"
                .to_string())
        );
    }

    fn bound_by_external_consent(mut body: Value) -> Value {
        body["outbound_credentials"] =
            json!([{"credential_provider_id": "vendor", "consent_mode": "external", "subject": "owner"}]);
        body
    }

    const MTLS_WITH_EXTERNAL_CONSENT: &str =
        "target.response_auth: mTLS can't be used with a Target bound by external consent; use the api_key method";

    #[test]
    fn test_mtls_on_a_target_bound_by_external_consent_is_refused_on_the_surface_and_each_variant() {
        let bound = bound_by_external_consent(surface("https://bravo.example", mtls(pinned())));
        assert_eq!(check(&bound), Err(MTLS_WITH_EXTERNAL_CONSENT.to_string()));
        assert_eq!(
            save(RuleMode::Warn, &bound, Some(&bound)).0,
            Err(MTLS_WITH_EXTERNAL_CONSENT.to_string()),
            "a stored surface with the same setting is refused too"
        );

        let mut variant = bound_by_external_consent(surface("https://bravo.example", api_key("X-Agent-Key")));
        variant["variants"] = json!([{"id": "beta-id", "alias": "beta", "name": "Beta",
            "overrides": {"target": {"response_auth": mtls(pinned())}}}]);
        assert_eq!(check(&variant), Err(format!("variants['beta'].{MTLS_WITH_EXTERNAL_CONSENT}")));
    }

    #[test]
    fn test_an_api_key_with_external_consent_and_mtls_without_it_save() {
        assert_eq!(check(&bound_by_external_consent(surface("https://bravo.example", api_key("X-Agent-Key")))), Ok(()));
        let mut on_behalf = surface("https://bravo.example", mtls(pinned()));
        on_behalf["outbound_credentials"] = json!([{"credential_provider_id": "vendor"}]);
        assert_eq!(check(&on_behalf), Ok(()), "a binding without external consent");
        assert_eq!(check(&surface("https://bravo.example", mtls(pinned()))), Ok(()));
    }

    #[test]
    fn test_mtls_without_a_trusted_certificate_or_with_a_revocation_check_is_refused() {
        assert_eq!(
            check(&surface("https://bravo.example", mtls(json!({"type": "pinned", "certificate_ids": []})))),
            Err("target.response_auth.mtls.server_trust must name at least one certificate".to_string())
        );
        for flag in ["check_crl", "require_ocsp"] {
            let mut trust = json!({"type": "ca", "ca_certificate_ids": ["bravo-ca"]});
            trust[flag] = json!(true);
            assert_eq!(
                check(&surface("https://bravo.example", mtls(trust))),
                Err("target.response_auth.mtls.server_trust cannot check CRLs or OCSP: set check_crl and \
                     require_ocsp to false"
                    .to_string()),
                "{flag}"
            );
        }
    }

    /// A certificate store holding each `(id, kind, with_key)`, inactive when named in `inactive`.
    async fn certificates_with_inactive(
        stored: &[(&str, CertificateKind, bool)],
        inactive: &[&str],
    ) -> (tempfile::TempDir, Box<dyn CertificateStore>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = crate::certificates::FilesystemCertificateStore::new(dir.path().to_path_buf())
            .await
            .expect("certificate store");
        for (id, kind, with_key) in stored {
            store
                .create_with_ids(
                    crate::certificates::CreateCertificateRequest {
                        tenant_id: None,
                        name: id.to_string(),
                        description: None,
                        tags: None,
                        kind: *kind,
                        certificate_pem: "-----BEGIN CERTIFICATE-----".to_string(),
                        private_key_pem: with_key.then(|| "-----BEGIN PRIVATE KEY-----".to_string()),
                        expires_at: None,
                        active: Some(!inactive.contains(id)),
                        identity_did: None,
                    },
                    id.to_string(),
                    format!("{id}-uuid"),
                )
                .await
                .expect("certificate stored");
        }
        (dir, Box::new(store))
    }

    async fn certificate_refusal(
        response_auth: Value,
        stored: &[(&str, CertificateKind, bool)],
    ) -> Result<(), String> {
        certificate_refusal_with_inactive(response_auth, stored, &[]).await
    }

    async fn certificate_refusal_with_inactive(
        response_auth: Value,
        stored: &[(&str, CertificateKind, bool)],
        inactive: &[&str],
    ) -> Result<(), String> {
        let (_dir, store) = certificates_with_inactive(stored, inactive).await;
        validate_response_auth_certificates(
            Some(store.as_ref()),
            &parse(&surface("https://bravo.example", response_auth)),
        )
        .await
        .map_err(|error| match error {
            SurfaceApiError::BadRequest(message) => message,
            other => panic!("unexpected error {other:?}"),
        })
    }

    #[tokio::test]
    async fn test_mtls_certificates_of_the_kind_the_trust_takes_save() {
        let pinned_with_client =
            [("bravo-cert", CertificateKind::ClientLeaf, false), ("gateway-cert", CertificateKind::ClientLeaf, true)];
        assert_eq!(certificate_refusal(mtls(pinned()), &pinned_with_client).await, Ok(()));
        let ca = json!({"mtls": {"server_trust": {"type": "ca", "ca_certificate_ids": ["bravo-ca"]}}});
        assert_eq!(certificate_refusal(ca, &[("bravo-ca", CertificateKind::Ca, false)]).await, Ok(()));
    }

    #[tokio::test]
    async fn test_mtls_certificates_of_the_wrong_kind_missing_or_without_a_key_are_refused() {
        let client = ("gateway-cert", CertificateKind::ClientLeaf, true);
        let ca = json!({"mtls": {"server_trust": {"type": "ca", "ca_certificate_ids": ["bravo-ca"]}}});
        for (case, response_auth, stored, refusal) in [
            (
                "a CA pinned as the server certificate",
                mtls(pinned()),
                vec![("bravo-cert", CertificateKind::Ca, false), client],
                "target.response_auth.mtls.server_trust certificate bravo-cert must be a client_leaf certificate",
            ),
            (
                "a server certificate pinned",
                mtls(pinned()),
                vec![("bravo-cert", CertificateKind::ServerLeaf, false), client],
                "target.response_auth.mtls.server_trust certificate bravo-cert must be a client_leaf certificate",
            ),
            (
                "a leaf trusted as a CA",
                ca,
                vec![("bravo-ca", CertificateKind::ClientLeaf, false)],
                "target.response_auth.mtls.server_trust certificate bravo-ca must be a ca certificate",
            ),
            (
                "a CA as the client certificate",
                mtls(pinned()),
                vec![("bravo-cert", CertificateKind::ClientLeaf, false), ("gateway-cert", CertificateKind::Ca, true)],
                "target.response_auth.mtls.client_certificate_id gateway-cert must be a client_leaf certificate",
            ),
            (
                "a client certificate without its key",
                mtls(pinned()),
                vec![
                    ("bravo-cert", CertificateKind::ClientLeaf, false),
                    ("gateway-cert", CertificateKind::ClientLeaf, false),
                ],
                "target.response_auth.mtls.client_certificate_id gateway-cert must be stored with its private key",
            ),
            ("a missing certificate", mtls(pinned()), vec![client], "Certificate reference is not accessible"),
        ] {
            assert_eq!(certificate_refusal(response_auth, &stored).await, Err(refusal.to_string()), "{case}");
        }
    }

    #[tokio::test]
    async fn test_an_inactive_server_trust_or_client_certificate_is_refused() {
        let stored =
            [("bravo-cert", CertificateKind::ClientLeaf, false), ("gateway-cert", CertificateKind::ClientLeaf, true)];
        assert_eq!(
            certificate_refusal_with_inactive(mtls(pinned()), &stored, &["bravo-cert"]).await,
            Err("target.response_auth.mtls.server_trust certificate bravo-cert must be active".to_string())
        );
        assert_eq!(
            certificate_refusal_with_inactive(mtls(pinned()), &stored, &["gateway-cert"]).await,
            Err("target.response_auth.mtls.client_certificate_id gateway-cert must be active".to_string())
        );
        assert_eq!(certificate_refusal_with_inactive(mtls(pinned()), &stored, &[]).await, Ok(()), "both active");
    }

    async fn secret_refusal(
        body: &Value,
        value: &str,
    ) -> Result<(), String> {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = crate::secrets::FilesystemSecretsStore::new_async(
            dir.path()
                .to_str()
                .expect("utf-8 path"),
        )
        .await
        .expect("secrets store");
        crate::secrets::SecretsStore::create(
            &store,
            crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "bravo-key".to_string(),
                secret_id: "bravo-key".to_string(),
                description: None,
                value: value.to_string(),
                secret_type: "General".to_string(),
                tags: vec![],
            },
        )
        .await
        .expect("secret stored");
        validate_response_auth_secrets(Some(&store), &parse(body))
            .await
            .map_err(|error| match error {
                SurfaceApiError::BadRequest(message) => message,
                other => panic!("unexpected error {other:?}"),
            })
    }

    #[tokio::test]
    async fn test_a_key_secret_without_a_non_blank_key_is_refused_on_the_surface_and_a_variant() {
        const BLANK: &str = "target.response_auth.api_key.secret_id bravo-key must hold at least one non-blank key";
        let base = surface("https://bravo.example", api_key("X-Agent-Key"));
        for blank in ["", "   ", " , ,"] {
            assert_eq!(secret_refusal(&base, blank).await, Err(BLANK.to_string()), "{blank:?}");
        }
        let mut variant = surface("https://bravo.example", mtls(pinned()));
        variant["variants"] = json!([{"id": "beta-id", "alias": "beta", "name": "Beta",
            "overrides": {"target": {"response_auth": api_key("X-Agent-Key")}}}]);
        assert_eq!(secret_refusal(&variant, " , ").await, Err(format!("variants['beta'].{BLANK}")));

        for held in ["bravo-secret", " , bravo-secret", "old-key,new-key"] {
            assert_eq!(secret_refusal(&base, held).await, Ok(()), "{held:?}");
        }
    }
}
