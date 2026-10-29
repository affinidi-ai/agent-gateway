//! External consent providers.
//!
//! A credential provider with an `issuer` describes one OAuth client of one
//! authorization server, for grants made through external consent: another
//! system runs the browser leg, and the gateway keeps the grant. The provider
//! is checked when it is created, without trusting what was pushed:
//!
//! - [`validate`] applies the static rules: an authorization code provider with
//!   `https` endpoints the Strict egress posture accepts, a plain `client_id`, a
//!   `token_endpoint_auth_method` with a secret exactly when the method needs one,
//!   a callback URL, a public `https` `resource`, and none of the fields the
//!   gateway's own consent flow uses.
//! - [`check_metadata`] compares it with the issuer's RFC 8414 or OpenID Connect
//!   metadata, read under the client profile and the Strict posture: the
//!   authorization, token and revocation endpoints must be the ones the metadata
//!   names, the server must support the client's authentication method, and the
//!   metadata must list S256 PKCE, unless the provider names the
//!   `allow_unadvertised_pkce` exception for a server that does not list it.
//! - [`refuse_changes`] keeps the issuer, the endpoints, the client fields and
//!   `resource` fixed for the provider's life: a different value is a new provider.
//! - [`check_grant_destination`] binds the provider's grants to where they are
//!   sent: a Transit Point carries them only to the origin of `resource`.
//!
//! So a token that can edit providers or surfaces cannot point a provider whose
//! grants are stored at an endpoint of its choosing, which would collect them on
//! the next refresh or revocation, nor send its grants to a host of its choosing.

use std::sync::Arc;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use futures::future::BoxFuture;

use super::{CredentialProvider, CredentialProviderType, TokenEndpointAuthMethod, UpdateCredentialProviderRequest};
use crate::authz_metadata::{ClientAuthzMetadata, DiscoveryError, DiscoveryFailure, DiscoveryOptions, EgressPosture};

const MAX_URL_CHARS: usize = 2048;
const MAX_CLIENT_ID_CHARS: usize = 2048;

/// Reads an issuer's authorization server metadata under the client profile.
pub type IssuerMetadata =
    Arc<dyn Fn(String) -> BoxFuture<'static, Result<ClientAuthzMetadata, DiscoveryError>> + Send + Sync>;

/// The issuer's metadata, read through the pinned, bounded fetch of
/// [`crate::authz_metadata`] under the Strict egress posture.
pub fn strict_issuer_metadata() -> IssuerMetadata {
    Arc::new(|issuer| {
        Box::pin(async move {
            crate::authz_metadata::discover_client(&issuer, EgressPosture::Strict, DiscoveryOptions::default()).await
        })
    })
}

/// Why an external consent provider, or a change to one, was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalProviderError {
    /// A static rule failed; the text says which.
    Invalid(&'static str),
    /// The issuer's metadata could not be read or is not acceptable.
    MetadataUnavailable(DiscoveryFailure),
    /// The named field is not what the issuer's metadata says.
    MetadataMismatch(&'static str),
    /// The named field cannot change on an external consent provider.
    Immutable(&'static str),
}

impl ExternalProviderError {
    /// A discovery failure as the API reports it. A failure before the server
    /// answered is `unreachable` whatever its cause, so the answer never says
    /// whether a name resolves to an address the egress posture blocks.
    fn metadata_reason(failure: DiscoveryFailure) -> &'static str {
        match failure {
            DiscoveryFailure::InvalidUrl => "invalid_url",
            DiscoveryFailure::Blocked | DiscoveryFailure::Unreachable => "unreachable",
            DiscoveryFailure::HttpStatus
            | DiscoveryFailure::TooLarge
            | DiscoveryFailure::InvalidDocument
            | DiscoveryFailure::IssuerMismatch => failure.code(),
        }
    }
}

impl IntoResponse for ExternalProviderError {
    fn into_response(self) -> Response {
        let body = match self {
            Self::Invalid(message) => serde_json::json!({ "error": message, "code": "invalid_provider" }),
            Self::MetadataUnavailable(failure) => serde_json::json!({
                "error": "The issuer's authorization server metadata could not be read or is not acceptable",
                "code": "provider_metadata_unavailable",
                "reason": Self::metadata_reason(failure),
            }),
            Self::MetadataMismatch(field) => serde_json::json!({
                "error": format!("{field} does not match the issuer's authorization server metadata"),
                "code": "provider_metadata_mismatch",
                "field": field,
            }),
            Self::Immutable(field) => serde_json::json!({
                "error": format!(
                    "{field} cannot change on a provider with an issuer; create a new provider instead"
                ),
                "code": "provider_field_immutable",
                "field": field,
            }),
        };
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    }
}

fn has_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
}

/// An `https` URL without credentials or fragment that the Strict egress
/// posture accepts before DNS: no literal loopback, private, link-local or
/// cloud-metadata host.
fn is_strict_https_url(value: &str) -> bool {
    value.chars().count() <= MAX_URL_CHARS
        && !has_whitespace_or_control(value)
        && url::Url::parse(value).is_ok_and(|url| url.scheme() == "https" && url.fragment().is_none())
        && crate::url_validation::validate_webhook_url(value).is_ok()
}

/// An absolute `https` URL without credentials or fragment.
fn is_https_url(value: &str) -> bool {
    value.chars().count() <= MAX_URL_CHARS
        && !has_whitespace_or_control(value)
        && url::Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
}

/// The static rules of a provider being created. A provider without an
/// `issuer` must not set the fields only an external consent provider has.
pub fn validate(provider: &CredentialProvider) -> Result<(), ExternalProviderError> {
    use ExternalProviderError::Invalid;

    let Some(issuer) = provider.issuer.as_deref() else {
        if provider
            .revocation_endpoint
            .is_some()
            || provider
                .token_endpoint_auth_method
                .is_some()
            || provider.client_id.is_some()
            || provider.allow_unadvertised_pkce
        {
            return Err(Invalid(
                "revocation_endpoint, token_endpoint_auth_method, client_id and allow_unadvertised_pkce need an issuer",
            ));
        }
        return Ok(());
    };
    if provider.provider_type != CredentialProviderType::OAuth2AuthorizationCode {
        return Err(Invalid("a provider with an issuer must be an oauth2_authorization_code provider"));
    }
    if crate::authz_metadata::validate_issuer(issuer, EgressPosture::Strict).is_err() {
        return Err(Invalid("issuer must be an https URL without credentials, query, fragment or whitespace"));
    }
    for (field, value, required) in [
        (
            "authorization_endpoint",
            provider
                .authorization_endpoint
                .as_deref(),
            true,
        ),
        (
            "token_endpoint",
            provider
                .token_endpoint
                .as_deref(),
            true,
        ),
        (
            "revocation_endpoint",
            provider
                .revocation_endpoint
                .as_deref(),
            false,
        ),
    ] {
        match value {
            None if required => {
                return Err(Invalid(match field {
                    "authorization_endpoint" => "authorization_endpoint is required with an issuer",
                    _ => "token_endpoint is required with an issuer",
                }));
            }
            Some(value) if !is_strict_https_url(value) => {
                return Err(Invalid(match field {
                    "authorization_endpoint" => "authorization_endpoint must be a public https URL",
                    "token_endpoint" => "token_endpoint must be a public https URL",
                    _ => "revocation_endpoint must be a public https URL",
                }));
            }
            _ => {}
        }
    }
    match provider.client_id.as_deref() {
        Some(client_id)
            if !client_id.is_empty()
                && client_id.chars().count() <= MAX_CLIENT_ID_CHARS
                && !has_whitespace_or_control(client_id) => {}
        _ => return Err(Invalid("client_id is required with an issuer, without whitespace")),
    }
    if provider
        .client_id_secret_ref
        .is_some()
    {
        return Err(Invalid("a provider with an issuer takes client_id, not client_id_secret_ref"));
    }
    let Some(method) = provider.token_endpoint_auth_method else {
        return Err(Invalid("token_endpoint_auth_method is required with an issuer"));
    };
    if method.uses_secret()
        != provider
            .client_secret_secret_ref
            .is_some()
    {
        return Err(Invalid(
            "client_secret_secret_ref is required for client_secret_basic and client_secret_post, and refused for none",
        ));
    }
    if !provider
        .callback_url
        .as_deref()
        .is_some_and(is_https_url)
    {
        return Err(Invalid("callback_url is required with an issuer, as an https URL"));
    }
    if !provider
        .resource
        .as_deref()
        .is_some_and(is_strict_https_url)
    {
        return Err(Invalid(
            "resource is required with an issuer, as a public https URL: its origin is the only one a Transit Point \
             sends the provider's grants to",
        ));
    }
    if !provider
        .additional_params
        .is_empty()
        || provider
            .consent_identity_strategy_id
            .is_some()
        || provider
            .api_key_secret_ref
            .is_some()
    {
        return Err(Invalid(
            "a provider with an issuer takes no additional_params, consent_identity_strategy_id or api_key_secret_ref",
        ));
    }
    Ok(())
}

/// Compare an external consent provider with its issuer's metadata.
///
/// The authorization and token endpoints must equal the metadata's byte for
/// byte, and the revocation endpoint too, including its absence. The client's
/// authentication method must be one the metadata lists, or `client_secret_basic`
/// when it lists none (RFC 8414). The metadata's PKCE methods must include S256.
/// A metadata document that lists no PKCE methods is refused, as MCP clients
/// refuse it, unless the provider names the `allow_unadvertised_pkce` exception.
pub fn check_metadata(
    provider: &CredentialProvider,
    metadata: &ClientAuthzMetadata,
) -> Result<(), ExternalProviderError> {
    use ExternalProviderError::MetadataMismatch;

    if provider.issuer.as_deref() != Some(metadata.issuer.as_str()) {
        return Err(MetadataMismatch("issuer"));
    }
    if provider
        .authorization_endpoint
        .as_deref()
        != Some(
            metadata
                .authorization_endpoint
                .as_str(),
        )
    {
        return Err(MetadataMismatch("authorization_endpoint"));
    }
    if provider
        .token_endpoint
        .as_deref()
        != Some(
            metadata
                .token_endpoint
                .as_str(),
        )
    {
        return Err(MetadataMismatch("token_endpoint"));
    }
    if provider.revocation_endpoint != metadata.revocation_endpoint {
        return Err(MetadataMismatch("revocation_endpoint"));
    }
    let method = provider
        .token_endpoint_auth_method
        .ok_or(MetadataMismatch("token_endpoint_auth_method"))?;
    let method_supported = match metadata
        .token_endpoint_auth_methods_supported
        .as_deref()
    {
        Some(supported) => supported
            .iter()
            .any(|name| name == method.as_str()),
        None => method == TokenEndpointAuthMethod::ClientSecretBasic,
    };
    if !method_supported {
        return Err(MetadataMismatch("token_endpoint_auth_method"));
    }
    let pkce_supported = match metadata
        .code_challenge_methods_supported
        .as_deref()
    {
        Some(methods) => methods
            .iter()
            .any(|method| method == "S256"),
        None => provider.allow_unadvertised_pkce,
    };
    if !pkce_supported {
        return Err(MetadataMismatch("code_challenge_methods_supported"));
    }
    Ok(())
}

fn changes<T: PartialEq>(
    requested: Option<&T>,
    stored: Option<&T>,
) -> bool {
    requested.is_some_and(|requested| Some(requested) != stored)
}

/// Refuse an update that would change what an external consent provider's
/// grants were made with, or make a provider without an issuer into one. A
/// field sent with its stored value is no change. The name, description,
/// default scopes and `token_refresh_enabled` stay editable.
pub fn refuse_changes(
    existing: &CredentialProvider,
    request: &UpdateCredentialProviderRequest,
) -> Result<(), ExternalProviderError> {
    if !existing.is_external_consent() {
        if request.issuer.is_some()
            || request
                .revocation_endpoint
                .is_some()
            || request
                .token_endpoint_auth_method
                .is_some()
            || request.client_id.is_some()
            || request.allow_unadvertised_pkce == Some(true)
        {
            return Err(ExternalProviderError::Invalid(
                "an existing provider cannot take an issuer, revocation_endpoint, token_endpoint_auth_method, \
                 client_id or allow_unadvertised_pkce; create a new provider instead",
            ));
        }
        return Ok(());
    }
    let fields: [(&'static str, bool); 15] = [
        ("issuer", changes(request.issuer.as_ref(), existing.issuer.as_ref())),
        ("provider_type", changes(request.provider_type.as_ref(), Some(&existing.provider_type))),
        (
            "authorization_endpoint",
            changes(
                request
                    .authorization_endpoint
                    .as_ref(),
                existing
                    .authorization_endpoint
                    .as_ref(),
            ),
        ),
        (
            "token_endpoint",
            changes(
                request
                    .token_endpoint
                    .as_ref(),
                existing
                    .token_endpoint
                    .as_ref(),
            ),
        ),
        (
            "revocation_endpoint",
            changes(
                request
                    .revocation_endpoint
                    .as_ref(),
                existing
                    .revocation_endpoint
                    .as_ref(),
            ),
        ),
        (
            "token_endpoint_auth_method",
            changes(
                request
                    .token_endpoint_auth_method
                    .as_ref(),
                existing
                    .token_endpoint_auth_method
                    .as_ref(),
            ),
        ),
        ("client_id", changes(request.client_id.as_ref(), existing.client_id.as_ref())),
        (
            "client_id_secret_ref",
            changes(
                request
                    .client_id_secret_ref
                    .as_ref(),
                existing
                    .client_id_secret_ref
                    .as_ref(),
            ),
        ),
        (
            "client_secret_secret_ref",
            changes(
                request
                    .client_secret_secret_ref
                    .as_ref(),
                existing
                    .client_secret_secret_ref
                    .as_ref(),
            ),
        ),
        ("callback_url", changes(request.callback_url.as_ref(), existing.callback_url.as_ref())),
        ("resource", changes(request.resource.as_ref(), existing.resource.as_ref())),
        (
            "additional_params",
            changes(
                request
                    .additional_params
                    .as_ref(),
                Some(&existing.additional_params),
            ),
        ),
        (
            "consent_identity_strategy_id",
            changes(
                request
                    .consent_identity_strategy_id
                    .as_ref(),
                existing
                    .consent_identity_strategy_id
                    .as_ref(),
            ),
        ),
        (
            "api_key_secret_ref",
            changes(
                request
                    .api_key_secret_ref
                    .as_ref(),
                existing
                    .api_key_secret_ref
                    .as_ref(),
            ),
        ),
        (
            "allow_unadvertised_pkce",
            changes(
                request
                    .allow_unadvertised_pkce
                    .as_ref(),
                Some(&existing.allow_unadvertised_pkce),
            ),
        ),
    ];
    match fields
        .into_iter()
        .find(|(_, changed)| *changed)
    {
        Some((field, _)) => Err(ExternalProviderError::Immutable(field)),
        None => Ok(()),
    }
}

/// Whether a Transit Point whose target is `target_endpoint` may carry the
/// grants of the external consent provider `provider`, and if so the origin
/// they may be sent to: the origin of the provider's `resource`.
///
/// The target must be a public `https` URL with that origin, never a `fabric://`
/// route. `exact_allowlist` is the test allow-list of fixtures
/// ([`crate::egress::bdd_egress_allowlist`] on the production path, so `None`):
/// it can admit an `http` or loopback fixture, never another origin or Fabric.
/// The check runs when the surface is saved and again on every call, so a grant
/// is bound to where it is sent, not to a Transit Point id.
pub fn check_grant_destination(
    provider: &CredentialProvider,
    target_endpoint: &str,
    exact_allowlist: Option<&str>,
) -> Result<url::Origin, &'static str> {
    if target_endpoint.starts_with("fabric://") {
        return Err("consent_mode external never forwards over Fabric");
    }
    let resource = provider
        .resource
        .as_deref()
        .and_then(|resource| url::Url::parse(resource).ok())
        .ok_or("the credential provider names no resource")?;
    let target = url::Url::parse(target_endpoint)
        .map_err(|_| "consent_mode external needs a target_endpoint that is a public https URL")?;
    if !is_strict_https_url(target_endpoint) && !crate::egress::exactly_allowlisted(target_endpoint, exact_allowlist) {
        return Err("consent_mode external needs a target_endpoint that is a public https URL");
    }
    if target.origin() != resource.origin() {
        return Err(
            "consent_mode external needs a target_endpoint with the origin of the credential provider's resource",
        );
    }
    Ok(resource.origin())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    const ISSUER: &str = "https://203.0.113.10";

    #[test]
    fn a_grant_goes_only_to_a_public_https_target_with_the_origin_of_the_providers_resource() {
        let provider = external_provider();
        let resource = url::Url::parse("https://203.0.113.10/mcp")
            .unwrap()
            .origin();
        for target in ["https://203.0.113.10/mcp", "https://203.0.113.10/other/path?x=1", "https://203.0.113.10:443"] {
            assert_eq!(check_grant_destination(&provider, target, None), Ok(resource.clone()), "{target}");
        }
        for (case, target) in [
            ("another host", "https://203.0.113.66/mcp"),
            ("another port", "https://203.0.113.10:8443/mcp"),
            ("http", "http://203.0.113.10/mcp"),
            ("Fabric", "fabric://gateway-b/channel"),
            ("not a URL", "vendor"),
        ] {
            assert!(check_grant_destination(&provider, target, None).is_err(), "{case} must be refused");
        }

        let mut private = external_provider();
        private.resource = Some("https://10.0.0.5/mcp".into());
        assert!(
            check_grant_destination(&private, "https://10.0.0.5/mcp", None).is_err(),
            "a private address is refused even when a stored provider names it"
        );
        let mut loopback = external_provider();
        loopback.resource = Some("https://127.0.0.1/mcp".into());
        assert!(check_grant_destination(&loopback, "https://127.0.0.1/mcp", None).is_err());
        let mut without_resource = external_provider();
        without_resource.resource = None;
        assert!(check_grant_destination(&without_resource, "https://203.0.113.10/mcp", None).is_err());
    }

    #[test]
    fn only_the_test_allowlist_admits_an_http_fixture_and_never_another_origin_or_fabric() {
        let mut fixture = external_provider();
        fixture.resource = Some("http://127.0.0.1:9/mcp".into());
        let allowlist = Some("http://127.0.0.1:9");
        assert_eq!(
            check_grant_destination(&fixture, "http://127.0.0.1:9/mcp", allowlist),
            Ok(url::Url::parse("http://127.0.0.1:9")
                .unwrap()
                .origin())
        );
        assert!(check_grant_destination(&fixture, "http://127.0.0.1:9/mcp", None).is_err());
        assert!(check_grant_destination(&fixture, "http://127.0.0.1:10/mcp", Some("http://127.0.0.1:10")).is_err());
        assert!(check_grant_destination(&fixture, "fabric://127.0.0.1:9/mcp", allowlist).is_err());
    }

    pub(crate) fn external_provider() -> CredentialProvider {
        serde_json::from_value(json!({
            "id": "provider", "tenant_id": "tenant-a", "name": "Linear", "provider_id": "boris-0123456789ab",
            "provider_type": "oauth2_authorization_code",
            "issuer": ISSUER,
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "revocation_endpoint": format!("{ISSUER}/token"),
            "token_endpoint_auth_method": "none",
            "client_id": "dcr-client-1",
            "callback_url": "https://203.0.113.20/api/v1/connect/callback/as-1",
            "resource": "https://203.0.113.10/mcp",
            "default_scopes": ["read"],
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap()
    }

    pub(crate) fn metadata() -> ClientAuthzMetadata {
        ClientAuthzMetadata {
            issuer: ISSUER.to_string(),
            metadata_url: format!("{ISSUER}/.well-known/oauth-authorization-server"),
            authorization_endpoint: format!("{ISSUER}/authorize"),
            token_endpoint: format!("{ISSUER}/token"),
            revocation_endpoint: Some(format!("{ISSUER}/token")),
            registration_endpoint: Some(format!("{ISSUER}/register")),
            jwks_uri: None,
            code_challenge_methods_supported: Some(vec!["plain".into(), "S256".into()]),
            token_endpoint_auth_methods_supported: Some(vec![
                "client_secret_basic".into(),
                "client_secret_post".into(),
                "none".into(),
            ]),
            authorization_response_iss_parameter_supported: true,
        }
    }

    fn invalid(provider: &CredentialProvider) -> bool {
        matches!(validate(provider), Err(ExternalProviderError::Invalid(_)))
    }

    #[test]
    fn a_public_and_a_confidential_external_provider_pass_the_static_rules() {
        let public = external_provider();
        assert_eq!(validate(&public), Ok(()));
        let mut confidential = external_provider();
        confidential.token_endpoint_auth_method = Some(TokenEndpointAuthMethod::ClientSecretPost);
        confidential.client_secret_secret_ref = Some("tenant-a-client-secret".into());
        confidential.revocation_endpoint = None;
        assert_eq!(validate(&confidential), Ok(()));
        confidential.token_endpoint_auth_method = Some(TokenEndpointAuthMethod::ClientSecretBasic);
        assert_eq!(validate(&confidential), Ok(()));
    }

    #[test]
    fn a_provider_without_an_issuer_takes_none_of_the_external_fields() {
        let mut legacy = external_provider();
        legacy.issuer = None;
        legacy.client_id = None;
        legacy.token_endpoint_auth_method = None;
        legacy.revocation_endpoint = None;
        legacy.client_id_secret_ref = Some("client-id".into());
        assert_eq!(validate(&legacy), Ok(()));
        for change in [
            |p: &mut CredentialProvider| p.client_id = Some("client".into()),
            |p: &mut CredentialProvider| p.token_endpoint_auth_method = Some(TokenEndpointAuthMethod::None),
            |p: &mut CredentialProvider| p.revocation_endpoint = Some(format!("{ISSUER}/revoke")),
            |p: &mut CredentialProvider| p.allow_unadvertised_pkce = true,
        ] {
            let mut provider = legacy.clone();
            change(&mut provider);
            assert!(invalid(&provider), "{provider:?}");
        }
    }

    #[test]
    fn each_static_rule_refuses_an_external_provider_that_breaks_it() {
        type Change = fn(&mut CredentialProvider);
        let cases: Vec<(&str, Change)> = vec![
            ("client credentials type", |p| p.provider_type = CredentialProviderType::OAuth2ClientCredentials),
            ("api key type", |p| p.provider_type = CredentialProviderType::ApiKey),
            ("http issuer", |p| p.issuer = Some("http://203.0.113.10".into())),
            ("issuer with a query", |p| p.issuer = Some(format!("{ISSUER}/?tenant=a"))),
            ("no authorization endpoint", |p| p.authorization_endpoint = None),
            ("no token endpoint", |p| p.token_endpoint = None),
            ("http token endpoint", |p| p.token_endpoint = Some("http://203.0.113.10/token".into())),
            ("loopback token endpoint", |p| p.token_endpoint = Some("https://127.0.0.1/token".into())),
            ("private authorization endpoint", |p| {
                p.authorization_endpoint = Some("https://10.0.0.5/authorize".into())
            }),
            ("metadata revocation endpoint", |p| {
                p.revocation_endpoint = Some("https://169.254.169.254/latest/meta-data/".into())
            }),
            ("fragment", |p| p.token_endpoint = Some(format!("{ISSUER}/token#x"))),
            ("credentials", |p| p.token_endpoint = Some("https://u:p@203.0.113.10/token".into())),
            ("no client id", |p| p.client_id = None),
            ("empty client id", |p| p.client_id = Some(String::new())),
            ("client id with a space", |p| p.client_id = Some("a b".into())),
            ("client id over 2048 characters", |p| p.client_id = Some("a".repeat(2049))),
            ("a client id secret reference", |p| p.client_id_secret_ref = Some("client-id".into())),
            ("no auth method", |p| p.token_endpoint_auth_method = None),
            ("a secret for a public client", |p| p.client_secret_secret_ref = Some("secret".into())),
            ("no secret for a confidential client", |p| {
                p.token_endpoint_auth_method = Some(TokenEndpointAuthMethod::ClientSecretBasic)
            }),
            ("no callback", |p| p.callback_url = None),
            ("http callback", |p| p.callback_url = Some("http://boris.example/callback".into())),
            ("additional params", |p| {
                p.additional_params
                    .insert("state".into(), "attacker".into());
            }),
            ("a consent identity strategy", |p| p.consent_identity_strategy_id = Some("strategy".into())),
            ("an api key", |p| p.api_key_secret_ref = Some("key".into())),
            ("no resource", |p| p.resource = None),
            ("http resource", |p| p.resource = Some("http://203.0.113.10/mcp".into())),
            ("private resource", |p| p.resource = Some("https://10.0.0.5/mcp".into())),
            ("loopback resource", |p| p.resource = Some("https://127.0.0.1/mcp".into())),
        ];
        for (case, change) in cases {
            let mut provider = external_provider();
            change(&mut provider);
            assert!(invalid(&provider), "{case} must be refused");
        }
    }

    #[test]
    fn a_provider_that_matches_its_issuers_metadata_passes() {
        assert_eq!(check_metadata(&external_provider(), &metadata()), Ok(()));
    }

    #[test]
    fn a_provider_whose_endpoints_differ_from_the_metadata_is_refused() {
        let mismatch = |change: fn(&mut CredentialProvider), field: &'static str| {
            let mut provider = external_provider();
            change(&mut provider);
            assert_eq!(
                check_metadata(&provider, &metadata()),
                Err(ExternalProviderError::MetadataMismatch(field)),
                "{field}"
            );
        };
        mismatch(|p| p.authorization_endpoint = Some(format!("{ISSUER}/authorize/")), "authorization_endpoint");
        mismatch(|p| p.token_endpoint = Some("https://203.0.113.66/token".into()), "token_endpoint");
        mismatch(|p| p.revocation_endpoint = Some("https://203.0.113.66/revoke".into()), "revocation_endpoint");
        mismatch(|p| p.revocation_endpoint = None, "revocation_endpoint");
        mismatch(|p| p.issuer = Some("https://203.0.113.66".into()), "issuer");

        let mut silent = metadata();
        silent.revocation_endpoint = None;
        assert_eq!(
            check_metadata(&external_provider(), &silent),
            Err(ExternalProviderError::MetadataMismatch("revocation_endpoint")),
            "a revocation endpoint the metadata does not name"
        );
    }

    #[test]
    fn the_client_must_use_an_authentication_method_the_server_supports() {
        let mut provider = external_provider();
        let mut metadata = metadata();
        metadata.token_endpoint_auth_methods_supported = Some(vec!["client_secret_post".into()]);
        assert_eq!(
            check_metadata(&provider, &metadata),
            Err(ExternalProviderError::MetadataMismatch("token_endpoint_auth_method"))
        );
        metadata.token_endpoint_auth_methods_supported = None;
        assert_eq!(
            check_metadata(&provider, &metadata),
            Err(ExternalProviderError::MetadataMismatch("token_endpoint_auth_method")),
            "a server that lists no methods supports client_secret_basic only"
        );
        provider.token_endpoint_auth_method = Some(TokenEndpointAuthMethod::ClientSecretBasic);
        provider.client_secret_secret_ref = Some("secret".into());
        assert_eq!(check_metadata(&provider, &metadata), Ok(()));
    }

    #[test]
    fn the_server_must_support_s256_when_it_lists_pkce_methods() {
        let provider = external_provider();
        let mut metadata = metadata();
        metadata.code_challenge_methods_supported = Some(vec!["plain".into()]);
        assert_eq!(
            check_metadata(&provider, &metadata),
            Err(ExternalProviderError::MetadataMismatch("code_challenge_methods_supported"))
        );
        let mut excepted = external_provider();
        excepted.allow_unadvertised_pkce = true;
        assert_eq!(
            check_metadata(&excepted, &metadata),
            Err(ExternalProviderError::MetadataMismatch("code_challenge_methods_supported")),
            "the exception never admits a list without S256"
        );
    }

    #[test]
    fn a_server_that_does_not_list_pkce_methods_is_refused_unless_the_provider_names_the_exception() {
        let mut metadata = metadata();
        metadata.code_challenge_methods_supported = None;
        assert_eq!(
            check_metadata(&external_provider(), &metadata),
            Err(ExternalProviderError::MetadataMismatch("code_challenge_methods_supported"))
        );
        let mut excepted = external_provider();
        excepted.allow_unadvertised_pkce = true;
        assert_eq!(check_metadata(&excepted, &metadata), Ok(()));
    }

    fn update(value: serde_json::Value) -> UpdateCredentialProviderRequest {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn an_external_provider_keeps_its_endpoints_and_client_fields() {
        let existing = external_provider();
        for (field, value) in [
            ("issuer", json!("https://203.0.113.66")),
            ("provider_type", json!("oauth2_client_credentials")),
            ("authorization_endpoint", json!("https://203.0.113.66/authorize")),
            ("token_endpoint", json!("https://203.0.113.66/token")),
            ("revocation_endpoint", json!("https://203.0.113.66/revoke")),
            ("token_endpoint_auth_method", json!("client_secret_post")),
            ("client_id", json!("another-client")),
            ("client_id_secret_ref", json!("client-id")),
            ("client_secret_secret_ref", json!("secret")),
            ("callback_url", json!("https://attacker.example/callback")),
            ("resource", json!("https://203.0.113.66/mcp")),
            ("additional_params", json!({"redirect_uri": "https://attacker.example/"})),
            ("consent_identity_strategy_id", json!("strategy")),
            ("api_key_secret_ref", json!("key")),
            ("allow_unadvertised_pkce", json!(true)),
        ] {
            assert_eq!(
                refuse_changes(&existing, &update(json!({ field: value }))),
                Err(ExternalProviderError::Immutable(field)),
                "{field}"
            );
        }
    }

    #[test]
    fn an_external_provider_accepts_its_stored_values_and_editable_fields() {
        let existing = external_provider();
        let round_trip = update(serde_json::to_value(&existing).unwrap());
        assert_eq!(refuse_changes(&existing, &round_trip), Ok(()));
        assert_eq!(
            refuse_changes(
                &existing,
                &update(json!({
                    "name": "Linear (work)", "description": "work", "default_scopes": ["read", "write"],
                    "token_refresh_enabled": false, "additional_params": {}
                }))
            ),
            Ok(())
        );
    }

    #[test]
    fn a_provider_without_an_issuer_cannot_become_an_external_one() {
        let mut existing = external_provider();
        existing.issuer = None;
        existing.client_id = None;
        existing.token_endpoint_auth_method = None;
        existing.revocation_endpoint = None;
        assert_eq!(refuse_changes(&existing, &update(json!({"token_endpoint": "https://203.0.113.66/t"}))), Ok(()));
        for field in [
            json!({"issuer": ISSUER}),
            json!({"client_id": "client"}),
            json!({"token_endpoint_auth_method": "none"}),
            json!({"revocation_endpoint": format!("{ISSUER}/token")}),
            json!({"allow_unadvertised_pkce": true}),
        ] {
            assert!(
                matches!(refuse_changes(&existing, &update(field.clone())), Err(ExternalProviderError::Invalid(_))),
                "{field}"
            );
        }
    }

    async fn rendered(error: ExternalProviderError) -> (StatusCode, serde_json::Value) {
        let response = error.into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn refusals_render_fixed_codes_and_never_say_why_a_host_was_not_reached() {
        let (status, body) = rendered(ExternalProviderError::MetadataMismatch("token_endpoint")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "provider_metadata_mismatch");
        assert_eq!(body["field"], "token_endpoint");
        let (_, body) = rendered(ExternalProviderError::Immutable("client_id")).await;
        assert_eq!(body["code"], "provider_field_immutable");
        assert_eq!(body["field"], "client_id");
        let (_, body) = rendered(ExternalProviderError::Invalid("client_id is required")).await;
        assert_eq!(body, json!({"error": "client_id is required", "code": "invalid_provider"}));
        for (failure, reason) in [
            (DiscoveryFailure::Blocked, "unreachable"),
            (DiscoveryFailure::Unreachable, "unreachable"),
            (DiscoveryFailure::InvalidUrl, "invalid_url"),
            (DiscoveryFailure::HttpStatus, "http_status"),
            (DiscoveryFailure::TooLarge, "too_large"),
            (DiscoveryFailure::InvalidDocument, "invalid_document"),
            (DiscoveryFailure::IssuerMismatch, "issuer_mismatch"),
        ] {
            let (status, body) = rendered(ExternalProviderError::MetadataUnavailable(failure)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body["code"], "provider_metadata_unavailable");
            assert_eq!(body["reason"], reason, "{failure:?}");
        }
    }
}
