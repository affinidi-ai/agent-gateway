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
//!   sent: a Transit Point carries them only to the origin of `resource`, and a
//!   `proxy://` Transit Point only to an MCP Proxy of its tenant, served only
//!   through surfaces, whose `base_url` has that origin
//!   ([`check_proxy_grant_destination`]), and only while the proxy is the one
//!   the surface was saved with ([`check_proxy_pin`]).
//!
//! So a token that can edit providers or surfaces cannot point a provider whose
//! grants are stored at an endpoint of its choosing, which would collect them on
//! the next refresh or revocation, nor send its grants to a host of its choosing;
//! and a token that can edit an MCP Proxy but not the surface cannot change what
//! the grants sent through it are used for.

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
            let options = DiscoveryOptions {
                direct: true,
                ..DiscoveryOptions::default()
            };
            crate::authz_metadata::discover_client(&issuer, EgressPosture::Strict, options).await
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
    /// The provider's `resource` is not permitted for its `issuer`
    /// ([`resource_permitted`]).
    ResourceNotPermitted,
    /// The operator's `external_consent_issuers` does not permit the named
    /// field: the issuer, or an endpoint off its host ([`issuer_permitted`]).
    IssuerNotPermitted(&'static str),
    /// A tenant's token asked for an external consent provider while the
    /// operator lists no `external_consent_issuers`.
    IssuersRequired,
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
            Self::ResourceNotPermitted => serde_json::json!({
                "error": "resource is not permitted for the issuer: its host must be the issuer's host or one of its \
                          subdomains, or its origin one the gateway's external_consent_resource_origins lists for \
                          the issuer",
                "code": "provider_resource_not_permitted",
            }),
            Self::IssuerNotPermitted(field) => serde_json::json!({
                "error": format!(
                    "{field} is not permitted by the gateway's external_consent_issuers: the issuer must be listed \
                     there, and its endpoints must be on the issuer's host or have an origin listed for it"
                ),
                "code": "provider_issuer_not_permitted",
                "field": field,
            }),
            Self::IssuersRequired => serde_json::json!({
                "error": "A tenant cannot create a credential provider with an issuer while the gateway lists no \
                          external_consent_issuers, since the tenant would choose the endpoints its client \
                          authenticates at. The operator must list, in gateway.json's external_consent_issuers, the \
                          issuers tenants may use",
                "code": "external_consent_issuers_required",
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
            || !provider
                .scope_comparison
                .is_exact()
            || provider.revocation_ends_authorization
        {
            return Err(Invalid(
                "revocation_endpoint, token_endpoint_auth_method, client_id, allow_unadvertised_pkce, \
                 scope_comparison and revocation_ends_authorization need an issuer",
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
            "client_secret_secret_ref is required for client_secret_basic and client_secret_post, and refused for \
             none and private_key_jwt",
        ));
    }
    validate_client_assertion(provider, method)?;
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

/// The signed-JWT settings of an external consent provider: only a client
/// that authenticates with `private_key_jwt` has them, and then it needs a
/// signing key, signs with RS256 or PS256, names no audience, since its
/// assertion is always addressed to its issuer, and is itself the issuer and
/// subject of its assertion.
fn validate_client_assertion(
    provider: &CredentialProvider,
    method: crate::credential_providers::TokenEndpointAuthMethod,
) -> Result<(), ExternalProviderError> {
    use crate::credential_providers::{CredentialProviderType, JwtAssertionSettings, TokenEndpointAuthMethod};
    use ExternalProviderError::Invalid;

    let jwt = &provider.jwt;
    if method != TokenEndpointAuthMethod::PrivateKeyJwt {
        if *jwt != JwtAssertionSettings::default() {
            return Err(Invalid(
                "a provider with an issuer signs no JWT unless its token_endpoint_auth_method is private_key_jwt",
            ));
        }
        return Ok(());
    }
    if jwt
        .jwt_signing_key_secret_ref
        .is_none()
    {
        return Err(Invalid("private_key_jwt needs jwt_signing_key_secret_ref"));
    }
    if jwt.jwt_issuer.is_some() || jwt.jwt_subject.is_some() {
        return Err(Invalid(
            "a private_key_jwt client is the issuer and subject of its assertion, so jwt_issuer and jwt_subject are \
             refused",
        ));
    }
    if jwt
        .jwt_signing_algorithm
        .is_some_and(|algorithm| {
            !CredentialProviderType::OAuth2ClientCredentialsJwtAuth.allows_jwt_algorithm(algorithm)
        })
    {
        return Err(Invalid("private_key_jwt signs with RS256 or PS256"));
    }
    if jwt.jwt_audience.is_some() {
        return Err(Invalid(
            "a private_key_jwt client's assertion is always addressed to its issuer, so jwt_audience is refused",
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
            || request
                .scope_comparison
                .is_some_and(|comparison| !comparison.is_exact())
            || request.revocation_ends_authorization == Some(true)
        {
            return Err(ExternalProviderError::Invalid(
                "an existing provider cannot take an issuer, revocation_endpoint, token_endpoint_auth_method, \
                 client_id, allow_unadvertised_pkce, scope_comparison or revocation_ends_authorization; create a \
                 new provider instead",
            ));
        }
        return Ok(());
    }
    let jwt = &request.jwt;
    let stored = &existing.jwt;
    let fields: [(&'static str, bool); 24] = [
        (
            "scope_comparison",
            changes(
                request
                    .scope_comparison
                    .as_ref(),
                Some(&existing.scope_comparison),
            ),
        ),
        (
            "revocation_ends_authorization",
            changes(
                request
                    .revocation_ends_authorization
                    .as_ref(),
                Some(&existing.revocation_ends_authorization),
            ),
        ),
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
        (
            "jwt_signing_key_secret_ref",
            changes(
                jwt.jwt_signing_key_secret_ref
                    .as_ref(),
                stored
                    .jwt_signing_key_secret_ref
                    .as_ref(),
            ),
        ),
        (
            "jwt_certificate_secret_ref",
            changes(
                jwt.jwt_certificate_secret_ref
                    .as_ref(),
                stored
                    .jwt_certificate_secret_ref
                    .as_ref(),
            ),
        ),
        (
            "jwt_signing_algorithm",
            changes(
                jwt.jwt_signing_algorithm
                    .as_ref(),
                stored
                    .jwt_signing_algorithm
                    .as_ref(),
            ),
        ),
        ("jwt_audience", changes(jwt.jwt_audience.as_ref(), stored.jwt_audience.as_ref())),
        ("jwt_key_id", changes(jwt.jwt_key_id.as_ref(), stored.jwt_key_id.as_ref())),
        ("jwt_issuer", changes(jwt.jwt_issuer.as_ref(), stored.jwt_issuer.as_ref())),
        ("jwt_subject", changes(jwt.jwt_subject.as_ref(), stored.jwt_subject.as_ref())),
    ];
    match fields
        .into_iter()
        .find(|(_, changed)| *changed)
    {
        Some((field, _)) => Err(ExternalProviderError::Immutable(field)),
        None => Ok(()),
    }
}

/// The origin of `provider`'s `resource`, as its ASCII serialization.
pub fn resource_origin(provider: &CredentialProvider) -> Option<String> {
    provider
        .resource
        .as_deref()
        .and_then(|resource| url::Url::parse(resource).ok())
        .map(|resource| {
            resource
                .origin()
                .ascii_serialization()
        })
}

/// An IP address, or a DNS name whose labels are letters, digits and `-`, none
/// empty: so no wildcard-looking `*`, no `_` and no trailing dot.
fn plain_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => domain
            .split('.')
            .all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            }),
        url::Host::Ipv4(_) | url::Host::Ipv6(_) => true,
    }
}

/// An origin an operator wrote in `external_consent_resource_origins`, as its
/// ASCII serialization: an `https` URL with a host and nothing after it but an
/// optional `/`, whose host is an IP address or a plain DNS name, labels of
/// letters, digits and `-` with none empty. Entries are exact origins, so a
/// host such as `*.example.com`, which the URL parser takes literally, is not
/// one. `None` for anything else, which then permits nothing.
fn configured_origin(value: &str) -> Option<String> {
    let url = url::Url::parse(value.trim()).ok()?;
    let bare = url.scheme() == "https"
        && plain_host(&url.host()?)
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    bare.then(|| {
        url.origin()
            .ascii_serialization()
    })
}

/// The entries of gateway.json's `external_consent_resource_origins` that are
/// not plain `https` origins, issuers and resources alike, wildcard-looking
/// hosts among them: they permit nothing, and the gateway names them at
/// startup.
pub fn invalid_resource_origin_entries(permitted: &std::collections::HashMap<String, Vec<String>>) -> Vec<String> {
    let mut invalid: Vec<String> = permitted
        .iter()
        .flat_map(|(issuer, resources)| std::iter::once(issuer).chain(resources))
        .filter(|entry| configured_origin(entry).is_none())
        .cloned()
        .collect();
    invalid.sort();
    invalid
}

/// Whether `provider`'s `resource` is permitted for its `issuer`, so its grants
/// may go there. By default the resource's host must be the issuer's host or
/// one of its subdomains (an IP address only itself): hosts are compared as the
/// URL parser normalises them, in lower case and with international names in
/// punycode, label by label, so `evil-notion.com`, `notion.com.evil.example` or
/// a look-alike name never passes for the issuer's. Any other resource origin
/// must be one that `permitted`, gateway.json's
/// `external_consent_resource_origins`, lists for the issuer's origin: only the
/// operator's file sets it, never a tenant or an API caller. Both URLs must
/// parse; the `https` rules of [`validate`] and [`check_grant_destination`]
/// apply as well.
pub fn resource_permitted(
    provider: &CredentialProvider,
    permitted: &std::collections::HashMap<String, Vec<String>>,
) -> bool {
    let parse = |value: Option<&str>| value.and_then(|value| url::Url::parse(value).ok());
    let (Some(issuer), Some(resource)) = (parse(provider.issuer.as_deref()), parse(provider.resource.as_deref()))
    else {
        return false;
    };
    let on_the_issuers_host = match (issuer.host(), resource.host()) {
        (Some(url::Host::Domain(issuer)), Some(url::Host::Domain(resource))) => {
            resource == issuer
                || resource
                    .strip_suffix(issuer)
                    .is_some_and(|label| label.ends_with('.') && label.len() > 1)
        }
        (Some(issuer), Some(resource)) => issuer == resource,
        _ => false,
    };
    if on_the_issuers_host {
        return true;
    }
    let issuer_origin = issuer
        .origin()
        .ascii_serialization();
    let resource_origin = resource
        .origin()
        .ascii_serialization();
    permitted
        .iter()
        .filter(|(listed_issuer, _)| configured_origin(listed_issuer).as_deref() == Some(issuer_origin.as_str()))
        .flat_map(|(_, resources)| resources)
        .any(|listed| configured_origin(listed).as_deref() == Some(resource_origin.as_str()))
}

/// The origins gateway.json's `external_consent_issuers` lists for `issuer`,
/// compared exactly, or `None` when it does not list the issuer, or names it
/// by an entry that is not a plain `https` issuer.
fn listed_issuer_origins(
    issuer: &str,
    issuers: &std::collections::HashMap<String, Vec<String>>,
) -> Option<Vec<String>> {
    issuers
        .iter()
        .find(|(entry, _)| entry.as_str() == issuer && configured_issuer(entry))
        .map(|(_, origins)| {
            origins
                .iter()
                .filter_map(|origin| configured_origin(origin))
                .collect()
        })
}

/// Whether `endpoint` is on `issuer`'s own host, as the URL parser normalises
/// both (any port, since the host's owner controls its ports), or has one of
/// the `listed` origins exactly.
fn endpoint_on_issuer(
    issuer: &str,
    endpoint: &str,
    listed: &[String],
) -> bool {
    let (Ok(issuer), Ok(endpoint)) = (url::Url::parse(issuer), url::Url::parse(endpoint)) else {
        return false;
    };
    if issuer.host().is_some() && issuer.host() == endpoint.host() {
        return true;
    }
    let origin = endpoint
        .origin()
        .ascii_serialization();
    listed.contains(&origin)
}

/// Whether gateway.json's `external_consent_issuers` permits `provider`: when
/// it is set, its issuer must be listed, compared exactly, and its
/// authorization, token and revocation endpoints must each be on the issuer's
/// own host or have an origin listed for it. Unset, every issuer is permitted.
/// The error names the field that is not permitted. Checked when a provider is
/// created, a surface binds it, a connect starts or completes, and whenever
/// its grants are refreshed or sent.
pub fn issuer_permitted(
    provider: &CredentialProvider,
    issuers: Option<&std::collections::HashMap<String, Vec<String>>>,
) -> Result<(), &'static str> {
    let Some(issuers) = issuers else {
        return Ok(());
    };
    let Some(issuer) = provider.issuer.as_deref() else {
        return Err("issuer");
    };
    let listed = listed_issuer_origins(issuer, issuers).ok_or("issuer")?;
    for (field, endpoint) in [
        (
            "authorization_endpoint",
            provider
                .authorization_endpoint
                .as_deref(),
        ),
        (
            "token_endpoint",
            provider
                .token_endpoint
                .as_deref(),
        ),
        (
            "revocation_endpoint",
            provider
                .revocation_endpoint
                .as_deref(),
        ),
    ] {
        if endpoint.is_some_and(|endpoint| !endpoint_on_issuer(issuer, endpoint, &listed)) {
            return Err(field);
        }
    }
    Ok(())
}

/// Whether gateway.json's `external_consent_issuers` permits the issuer's
/// metadata: its `jwks_uri`, when it names one, is held to the rule of
/// [`issuer_permitted`]. The error names the field.
pub fn metadata_permitted(
    metadata: &ClientAuthzMetadata,
    issuers: Option<&std::collections::HashMap<String, Vec<String>>>,
) -> Result<(), &'static str> {
    let Some(issuers) = issuers else {
        return Ok(());
    };
    let listed = listed_issuer_origins(&metadata.issuer, issuers).ok_or("issuer")?;
    match metadata.jwks_uri.as_deref() {
        Some(jwks_uri) if !endpoint_on_issuer(&metadata.issuer, jwks_uri, &listed) => Err("jwks_uri"),
        _ => Ok(()),
    }
}

/// Whether `entry`, a key of `external_consent_issuers`, is a plain `https`
/// issuer: one the Strict posture accepts, written exactly, with a plain host.
fn configured_issuer(entry: &str) -> bool {
    entry.trim() == entry
        && crate::authz_metadata::validate_issuer(entry, EgressPosture::Strict).is_ok()
        && url::Url::parse(entry).is_ok_and(|url| {
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url
                    .host()
                    .is_some_and(|host| plain_host(&host))
        })
}

/// The entries of gateway.json's `external_consent_issuers` that are not
/// plain `https` issuers, or origins listed for one that are not plain `https`
/// origins: they permit nothing, and the gateway names them at startup.
pub fn invalid_issuer_entries(issuers: &std::collections::HashMap<String, Vec<String>>) -> Vec<String> {
    let mut invalid: Vec<String> = issuers
        .iter()
        .filter(|(issuer, _)| !configured_issuer(issuer))
        .map(|(issuer, _)| issuer.clone())
        .chain(
            issuers
                .values()
                .flatten()
                .filter(|origin| configured_origin(origin).is_none())
                .cloned(),
        )
        .collect();
    invalid.sort();
    invalid
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
/// is bound to where it is sent, not to a Transit Point id. It resolves nothing
/// on the async executor: without an allow-list, as in production, it resolves
/// nothing at all.
pub async fn check_grant_destination(
    provider: &CredentialProvider,
    target_endpoint: &str,
    exact_allowlist: Option<&str>,
) -> Result<url::Origin, &'static str> {
    grant_origin(provider, target_endpoint, exact_allowlist)
        .await
        .map_err(|refused| match refused {
            DestinationRefused::Fabric => "consent_mode external never forwards over Fabric",
            DestinationRefused::NoResource => NO_RESOURCE,
            DestinationRefused::NotPublicHttps => {
                "consent_mode external needs a target_endpoint that is a public https URL"
            }
            DestinationRefused::OtherOrigin => {
                "consent_mode external needs a target_endpoint with the origin of the credential provider's resource"
            }
        })
}

const NO_RESOURCE: &str = "the credential provider names no resource";

/// The refusal of a grant to the MCP Proxy a `proxy://` Transit Point names
/// that is missing or of another tenant: the two are not told apart.
pub const PROXY_UNAVAILABLE: &str = "consent_mode external needs an MCP Proxy of the surface's own tenant";

/// Why [`grant_origin`] refused a destination.
enum DestinationRefused {
    Fabric,
    NoResource,
    NotPublicHttps,
    OtherOrigin,
}

/// The origin of `provider`'s `resource`, when `destination` is a public
/// `https` URL (or a fixture `exact_allowlist` admits) with that origin.
async fn grant_origin(
    provider: &CredentialProvider,
    destination: &str,
    exact_allowlist: Option<&str>,
) -> Result<url::Origin, DestinationRefused> {
    if destination.starts_with("fabric://") {
        return Err(DestinationRefused::Fabric);
    }
    let resource = provider
        .resource
        .as_deref()
        .and_then(|resource| url::Url::parse(resource).ok())
        .ok_or(DestinationRefused::NoResource)?;
    let target = url::Url::parse(destination).map_err(|_| DestinationRefused::NotPublicHttps)?;
    if !is_strict_https_url(destination) && !crate::egress::exactly_allowlisted(destination, exact_allowlist).await {
        return Err(DestinationRefused::NotPublicHttps);
    }
    if target.origin() != resource.origin() {
        return Err(DestinationRefused::OtherOrigin);
    }
    Ok(resource.origin())
}

/// Whether the MCP Proxy `proxy` may be sent the grants of a Transit Point on
/// a surface of `tenant_id` whose target is `proxy://<its id>`: it is that
/// tenant's, and it is served only through surfaces (`direct_access: false`),
/// so nothing reaches its backend with a grant but the Transit Point that
/// holds it. A missing proxy and another tenant's are refused alike
/// ([`PROXY_UNAVAILABLE`]).
pub fn proxy_may_carry_grants(
    proxy: &crate::mcp_proxies::types::McpProxy,
    tenant_id: Option<&str>,
) -> Result<(), &'static str> {
    if proxy.tenant_id.as_deref() != tenant_id {
        return Err(PROXY_UNAVAILABLE);
    }
    if proxy.direct_access {
        return Err("consent_mode external needs an MCP Proxy served only through surfaces: set the MCP Proxy's \
             direct_access to false");
    }
    Ok(())
}

/// Whether a Transit Point on a surface of `tenant_id` whose target is
/// `proxy://<id>`, the MCP Proxy `proxy`, may carry the grants of the
/// external consent provider `provider`, and if so the origin they may be
/// sent to: the origin of the provider's `resource`, as for an `https`
/// Transit Point ([`check_grant_destination`]).
///
/// The proxy must be one [`proxy_may_carry_grants`] permits, and its
/// `base_url`, where its tool calls go, a public `https` URL with that origin.
/// The check runs when the surface is saved, when a connect starts, and on
/// every call with the proxy the call is sent through, so a proxy edited
/// afterwards to point elsewhere is never sent the grant.
pub async fn check_proxy_grant_destination(
    provider: &CredentialProvider,
    proxy: &crate::mcp_proxies::types::McpProxy,
    tenant_id: Option<&str>,
    exact_allowlist: Option<&str>,
) -> Result<url::Origin, &'static str> {
    proxy_may_carry_grants(proxy, tenant_id)?;
    grant_origin(provider, &proxy.base_url, exact_allowlist)
        .await
        .map_err(|refused| match refused {
            DestinationRefused::NoResource => NO_RESOURCE,
            DestinationRefused::Fabric | DestinationRefused::NotPublicHttps => {
                "consent_mode external needs an MCP Proxy whose base_url is a public https URL"
            }
            DestinationRefused::OtherOrigin => {
                "consent_mode external needs an MCP Proxy whose base_url has the origin of the credential provider's \
                 resource"
            }
        })
}

/// The refusal of a grant through an MCP Proxy that changed after the surface
/// was saved: its `base_url`, spec or `flatten_post_params` differ from those
/// the binding was pinned to ([`check_proxy_pin`]).
pub const PROXY_CHANGED: &str = "consent_mode external needs the MCP Proxy as it was when the surface was saved: its \
                                 base_url or OpenAPI spec has changed since, so save the surface again to use it";

/// Whether the MCP Proxy `proxy` still does what it did when the surface
/// whose `proxy://` Transit Point names it was saved: its
/// [`crate::mcp_proxies::types::McpProxy::grant_pin`] is `pinned`, the one the
/// save set on the binding. A binding with no pin, as one stored outside the
/// API has, is refused alike. So whoever may edit the proxy, but not the
/// surface, cannot change what a grant is used for: which operations its tool
/// names call, on which paths, with which descriptions.
pub fn check_proxy_pin(
    proxy: &crate::mcp_proxies::types::McpProxy,
    pinned: Option<&str>,
) -> Result<(), &'static str> {
    if pinned != Some(proxy.grant_pin().as_str()) {
        return Err(PROXY_CHANGED);
    }
    Ok(())
}

/// Where a Transit Point on a surface of `tenant_id` whose target is
/// `target_endpoint` sends the grants of `provider`: an `https` target's
/// origin ([`check_grant_destination`]), or for `proxy://<id>` the origin of
/// that MCP Proxy's `base_url`, read from `proxies`
/// ([`check_proxy_grant_destination`]), while the proxy is still the one the
/// binding's `proxy_pin` was taken from ([`check_proxy_pin`]).
pub async fn check_transit_grant_destination(
    provider: &CredentialProvider,
    target_endpoint: &str,
    proxy_pin: Option<&str>,
    proxies: Option<&dyn crate::mcp_proxies::McpProxyStore>,
    tenant_id: Option<&str>,
    exact_allowlist: Option<&str>,
) -> Result<url::Origin, &'static str> {
    let Some(proxy_id) = crate::mcp_proxies::types::endpoint_proxy_id(target_endpoint) else {
        return check_grant_destination(provider, target_endpoint, exact_allowlist).await;
    };
    let (Some(store), true) = (proxies, crate::mcp_proxies::handlers::is_valid_mcp_proxy_id(proxy_id)) else {
        return Err(PROXY_UNAVAILABLE);
    };
    let proxy = store
        .get(proxy_id)
        .await
        .ok()
        .flatten()
        .ok_or(PROXY_UNAVAILABLE)?;
    let destination = check_proxy_grant_destination(provider, &proxy, tenant_id, exact_allowlist).await?;
    check_proxy_pin(&proxy, proxy_pin)?;
    Ok(destination)
}

/// The refusal of a `proxy://` Transit Point that does not speak MCP.
pub const PROXY_TRANSIT_POINT_NEEDS_MCP: &str = "a Transit Point whose target is an MCP Proxy needs protocol mcp";

/// Whether the Transit Point `point` of `surface`, a resolved view, can be
/// served when its target is `proxy://<id>`: it speaks MCP, and it sends its
/// MCP Proxy's backend no credential but the grant of a `consent_mode:
/// external` binding, in a header. So it has no `target_auth`, and no other
/// binding applies to it: neither a `transit_credentials` of another consent
/// mode nor the surface's `outbound_credentials`, which apply on every
/// Transit Point. A Transit Point of any other target passes.
///
/// One rule set for every place: a surface save refuses a Transit Point that
/// breaks it (`400`), a connect for its binding is refused (`409`), and a
/// call to one stored outside the API is refused (`503`) before any
/// credential is read.
pub fn check_proxy_transit_point(
    surface: &crate::config::agent_surface::AgentSurface,
    point: &crate::config::agent_surface::TransitPoint,
) -> Result<(), &'static str> {
    if crate::mcp_proxies::types::endpoint_proxy_id(&point.target_endpoint).is_none() {
        return Ok(());
    }
    if point.protocol != crate::config::agent_surface::TransitProtocol::Mcp {
        return Err(PROXY_TRANSIT_POINT_NEEDS_MCP);
    }
    if point.target_auth.is_some() {
        return Err("a Transit Point whose target is an MCP Proxy sends its backend no credential but a consent_mode \
                    external grant: remove its target_auth");
    }
    if surface
        .transit_point_outbound_credentials(point)
        .iter()
        .any(|binding| matches!(binding.required_for, crate::config::types::CredentialRequirement::All))
    {
        return Err("a Transit Point whose target is an MCP Proxy sends its backend no credential but a consent_mode \
                    external grant: remove its transit_credentials of another consent_mode, and the surface's \
                    outbound_credentials");
    }
    if surface
        .transit_point_external_credentials(point)
        .is_some_and(|binding| {
            binding
                .inject_as
                .to_binding_injection()
                .header_name()
                .is_none()
        })
    {
        return Err("a Transit Point whose target is an MCP Proxy sends the grant in a header: inject_as \
                    bearer_header or custom_header");
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) const ISSUER: &str = "https://203.0.113.10";

    #[tokio::test]
    async fn a_grant_goes_only_to_a_public_https_target_with_the_origin_of_the_providers_resource() {
        let provider = external_provider();
        let resource = url::Url::parse("https://203.0.113.10/mcp")
            .unwrap()
            .origin();
        for target in ["https://203.0.113.10/mcp", "https://203.0.113.10/other/path?x=1", "https://203.0.113.10:443"] {
            assert_eq!(check_grant_destination(&provider, target, None).await, Ok(resource.clone()), "{target}");
        }
        for (case, target) in [
            ("another host", "https://203.0.113.66/mcp"),
            ("another port", "https://203.0.113.10:8443/mcp"),
            ("http", "http://203.0.113.10/mcp"),
            ("Fabric", "fabric://gateway-b/channel"),
            ("not a URL", "vendor"),
        ] {
            assert!(
                check_grant_destination(&provider, target, None)
                    .await
                    .is_err(),
                "{case} must be refused"
            );
        }

        let mut private = external_provider();
        private.resource = Some("https://10.0.0.5/mcp".into());
        assert!(
            check_grant_destination(&private, "https://10.0.0.5/mcp", None)
                .await
                .is_err(),
            "a private address is refused even when a stored provider names it"
        );
        let mut loopback = external_provider();
        loopback.resource = Some("https://127.0.0.1/mcp".into());
        assert!(
            check_grant_destination(&loopback, "https://127.0.0.1/mcp", None)
                .await
                .is_err()
        );
        let mut without_resource = external_provider();
        without_resource.resource = None;
        assert!(
            check_grant_destination(&without_resource, "https://203.0.113.10/mcp", None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn only_the_test_allowlist_admits_an_http_fixture_and_never_another_origin_or_fabric() {
        let mut fixture = external_provider();
        fixture.resource = Some("http://127.0.0.1:9/mcp".into());
        let allowlist = Some("http://127.0.0.1:9");
        assert_eq!(
            check_grant_destination(&fixture, "http://127.0.0.1:9/mcp", allowlist).await,
            Ok(url::Url::parse("http://127.0.0.1:9")
                .unwrap()
                .origin())
        );
        assert!(
            check_grant_destination(&fixture, "http://127.0.0.1:9/mcp", None)
                .await
                .is_err()
        );
        assert!(
            check_grant_destination(&fixture, "http://127.0.0.1:10/mcp", Some("http://127.0.0.1:10"))
                .await
                .is_err()
        );
        assert!(
            check_grant_destination(&fixture, "fabric://127.0.0.1:9/mcp", allowlist)
                .await
                .is_err()
        );
    }

    /// An MCP Proxy of `tenant`, served only through surfaces, whose tool
    /// calls go to `base_url`.
    pub(crate) fn grant_proxy(
        id: &str,
        tenant: Option<&str>,
        base_url: &str,
    ) -> crate::mcp_proxies::types::McpProxy {
        let mut proxy = crate::mcp_proxies::types::McpProxy::new(
            id.into(),
            String::new(),
            base_url.into(),
            String::new(),
            "/mcp".into(),
            format!("/{id}"),
        );
        proxy.id = id.into();
        proxy.tenant_id = tenant.map(str::to_string);
        proxy.direct_access = false;
        proxy
    }

    /// A `proxy://` Transit Point carries a grant only to an MCP Proxy of the
    /// surface's tenant, served only through surfaces, whose `base_url` is a
    /// public `https` URL with the origin of the provider's resource; a
    /// missing proxy and another tenant's are refused alike.
    #[tokio::test]
    async fn a_grant_goes_through_a_proxy_only_to_the_providers_resource_from_the_surfaces_own_tenant() {
        use crate::mcp_proxies::McpProxyStore;
        let provider = external_provider();
        let resource = url::Url::parse("https://203.0.113.10/mcp")
            .unwrap()
            .origin();
        let permitted = grant_proxy("drive", Some("tenant-a"), "https://203.0.113.10/drive/v3");
        assert_eq!(
            check_proxy_grant_destination(&provider, &permitted, Some("tenant-a"), None).await,
            Ok(resource.clone())
        );
        let mut direct = permitted.clone();
        direct.direct_access = true;
        for (case, proxy, tenant, expected) in [
            ("another tenant's proxy", permitted.clone(), Some("tenant-b"), PROXY_UNAVAILABLE),
            (
                "an operator's proxy on a tenant's surface",
                grant_proxy("drive", None, "https://203.0.113.10/x"),
                Some("tenant-a"),
                PROXY_UNAVAILABLE,
            ),
            ("a tenant's proxy on an operator's surface", permitted.clone(), None, PROXY_UNAVAILABLE),
            (
                "a proxy anyone can call directly",
                direct,
                Some("tenant-a"),
                "consent_mode external needs an MCP Proxy served only through surfaces: set the MCP Proxy's \
                 direct_access to false",
            ),
            (
                "another origin",
                grant_proxy("drive", Some("tenant-a"), "https://203.0.113.66/drive/v3"),
                Some("tenant-a"),
                "consent_mode external needs an MCP Proxy whose base_url has the origin of the credential \
                 provider's resource",
            ),
            (
                "another port",
                grant_proxy("drive", Some("tenant-a"), "https://203.0.113.10:8443/drive/v3"),
                Some("tenant-a"),
                "consent_mode external needs an MCP Proxy whose base_url has the origin of the credential \
                 provider's resource",
            ),
            (
                "http",
                grant_proxy("drive", Some("tenant-a"), "http://203.0.113.10/drive/v3"),
                Some("tenant-a"),
                "consent_mode external needs an MCP Proxy whose base_url is a public https URL",
            ),
        ] {
            assert_eq!(check_proxy_grant_destination(&provider, &proxy, tenant, None).await, Err(expected), "{case}");
        }

        let directory = tempfile::tempdir().unwrap();
        let store = crate::mcp_proxies::FileSystemMcpProxyStore::new(directory.path().to_path_buf())
            .await
            .unwrap();
        store
            .create(&permitted)
            .await
            .unwrap();
        let proxies: Option<&dyn McpProxyStore> = Some(&store);
        let pin = permitted.grant_pin();
        let pinned = Some(pin.as_str());
        assert_eq!(
            check_transit_grant_destination(&provider, "proxy://drive", pinned, proxies, Some("tenant-a"), None).await,
            Ok(resource.clone())
        );
        assert_eq!(
            check_transit_grant_destination(
                &provider,
                "https://203.0.113.10/mcp",
                None,
                proxies,
                Some("tenant-a"),
                None
            )
            .await,
            Ok(resource),
            "an https Transit Point is checked as before"
        );
        for (case, endpoint, proxies, tenant) in [
            ("a missing proxy", "proxy://missing", proxies, Some("tenant-a")),
            ("another tenant's proxy", "proxy://drive", proxies, Some("tenant-b")),
            ("no proxy store", "proxy://drive", None, Some("tenant-a")),
            ("an id no MCP Proxy can have", "proxy://drive/x", proxies, Some("tenant-a")),
        ] {
            assert_eq!(
                check_transit_grant_destination(&provider, endpoint, pinned, proxies, tenant, None).await,
                Err(PROXY_UNAVAILABLE),
                "{case}"
            );
        }
        for (case, pin) in [("no pin", None), ("a pin of another proxy", Some("sha256:00"))] {
            assert_eq!(
                check_transit_grant_destination(&provider, "proxy://drive", pin, proxies, Some("tenant-a"), None).await,
                Err(PROXY_CHANGED),
                "{case}"
            );
        }
        assert_eq!(
            check_grant_destination(&provider, "proxy://drive", None).await,
            Err("consent_mode external needs a target_endpoint that is a public https URL"),
            "the Access Point's Target is never an MCP Proxy with a grant"
        );
    }

    /// The pin of an MCP Proxy changes with what its tool calls do (its
    /// `base_url`, its spec, `flatten_post_params`) and with nothing else, so
    /// an update that changes none of them keeps it.
    #[test]
    fn an_mcp_proxy_pin_follows_what_its_tool_calls_do_and_nothing_else() {
        let mut proxy = grant_proxy("drive", Some("tenant-a"), "https://203.0.113.10/drive/v3");
        proxy.openapi_spec = r#"{"openapi": "3.0.0", "paths": {"/files": {}}}"#.into();
        let pin = proxy.grant_pin();
        assert!(pin.starts_with("sha256:"), "{pin}");
        assert_eq!(check_proxy_pin(&proxy, Some(&pin)), Ok(()));
        let mut unchanged = proxy.clone();
        unchanged.name = "Renamed".into();
        unchanged.description = "Described".into();
        unchanged.updated_at = chrono::Utc::now() + chrono::Duration::hours(1);
        unchanged.managed_by = Some("Boris".into());
        assert_eq!(unchanged.grant_pin(), pin, "a save that changes nothing it calls keeps the pin");
        type Edit = fn(&mut crate::mcp_proxies::types::McpProxy);
        let edits: [(&str, Edit); 4] = [
            ("base_url", |proxy| proxy.base_url = "https://203.0.113.10/drive/v2".into()),
            ("spec", |proxy| proxy.openapi_spec = "{\"paths\": {}}".into()),
            ("spec whitespace", |proxy| proxy.openapi_spec.push(' ')),
            ("flatten_post_params", |proxy| proxy.flatten_post_params = true),
        ];
        for (case, edit) in edits {
            let mut edited = proxy.clone();
            edit(&mut edited);
            assert_ne!(edited.grant_pin(), pin, "{case}");
            assert_eq!(check_proxy_pin(&edited, Some(&pin)), Err(PROXY_CHANGED), "{case}");
        }
        let mut shifted = proxy.clone();
        shifted.base_url = format!("{}{}", proxy.base_url, proxy.openapi_spec);
        shifted.openapi_spec = String::new();
        assert_ne!(shifted.grant_pin(), pin, "fields cannot run into each other");
    }

    fn issued_for(
        issuer: &str,
        resource: &str,
    ) -> CredentialProvider {
        let mut provider = external_provider();
        provider.issuer = Some(issuer.into());
        provider.resource = Some(resource.into());
        provider
    }

    /// A provider's resource must be on its issuer's host or a subdomain, or be
    /// an origin the operator lists for the issuer; look-alike hosts never pass.
    #[test]
    fn a_providers_resource_must_be_permitted_for_its_issuer() {
        let none = std::collections::HashMap::new();
        let issuer = "https://mcp.notion.com";
        for resource in [
            "https://mcp.notion.com/mcp",
            "https://MCP.Notion.com/mcp",
            "https://mcp.notion.com:8443/mcp",
            "https://api.mcp.notion.com/v1",
        ] {
            assert!(resource_permitted(&issued_for(issuer, resource), &none), "{resource}");
        }
        for (case, resource) in [
            ("another site", "https://collector.example/mcp"),
            ("a name that ends like the issuer's", "https://evil-mcp.notion.com.example/mcp"),
            ("a label that ends like the issuer's", "https://evilmcp.notion.com/mcp"),
            ("a prefix of another domain", "https://evil-notion.com/mcp"),
            ("the issuer's name under another domain", "https://notion.com.evil.example/mcp"),
            ("the issuer's name under another domain", "https://mcp.notion.com.evil.example/mcp"),
            ("a look-alike in punycode", "https://mcp.n\u{043e}tion.com/mcp"),
            ("a sibling of the issuer", "https://api.notion.com/mcp"),
            ("the issuer's parent", "https://notion.com/mcp"),
            ("a trailing dot", "https://mcp.notion.com./mcp"),
            ("an IP address", "https://203.0.113.10/mcp"),
        ] {
            assert!(!resource_permitted(&issued_for(issuer, resource), &none), "{case}: {resource}");
        }
        assert!(resource_permitted(&issued_for("https://203.0.113.10", "https://203.0.113.10/mcp"), &none));
        assert!(!resource_permitted(&issued_for("https://203.0.113.10", "https://203.0.113.11/mcp"), &none));
        let mut without_resource = external_provider();
        without_resource.resource = None;
        assert!(!resource_permitted(&without_resource, &none));
    }

    /// The operator's `external_consent_resource_origins` permits other origins
    /// for one issuer, exactly as listed: no other issuer, origin or scheme.
    #[test]
    fn an_origin_the_operator_lists_for_the_issuer_is_permitted_and_no_other() {
        let google = "https://accounts.google.com";
        let permitted = std::collections::HashMap::from([
            (format!("{google}/"), vec!["https://www.googleapis.com".to_string()]),
            ("https://other-issuer.example".to_string(), vec!["https://collector.example".to_string()]),
            ("not an origin".to_string(), vec!["https://collector.example/path".to_string()]),
        ]);
        assert!(resource_permitted(&issued_for(google, "https://www.googleapis.com/calendar/v3"), &permitted));
        assert!(
            !resource_permitted(
                &issued_for(google, "https://www.googleapis.com/calendar/v3"),
                &std::collections::HashMap::new()
            ),
            "without the operator's entry the sibling site is refused"
        );
        for resource in [
            "https://collector.example/mcp",
            "https://storage.googleapis.com/b",
            "https://www.googleapis.com:8443/calendar",
            "https://www.googleapis.com.evil.example/calendar",
        ] {
            assert!(!resource_permitted(&issued_for(google, resource), &permitted), "{resource}");
        }
        assert_eq!(invalid_resource_origin_entries(&permitted), ["https://collector.example/path", "not an origin"]);
    }

    /// Entries are exact origins. One that is not a plain `https` origin, such
    /// as one that looks like a wildcard, is named at startup and permits
    /// nothing, not even the literal origin it spells.
    #[test]
    fn an_entry_that_is_not_a_plain_https_origin_is_named_and_permits_nothing() {
        let google = "https://accounts.google.com";
        let entries = [
            "https://*.googleapis.com",
            "https://*",
            "https://www_googleapis.com",
            "https://www.googleapis.com.",
            "https://www..googleapis.com",
            "https://user@www.googleapis.com",
            "https://www.googleapis.com/calendar",
            "https://www.googleapis.com?x=1",
            "https://www.googleapis.com#x",
            "http://www.googleapis.com",
            "www.googleapis.com",
        ];
        let permitted = std::collections::HashMap::from([(
            google.to_string(),
            entries
                .iter()
                .map(|entry| entry.to_string())
                .collect(),
        )]);
        let mut named = entries.to_vec();
        named.sort();
        assert_eq!(invalid_resource_origin_entries(&permitted), named);
        for resource in [
            "https://*.googleapis.com/calendar",
            "https://storage.googleapis.com/calendar",
            "https://www_googleapis.com/calendar",
            "https://www.googleapis.com./calendar",
        ] {
            assert!(!resource_permitted(&issued_for(google, resource), &permitted), "{resource}");
        }

        let wildcard_issuer = std::collections::HashMap::from([(
            "https://*.google.com".to_string(),
            vec!["https://www.googleapis.com".to_string()],
        )]);
        assert_eq!(invalid_resource_origin_entries(&wildcard_issuer), ["https://*.google.com"]);
        assert!(!resource_permitted(
            &issued_for("https://*.google.com", "https://www.googleapis.com/calendar"),
            &wildcard_issuer
        ));
        let plain = std::collections::HashMap::from([(
            "https://login.microsoftonline.com".to_string(),
            vec![
                "https://graph.microsoft.com".to_string(),
                "https://xn--bcher-kva.example:8443/".to_string(),
                "https://203.0.113.20".to_string(),
                "https://[2001:db8::1]".to_string(),
            ],
        )]);
        assert!(invalid_resource_origin_entries(&plain).is_empty(), "plain origins, ports and IPs are valid");
    }

    fn issuers(entries: &[(&str, &[&str])]) -> std::collections::HashMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(issuer, origins)| {
                (
                    issuer.to_string(),
                    origins
                        .iter()
                        .map(|origin| origin.to_string())
                        .collect(),
                )
            })
            .collect()
    }

    /// Without `external_consent_issuers` any issuer is permitted, as before.
    /// With it, only a listed issuer, compared exactly, whose authorization,
    /// token and revocation endpoints are on its own host or listed for it.
    #[test]
    fn only_a_listed_issuer_with_its_endpoints_on_its_host_or_listed_is_permitted() {
        let provider = external_provider();
        assert_eq!(issuer_permitted(&provider, None), Ok(()), "no allow-list permits any issuer");
        assert_eq!(issuer_permitted(&provider, Some(&issuers(&[(ISSUER, &[])]))), Ok(()));
        assert_eq!(issuer_permitted(&provider, Some(&issuers(&[]))), Err("issuer"), "an empty list permits none");
        for listed in
            ["https://203.0.113.11", "https://203.0.113.10/", "https://203.0.113.10/tenant", "https://203.0.113.10:443"]
        {
            assert_eq!(
                issuer_permitted(&provider, Some(&issuers(&[(listed, &[])]))),
                Err("issuer"),
                "{listed} is not the issuer {ISSUER}"
            );
        }

        let google = "https://accounts.google.com";
        let mut provider = external_provider();
        provider.issuer = Some(google.into());
        provider.authorization_endpoint = Some(format!("{google}/o/oauth2/v2/auth"));
        provider.token_endpoint = Some("https://oauth2.googleapis.com/token".into());
        provider.revocation_endpoint = Some("https://oauth2.googleapis.com/revoke".into());
        assert_eq!(
            issuer_permitted(&provider, Some(&issuers(&[(google, &[])]))),
            Err("token_endpoint"),
            "a token endpoint off the issuer's host must be listed"
        );
        assert_eq!(
            issuer_permitted(&provider, Some(&issuers(&[(google, &["https://oauth2.googleapis.com"])]))),
            Ok(())
        );
        provider.token_endpoint = Some("https://collector.example/token".into());
        assert_eq!(
            issuer_permitted(&provider, Some(&issuers(&[(google, &["https://oauth2.googleapis.com"])]))),
            Err("token_endpoint")
        );
        provider.token_endpoint = Some("https://oauth2.googleapis.com/token".into());
        provider.authorization_endpoint = Some("https://accounts.google.com.evil.example/auth".into());
        assert_eq!(
            issuer_permitted(&provider, Some(&issuers(&[(google, &["https://oauth2.googleapis.com"])]))),
            Err("authorization_endpoint")
        );
        provider.authorization_endpoint = Some(format!("{google}/o/oauth2/v2/auth"));
        provider.revocation_endpoint = Some("https://oauth2.googleapis.com:8443/revoke".into());
        assert_eq!(
            issuer_permitted(&provider, Some(&issuers(&[(google, &["https://oauth2.googleapis.com"])]))),
            Err("revocation_endpoint"),
            "a listed origin is exact, port included"
        );
        provider.revocation_endpoint = None;
        assert_eq!(
            issuer_permitted(&provider, Some(&issuers(&[(google, &["https://oauth2.googleapis.com"])]))),
            Ok(())
        );

        let mut subdomain = external_provider();
        subdomain.issuer = Some("https://login.vendor.example".into());
        subdomain.authorization_endpoint = Some("https://login.vendor.example/authorize".into());
        subdomain.token_endpoint = Some("https://api.login.vendor.example/token".into());
        subdomain.revocation_endpoint = None;
        assert_eq!(
            issuer_permitted(&subdomain, Some(&issuers(&[("https://login.vendor.example", &[])]))),
            Err("token_endpoint"),
            "only the issuer's own host, not a subdomain"
        );
    }

    /// A `jwks_uri` the issuer's metadata names is held to the same rule.
    #[test]
    fn a_jwks_uri_off_the_issuers_host_must_be_listed() {
        let mut metadata = metadata();
        assert_eq!(metadata_permitted(&metadata, Some(&issuers(&[(ISSUER, &[])]))), Ok(()));
        metadata.jwks_uri = Some(format!("{ISSUER}/jwks"));
        assert_eq!(metadata_permitted(&metadata, Some(&issuers(&[(ISSUER, &[])]))), Ok(()));
        metadata.jwks_uri = Some("https://203.0.113.66/jwks".into());
        assert_eq!(metadata_permitted(&metadata, None), Ok(()));
        assert_eq!(metadata_permitted(&metadata, Some(&issuers(&[(ISSUER, &[])]))), Err("jwks_uri"));
        assert_eq!(metadata_permitted(&metadata, Some(&issuers(&[(ISSUER, &["https://203.0.113.66"])]))), Ok(()));
    }

    /// Entries that are not plain `https` issuers or origins are named at
    /// startup and permit nothing.
    #[test]
    fn issuer_entries_that_are_not_plain_https_issuers_or_origins_are_named_and_permit_nothing() {
        let entries = issuers(&[
            ("https://*.google.com", &[]),
            ("http://accounts.google.com", &[]),
            ("https://accounts.google.com?x=1", &[]),
            ("https://user@accounts.google.com", &[]),
            (
                "https://login.microsoftonline.com/tenant/v2.0",
                &["https://*.microsoft.com", "https://graph.microsoft.com"],
            ),
        ]);
        assert_eq!(
            invalid_issuer_entries(&entries),
            [
                "http://accounts.google.com",
                "https://*.google.com",
                "https://*.microsoft.com",
                "https://accounts.google.com?x=1",
                "https://user@accounts.google.com",
            ]
        );
        let mut provider = external_provider();
        provider.issuer = Some("https://*.google.com".into());
        assert_eq!(issuer_permitted(&provider, Some(&entries)), Err("issuer"));
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

    /// A client that authenticates with `private_key_jwt` names a signing key
    /// and no secret; no other client signs a JWT, and none acts as another
    /// issuer or subject.
    #[test]
    fn a_private_key_jwt_client_names_its_signing_key_and_no_other_does() {
        use crate::credential_providers::JwtSigningAlgorithm;
        let mut signing = external_provider();
        signing.token_endpoint_auth_method = Some(TokenEndpointAuthMethod::PrivateKeyJwt);
        signing
            .jwt
            .jwt_signing_key_secret_ref = Some("signing-key".into());
        signing.jwt.jwt_key_id = Some("key-1".into());
        assert_eq!(validate(&signing), Ok(()));
        assert_eq!(signing.jwt_signing_algorithm(), Some(JwtSigningAlgorithm::PS256));
        signing
            .jwt
            .jwt_signing_algorithm = Some(JwtSigningAlgorithm::RS256);
        assert_eq!(validate(&signing), Ok(()));

        type Change = fn(&mut CredentialProvider);
        let cases: Vec<(&str, Change)> = vec![
            ("no signing key", |p| {
                p.jwt
                    .jwt_signing_key_secret_ref = None
            }),
            ("a client secret", |p| p.client_secret_secret_ref = Some("secret".into())),
            ("an ES256 key", |p| p.jwt.jwt_signing_algorithm = Some(JwtSigningAlgorithm::ES256)),
            ("another issuer", |p| p.jwt.jwt_issuer = Some("someone@example.com".into())),
            ("another subject", |p| p.jwt.jwt_subject = Some("someone".into())),
            ("an http audience", |p| p.jwt.jwt_audience = Some("http://203.0.113.10/token".into())),
            ("an audience, which is always the issuer", |p| {
                p.jwt.jwt_audience = Some("https://203.0.113.10/token".into())
            }),
        ];
        for (case, change) in cases {
            let mut provider = signing.clone();
            change(&mut provider);
            assert!(invalid(&provider), "{case} must be refused");
        }
        let mut public = external_provider();
        public
            .jwt
            .jwt_signing_key_secret_ref = Some("signing-key".into());
        assert!(invalid(&public), "a public client signs nothing");
        assert_eq!(public.jwt_signing_algorithm(), None);

        let mut metadata = metadata();
        signing
            .jwt
            .jwt_signing_algorithm = None;
        assert_eq!(
            check_metadata(&signing, &metadata),
            Err(ExternalProviderError::MetadataMismatch("token_endpoint_auth_method"))
        );
        metadata
            .token_endpoint_auth_methods_supported
            .as_mut()
            .unwrap()
            .push("private_key_jwt".into());
        assert_eq!(check_metadata(&signing, &metadata), Ok(()));
        for (field, value) in [
            ("jwt_signing_key_secret_ref", json!("another-key")),
            ("jwt_key_id", json!("key-2")),
            ("jwt_audience", json!("https://203.0.113.66/token")),
        ] {
            assert_eq!(
                refuse_changes(&signing, &update(json!({ field: value }))),
                Err(ExternalProviderError::Immutable(field)),
                "{field}"
            );
        }
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
            |p: &mut CredentialProvider| {
                p.scope_comparison = crate::credential_providers::scope_comparison::ScopeComparison::Google
            },
            |p: &mut CredentialProvider| p.revocation_ends_authorization = true,
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
            ("scope_comparison", json!("google")),
            ("revocation_ends_authorization", json!(true)),
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
