//! Target Authentication: the credential the gateway attaches, as itself, to the
//! requests it sends to a surface's Target.
//!
//! Every call site resolves through [`TargetCredentialResolver::resolve`], or through
//! [`TargetCredentialResolver::resolve_unrecorded`] for a read that answers no caller,
//! and applies the surface's fallback through [`apply_target_auth_fallback`], so the
//! caller gate, path confinement, tenancy, provider-type and leg rules hold everywhere.

use std::sync::Arc;

use axum::http::{HeaderName, HeaderValue};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use crate::audit::request_events::{RejectionReason, RejectionStage, RequestFacts, request_rejected};
use crate::config::agent_surface::AgentSurface;
use crate::config::{CredentialInjection, TargetAuthConfig, TargetAuthFallback, TargetAuthMethod};
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::credential_providers::{CredentialProvider, ProviderGrant};
use crate::delegation_vault::audit::{DelegationAuditAction, audit_event};
use crate::delegation_vault::gateway_token::{
    Freshness, GatewayTokenCache, GatewayTokenError, GatewayTokenKey, ProviderSecrets, acquire_gateway_token,
};
use crate::proxy::handler::CallerAssertion;
use crate::secrets::SecretsStore;

/// The request leg a Target credential is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetLeg {
    HttpTarget,
    FabricForward,
    McpProxy,
    TransitPoint,
}

impl TargetLeg {
    pub fn supports_credential_provider(self) -> bool {
        match self {
            Self::HttpTarget => true,
            Self::FabricForward | Self::McpProxy | Self::TransitPoint => false,
        }
    }
}

pub struct TargetAuthContext<'a> {
    pub surface: &'a AgentSurface,
    /// The final upstream URL, exactly as passed to the HTTP client.
    pub destination: &'a str,
    pub leg: TargetLeg,
    pub caller: CallerAssertion,
    pub via_fabric: bool,
    pub trace_id: Option<&'a str>,
    /// Header names the request already carries for another credential: a delegated
    /// credential, or on the receiving gateway any header that arrived in the
    /// `ForwardRequest`. Neither credential silently replaces the other.
    pub occupied_headers: &'a [HeaderName],
}

#[derive(Debug)]
pub enum TargetCredentialOutcome {
    Inject(TargetCredential),
    Withheld(WithheldReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithheldReason {
    UnauthenticatedCaller,
    NotImplemented,
    /// A `static_secret` header whose name the request already carries: the
    /// per-caller credential wins.
    HeaderAlreadySet,
}

/// A validated header whose value is marked sensitive.
pub struct TargetCredential {
    pub name: HeaderName,
    pub value: HeaderValue,
    pub provenance: CredentialProvenance,
}

/// Where a Target credential came from, never its value: the credential provider's
/// name and, for a gateway token, when it expires. Empty for a static secret.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CredentialProvenance {
    pub provider_name: Option<String>,
    pub expires_at: Option<std::time::SystemTime>,
}

impl TargetCredential {
    /// The header as text, for callers that build their own header maps.
    pub fn into_pair(self) -> (String, String) {
        (self.name.to_string(), String::from_utf8_lossy(self.value.as_bytes()).into_owned())
    }

    /// Sets the credential on `request`, replacing any header of the same name the
    /// request already has, so the Target receives exactly one.
    pub fn set_on(
        self,
        request: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(self.name, self.value);
        request.headers(headers)
    }
}

impl std::fmt::Debug for TargetCredential {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("TargetCredential")
            .field("name", &self.name)
            .field("value", &"[redacted]")
            .field("provenance", &self.provenance)
            .finish()
    }
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetCredentialError {
    #[error("secret_unavailable")]
    SecretUnavailable,
    #[error("provider_not_found")]
    ProviderNotFound,
    #[error("token_unavailable")]
    TokenUnavailable,
    #[error("forbidden")]
    Forbidden,
    #[error("unsupported")]
    Unsupported,
    #[error("invalid_header")]
    InvalidHeader,
    #[error("outside_target_base")]
    OutsideTargetBase,
    #[error("header_conflict")]
    HeaderConflict,
}

impl TargetCredentialError {
    /// Whether `fallback: passthrough` may forward the request without the credential.
    pub fn honours_fallback(self) -> bool {
        match self {
            Self::SecretUnavailable | Self::ProviderNotFound | Self::TokenUnavailable => true,
            Self::Forbidden
            | Self::Unsupported
            | Self::InvalidHeader
            | Self::OutsideTargetBase
            | Self::HeaderConflict => false,
        }
    }

    pub fn category(self) -> &'static str {
        match self {
            Self::SecretUnavailable => "secret_unavailable",
            Self::ProviderNotFound => "provider_not_found",
            Self::TokenUnavailable => "token_unavailable",
            Self::Forbidden => "forbidden",
            Self::Unsupported => "unsupported",
            Self::InvalidHeader => "invalid_header",
            Self::OutsideTargetBase => "outside_target_base",
            Self::HeaderConflict => "header_conflict",
        }
    }
}

impl From<GatewayTokenError> for TargetCredentialError {
    fn from(error: GatewayTokenError) -> Self {
        match error {
            GatewayTokenError::Forbidden => Self::Forbidden,
            GatewayTokenError::Unsupported => Self::Unsupported,
            GatewayTokenError::SecretUnavailable => Self::SecretUnavailable,
            GatewayTokenError::Unavailable
            | GatewayTokenError::InvalidResponse
            | GatewayTokenError::AssertionFailed => Self::TokenUnavailable,
        }
    }
}

/// What a call site does with the resolution.
#[derive(Debug)]
pub enum TargetAuthDecision {
    Inject(TargetCredential),
    Continue,
    Reject,
}

/// The fixed 502 body every call site answers when Target Authentication fails.
pub const TARGET_AUTH_FAILED: &str = "Target authentication failed";

/// The one place the surface's fallback is applied. `Reject` always answers 502
/// [`TARGET_AUTH_FAILED`].
pub fn apply_target_auth_fallback(
    auth: &TargetAuthConfig,
    result: Result<TargetCredentialOutcome, TargetCredentialError>,
) -> TargetAuthDecision {
    match result {
        Ok(TargetCredentialOutcome::Inject(credential)) => TargetAuthDecision::Inject(credential),
        Ok(TargetCredentialOutcome::Withheld(_)) => TargetAuthDecision::Continue,
        Err(error) if !refuses_request(auth, error) => TargetAuthDecision::Continue,
        Err(_) => TargetAuthDecision::Reject,
    }
}

/// Whether the surface's fallback leaves a request without its credential refused.
fn refuses_request(
    auth: &TargetAuthConfig,
    error: TargetCredentialError,
) -> bool {
    !(error.honours_fallback() && auth.fallback == TargetAuthFallback::Passthrough)
}

/// Resolves Target Authentication from the secrets store, the credential provider
/// store and the gateway token cache shared by every surface on this replica.
#[derive(Clone)]
pub struct TargetCredentialResolver {
    secrets: Option<Arc<dyn SecretsStore>>,
    providers: Option<Arc<dyn CredentialProviderStorage>>,
    tokens: Arc<GatewayTokenCache>,
}

impl TargetCredentialResolver {
    pub fn new(
        secrets: Option<Arc<dyn SecretsStore>>,
        providers: Option<Arc<dyn CredentialProviderStorage>>,
        tokens: Arc<GatewayTokenCache>,
    ) -> Self {
        Self { secrets, providers, tokens }
    }

    /// Resolves the credential for a request whose refusal is answered 502, and records
    /// that refusal as a rejected request.
    pub async fn resolve(
        &self,
        auth: &TargetAuthConfig,
        ctx: &TargetAuthContext<'_>,
    ) -> Result<TargetCredentialOutcome, TargetCredentialError> {
        let result = self
            .resolve_unrecorded(auth, ctx)
            .await;
        if let Err(error) = &result
            && refuses_request(auth, *error)
        {
            request_rejected(
                &RequestFacts {
                    surface_id: &ctx.surface.surface_id,
                    channel_name: &ctx.surface.name,
                    trace_id: ctx.trace_id,
                    via_fabric: ctx.via_fabric,
                },
                RejectionStage::Forward,
                RejectionReason::TargetAuthUnavailable,
                502,
                None,
            );
        }
        result
    }

    /// [`Self::resolve`] for a read whose refusal answers no caller, so it records no
    /// rejected request.
    pub async fn resolve_unrecorded(
        &self,
        auth: &TargetAuthConfig,
        ctx: &TargetAuthContext<'_>,
    ) -> Result<TargetCredentialOutcome, TargetCredentialError> {
        let result = self
            .resolve_method(auth, ctx)
            .await;
        if let Err(error) = &result {
            warn!(
                surface_id = %ctx.surface.surface_id,
                category = error.category(),
                "Target authentication failed"
            );
        }
        result
    }

    async fn resolve_method(
        &self,
        auth: &TargetAuthConfig,
        ctx: &TargetAuthContext<'_>,
    ) -> Result<TargetCredentialOutcome, TargetCredentialError> {
        match &auth.method {
            TargetAuthMethod::CredentialLookup => {
                debug!(surface_id = %ctx.surface.surface_id, "credential_lookup Target Authentication injects nothing");
                Ok(TargetCredentialOutcome::Withheld(WithheldReason::NotImplemented))
            }
            TargetAuthMethod::StaticSecret {
                secret_id,
                header_name,
                header_format,
            } => {
                if let Some(withheld) = withheld_for_caller(ctx, false) {
                    return Ok(withheld);
                }
                confine_to_target_base(ctx)?;
                if is_occupied(ctx, header_name) {
                    debug!(surface_id = %ctx.surface.surface_id, "The request already carries the Target Authentication header");
                    return Ok(TargetCredentialOutcome::Withheld(WithheldReason::HeaderAlreadySet));
                }
                let store = self
                    .secrets
                    .as_ref()
                    .ok_or(TargetCredentialError::SecretUnavailable)?;
                let secret = store
                    .get_by_secret_id(secret_id)
                    .await
                    .map_err(|_| TargetCredentialError::SecretUnavailable)?
                    .ok_or(TargetCredentialError::SecretUnavailable)?;
                if secret.tenant_id != ctx.surface.tenant_id {
                    return Err(TargetCredentialError::Forbidden);
                }
                let value = Zeroizing::new(secret.value);
                let credential = header(header_name, &header_format.replace("{value}", &value))?;
                Ok(TargetCredentialOutcome::Inject(credential))
            }
            TargetAuthMethod::CredentialProvider {
                credential_provider_id,
                scopes,
                inject_as,
            } => {
                let target = ProviderTarget {
                    credential_provider_id,
                    scopes,
                    inject_as,
                };
                let result = self
                    .resolve_provider(&target, ctx)
                    .await;
                target.audit(ctx, &result);
                result.map(|resolved| match resolved {
                    ProviderResolution::Inject { credential, .. } => TargetCredentialOutcome::Inject(credential),
                    ProviderResolution::Withheld(reason) => TargetCredentialOutcome::Withheld(reason),
                })
            }
        }
    }

    async fn resolve_provider(
        &self,
        target: &ProviderTarget<'_>,
        ctx: &TargetAuthContext<'_>,
    ) -> Result<ProviderResolution, TargetCredentialError> {
        if !ctx
            .leg
            .supports_credential_provider()
            || matches!(target.inject_as, CredentialInjection::Meta { .. })
        {
            return Err(TargetCredentialError::Unsupported);
        }
        if let Some(TargetCredentialOutcome::Withheld(reason)) = withheld_for_caller(ctx, true) {
            return Ok(ProviderResolution::Withheld(reason));
        }
        confine_to_target_base(ctx)?;
        if !permits_credential_provider_target(&ctx.surface.target.endpoint) {
            return Err(TargetCredentialError::Forbidden);
        }
        if injection_header_name(target.inject_as).is_some_and(|name| is_occupied(ctx, name)) {
            return Err(TargetCredentialError::HeaderConflict);
        }
        let provider = self
            .providers
            .as_ref()
            .ok_or(TargetCredentialError::ProviderNotFound)?
            .get(target.credential_provider_id)
            .await
            .map_err(|_| TargetCredentialError::ProviderNotFound)?
            .ok_or(TargetCredentialError::ProviderNotFound)?;
        if provider.tenant_id != ctx.surface.tenant_id {
            return Err(TargetCredentialError::Forbidden);
        }
        if !provider
            .provider_type
            .serves_target_authentication()
        {
            return Err(TargetCredentialError::Unsupported);
        }
        let store = self
            .secrets
            .as_ref()
            .ok_or(TargetCredentialError::SecretUnavailable)?;
        let secrets = ProviderSecrets::new(store, &provider);
        let (value, freshness, expires_at) = match provider.provider_type.grant() {
            ProviderGrant::StaticKey => {
                let secret_ref = provider
                    .api_key_secret_ref
                    .as_deref()
                    .ok_or(TargetCredentialError::SecretUnavailable)?;
                (
                    secrets
                        .resolve(secret_ref)
                        .await?,
                    None,
                    None,
                )
            }
            ProviderGrant::GatewayToken => {
                let scopes = effective_scopes(target.scopes, &provider);
                let key = GatewayTokenKey::for_target_auth(&provider, &scopes)?;
                let grant = acquire_gateway_token(&self.tokens, &key, &provider, &secrets).await?;
                (grant.access_token, Some(grant.freshness), Some(grant.expires_at))
            }
            ProviderGrant::UserConsent => return Err(TargetCredentialError::Unsupported),
        };
        let mut credential = injected_header(target.inject_as, &value)?;
        credential.provenance = CredentialProvenance {
            provider_name: Some(provider.name.clone()),
            expires_at,
        };
        Ok(ProviderResolution::Inject {
            credential,
            provider: Box::new(provider),
            freshness,
        })
    }
}

struct ProviderTarget<'a> {
    credential_provider_id: &'a str,
    scopes: &'a [String],
    inject_as: &'a CredentialInjection,
}

enum ProviderResolution {
    Inject { credential: TargetCredential, provider: Box<CredentialProvider>, freshness: Option<Freshness> },
    Withheld(WithheldReason),
}

impl ProviderTarget<'_> {
    fn audit(
        &self,
        ctx: &TargetAuthContext<'_>,
        result: &Result<ProviderResolution, TargetCredentialError>,
    ) {
        let (category, action, detail, provider) = match result {
            Ok(ProviderResolution::Withheld(_)) => return,
            Ok(ProviderResolution::Inject { provider, freshness, .. }) => (
                "token_injected",
                DelegationAuditAction::TokenInjected,
                format!("target_auth_{}", freshness.map_or("api_key", Freshness::as_str)),
                Some(provider.as_ref()),
            ),
            Err(error) => (
                "token_not_found",
                DelegationAuditAction::TokenNotFound,
                format!("target_auth_{}", error.category()),
                None,
            ),
        };
        let surface = ctx.surface;
        crate::delegation_vault::audit::emit(category, || {
            let mut event = audit_event(
                action,
                None,
                None,
                Some(provider.map_or(self.credential_provider_id, |provider| provider.provider_id.as_str())),
                Some(&surface.surface_id),
            );
            event.provider_name = provider.map(|provider| provider.name.clone());
            event.channel_name = Some(surface.name.clone());
            event.target_endpoint = Some(
                surface
                    .target
                    .endpoint
                    .clone(),
            );
            event.protocol = Some(
                surface
                    .access_point
                    .protocol
                    .to_string(),
            );
            event.scopes = Some(match provider {
                Some(provider) => effective_scopes(self.scopes, provider),
                None => self.scopes.to_vec(),
            });
            event.inject_as = Some(injection_label(self.inject_as).to_string());
            event.via_fabric = ctx.via_fabric;
            event.trace_id = ctx
                .trace_id
                .map(str::to_string);
            event.detail = Some(detail);
            event
        });
    }
}

/// The caller gate: a caller nobody vouched for never receives the credential.
/// `GatewayOriginated` vouches only for a request to one of the surface's agent
/// card URLs. For a provider credential, an `Authenticated` caller on a surface
/// that does not authenticate its callers is treated as unauthenticated too.
fn withheld_for_caller(
    ctx: &TargetAuthContext<'_>,
    gateway_identity: bool,
) -> Option<TargetCredentialOutcome> {
    let vouched = ctx
        .caller
        .permits_target_credential()
        && match ctx.caller {
            CallerAssertion::GatewayOriginated => crate::proxy::paths::is_agent_card_url(ctx.surface, ctx.destination),
            CallerAssertion::Authenticated | CallerAssertion::Unauthenticated => {
                !gateway_identity || crate::proxy::handler::surface_authenticates_callers(ctx.surface)
            }
        };
    if vouched {
        return None;
    }
    warn!(
        surface_id = %ctx.surface.surface_id,
        "Refusing to inject target credentials: the caller was not authenticated"
    );
    Some(TargetCredentialOutcome::Withheld(WithheldReason::UnauthenticatedCaller))
}

fn is_occupied(
    ctx: &TargetAuthContext<'_>,
    header_name: &str,
) -> bool {
    ctx.occupied_headers
        .iter()
        .any(|occupied| {
            occupied
                .as_str()
                .eq_ignore_ascii_case(header_name.trim())
        })
}

fn confine_to_target_base(ctx: &TargetAuthContext<'_>) -> Result<(), TargetCredentialError> {
    match ctx.leg {
        TargetLeg::HttpTarget if !crate::proxy::paths::is_within_target_base(ctx.surface, ctx.destination) => {
            Err(TargetCredentialError::OutsideTargetBase)
        }
        TargetLeg::HttpTarget | TargetLeg::FabricForward | TargetLeg::McpProxy | TargetLeg::TransitPoint => Ok(()),
    }
}

/// Whether a surface's Target may receive a credential provider's credential: an
/// https endpoint, or, under `AG_TEST_MODE=true`, an endpoint whose origin an
/// origin-only entry of the test egress allowlist names.
pub fn permits_credential_provider_target(endpoint: &str) -> bool {
    let Ok(endpoint) = url::Url::parse(endpoint.trim()) else {
        return false;
    };
    endpoint.scheme() == "https"
        || (endpoint.scheme() == "http"
            && crate::egress::bdd_egress_allowlist().is_some_and(|allowlist| {
                allowlist
                    .split(',')
                    .filter_map(|entry| url::Url::parse(entry.trim()).ok())
                    .any(|entry| {
                        entry
                            .path()
                            .trim_end_matches('/')
                            .is_empty()
                            && entry.origin() == endpoint.origin()
                    })
            }))
}

/// Whether a request leg may carry the gateway's own token from an `oauth2_jwt_bearer`
/// delegation binding: the surface authenticates its callers, the leg's `endpoint`
/// passes [`permits_credential_provider_target`], and on the HTTP Target leg the final
/// upstream URL, `destination`, stays under the Target's base. The surface save applies
/// the same rule; this holds it for surfaces that reach the runtime without that check.
pub fn permits_jwt_bearer_leg(
    surface: &AgentSurface,
    endpoint: &str,
    destination: Option<&str>,
) -> bool {
    crate::proxy::handler::surface_authenticates_callers(surface)
        && permits_credential_provider_target(endpoint)
        && destination.is_none_or(|destination| crate::proxy::paths::is_within_target_base(surface, destination))
}

/// Header names a Target credential may never set.
const FORBIDDEN_TARGET_HEADERS: &[&str] = &["host", "content-length", "transfer-encoding", "connection"];

/// Whether `inject_as` may carry a Target credential: `bearer_header`, or a
/// `custom_header` with a valid name that is not hop-by-hop or framing.
pub fn validate_target_injection(inject_as: &CredentialInjection) -> Result<(), String> {
    match inject_as {
        CredentialInjection::BearerHeader => Ok(()),
        CredentialInjection::CustomHeader { name, format } => {
            if HeaderName::from_bytes(name.as_bytes()).is_err()
                || FORBIDDEN_TARGET_HEADERS
                    .iter()
                    .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
            {
                return Err(format!("inject_as.name '{name}' cannot carry a Target credential"));
            }
            if !format.contains("{value}") {
                return Err("inject_as.format must contain {value}".to_string());
            }
            Ok(())
        }
        CredentialInjection::Meta { .. } => Err("inject_as 'meta' is not supported for Target Authentication".into()),
    }
}

/// The header an injection writes: `Authorization` for `bearer_header`, the
/// configured name for `custom_header`, none for `meta`.
pub fn injection_header_name(inject_as: &CredentialInjection) -> Option<&str> {
    match inject_as {
        CredentialInjection::BearerHeader => Some("Authorization"),
        CredentialInjection::CustomHeader { name, .. } => Some(name),
        CredentialInjection::Meta { .. } => None,
    }
}

/// The header a Target Authentication method writes, if any.
pub fn target_auth_header_name(method: &TargetAuthMethod) -> Option<&str> {
    match method {
        TargetAuthMethod::CredentialLookup => None,
        TargetAuthMethod::StaticSecret { header_name, .. } => Some(header_name),
        TargetAuthMethod::CredentialProvider { inject_as, .. } => injection_header_name(inject_as),
    }
}

fn effective_scopes(
    scopes: &[String],
    provider: &CredentialProvider,
) -> Vec<String> {
    if scopes.is_empty() {
        provider
            .default_scopes
            .clone()
    } else {
        scopes.to_vec()
    }
}

fn injection_label(inject_as: &CredentialInjection) -> &'static str {
    match inject_as {
        CredentialInjection::BearerHeader => "bearer_header",
        CredentialInjection::CustomHeader { .. } => "custom_header",
        CredentialInjection::Meta { .. } => "meta",
    }
}

fn injected_header(
    inject_as: &CredentialInjection,
    value: &str,
) -> Result<TargetCredential, TargetCredentialError> {
    match inject_as {
        CredentialInjection::BearerHeader => header("Authorization", &format!("Bearer {value}")),
        CredentialInjection::CustomHeader { name, format } => {
            if validate_target_injection(inject_as).is_err() {
                return Err(TargetCredentialError::InvalidHeader);
            }
            header(name, &format.replace("{value}", value))
        }
        CredentialInjection::Meta { .. } => Err(TargetCredentialError::Unsupported),
    }
}

fn header(
    name: &str,
    value: &str,
) -> Result<TargetCredential, TargetCredentialError> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| TargetCredentialError::InvalidHeader)?;
    let mut value = HeaderValue::from_str(value).map_err(|_| TargetCredentialError::InvalidHeader)?;
    value.set_sensitive(true);
    Ok(TargetCredential {
        name,
        value,
        provenance: CredentialProvenance::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::mock_auth_server::{Endpoint, Fault, JwtBearerClient, MockAuthServer};
    use crate::component_tests::helpers::oidc_keys::SigningFixture;
    use crate::credential_providers::CredentialProviderType;
    use crate::credential_providers::jwt_assertion::JwtBearerAlgorithm;
    use crate::credential_providers::storage::FileSystemCredentialProviderStore;
    use crate::delegation_vault::gateway_token::GrantEgress;
    use crate::secrets::{CreateSecretRequest, FilesystemSecretsStore};
    use serde_json::json;

    const TARGET: &str = "https://agent.example/api";

    struct Fixture {
        server: MockAuthServer,
        _directory: tempfile::TempDir,
        secrets: Arc<dyn SecretsStore>,
        providers: Arc<dyn CredentialProviderStorage>,
        resolver: TargetCredentialResolver,
    }

    impl Fixture {
        async fn start() -> Self {
            let server = MockAuthServer::start().await;
            server.register_client("client-a", "secret-a");
            let directory = tempfile::tempdir().expect("tempdir");
            let secrets: Arc<dyn SecretsStore> = Arc::new(
                FilesystemSecretsStore::new_async(
                    directory
                        .path()
                        .join("secrets")
                        .to_str()
                        .expect("utf-8 path"),
                )
                .await
                .expect("secrets store"),
            );
            let providers: Arc<dyn CredentialProviderStorage> = Arc::new(
                FileSystemCredentialProviderStore::new(
                    directory
                        .path()
                        .join("providers"),
                )
                .await
                .expect("provider store"),
            );
            let tokens = Arc::new(GatewayTokenCache::new(GrantEgress {
                timeout: std::time::Duration::from_secs(5),
                exact_allowlist: Some(server.token_endpoint()),
            }));
            let resolver = TargetCredentialResolver::new(Some(secrets.clone()), Some(providers.clone()), tokens);
            Self {
                server,
                _directory: directory,
                secrets,
                providers,
                resolver,
            }
        }

        async fn secret(
            &self,
            secret_id: &str,
            value: &str,
            tenant: Option<&str>,
        ) {
            self.secrets
                .create(CreateSecretRequest {
                    tenant_id: tenant.map(str::to_string),
                    name: secret_id.to_string(),
                    secret_id: secret_id.to_string(),
                    description: None,
                    value: value.to_string(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .expect("secret is created");
        }

        async fn provider(
            &self,
            id: &str,
            provider_type: CredentialProviderType,
            tenant: Option<&str>,
            configure: impl FnOnce(&mut CredentialProvider),
        ) {
            let mut provider: CredentialProvider = serde_json::from_value(json!({
                "id": id, "name": id, "provider_id": id,
                "token_endpoint": self.server.token_endpoint(),
                "default_scopes": ["read"],
                "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
            }))
            .expect("provider deserializes");
            provider.provider_type = provider_type;
            provider.tenant_id = tenant.map(str::to_string);
            configure(&mut provider);
            self.providers
                .create(provider)
                .await
                .expect("provider is created");
        }

        async fn client_credentials(
            &self,
            id: &str,
            tenant: Option<&str>,
        ) {
            self.secret(&format!("{id}_ID"), "client-a", tenant)
                .await;
            self.secret(&format!("{id}_SECRET"), "secret-a", tenant)
                .await;
            self.provider(id, CredentialProviderType::OAuth2ClientCredentials, tenant, |provider| {
                provider.client_id_secret_ref = Some(format!("{id}_ID"));
                provider.client_secret_secret_ref = Some(format!("{id}_SECRET"));
            })
            .await;
        }

        async fn resolve(
            &self,
            surface: &AgentSurface,
            destination: &str,
            leg: TargetLeg,
            caller: CallerAssertion,
        ) -> Result<TargetCredentialOutcome, TargetCredentialError> {
            self.resolve_occupied(surface, destination, leg, caller, &[])
                .await
        }

        async fn resolve_occupied(
            &self,
            surface: &AgentSurface,
            destination: &str,
            leg: TargetLeg,
            caller: CallerAssertion,
            occupied_headers: &[HeaderName],
        ) -> Result<TargetCredentialOutcome, TargetCredentialError> {
            let auth = surface
                .target_auth()
                .expect("surface has Target Authentication");
            self.resolver
                .resolve(
                    auth,
                    &TargetAuthContext {
                        surface,
                        destination,
                        leg,
                        caller,
                        via_fabric: false,
                        trace_id: Some("trace-1"),
                        occupied_headers,
                    },
                )
                .await
        }
    }

    fn surface(
        method: serde_json::Value,
        fallback: &str,
        tenant: Option<&str>,
        authenticates_callers: bool,
    ) -> AgentSurface {
        let mut access_point = json!({"listen_address": "127.0.0.1:0", "route": "/agent", "protocol": "a2a"});
        if authenticates_callers {
            access_point["caller_authentication"] = json!({"methods": [{
                "type": "jwt_bearer", "jwt_verification_strategy_id": "strategy", "audiences": []
            }]});
        }
        serde_json::from_value(json!({
            "surface_id": "surface-1", "name": "Surface", "tenant_id": tenant,
            "access_point": access_point,
            "target": {"endpoint": TARGET, "auth": {"method": method, "fallback": fallback}}
        }))
        .expect("surface JSON")
    }

    fn provider_method(id: &str) -> serde_json::Value {
        json!({"credential_provider": {"credential_provider_id": id}})
    }

    fn injected(outcome: Result<TargetCredentialOutcome, TargetCredentialError>) -> (String, String) {
        match outcome {
            Ok(TargetCredentialOutcome::Inject(credential)) => credential.into_pair(),
            other => panic!("expected a credential, got {other:?}"),
        }
    }

    const IN_BASE: &str = "https://agent.example/api/v1/message:send";

    #[tokio::test]
    async fn test_client_credentials_provider_injects_one_cached_gateway_token() {
        let fixture = Fixture::start().await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        let surface = surface(provider_method("cp-cc"), "reject", None, true);

        let (name, value) = injected(
            fixture
                .resolve(&surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                .await,
        );
        assert_eq!(name, "authorization");
        assert!(value.starts_with("Bearer ey"), "a signed token from the mock: {value}");
        let card = "https://agent.example/api/.well-known/agent-card.json";
        let (_, again) = injected(
            fixture
                .resolve(&surface, card, TargetLeg::HttpTarget, CallerAssertion::GatewayOriginated)
                .await,
        );
        assert_eq!(again, value, "the card fetch and the call share one token");
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            1
        );
        assert_eq!(
            fixture.server.requests()[0]
                .scope
                .as_deref(),
            Some("read")
        );
    }

    #[tokio::test]
    async fn test_jwt_bearer_provider_injects_a_token_the_authorization_server_issued() {
        let fixture = Fixture::start().await;
        let key = SigningFixture::es256(0);
        fixture
            .server
            .register_jwt_client(JwtBearerClient {
                iss: "https://issuer.demo.example".into(),
                sub: "agent-1".into(),
                keys: vec![key.clone()],
            });
        fixture
            .secret("SIGNING_KEY", key.private_pkcs8_pem(), None)
            .await;
        fixture
            .provider("cp-jwt", CredentialProviderType::OAuth2JwtBearer, None, |provider| {
                provider.jwt_bearer = Some(crate::credential_providers::JwtBearerSettings {
                    assertion_issuer: "https://issuer.demo.example".into(),
                    assertion_subject: Some("agent-1".into()),
                    signing_key_secret_ref: "SIGNING_KEY".into(),
                    signing_algorithm: JwtBearerAlgorithm::Es256,
                    key_id: Some(key.kid.clone()),
                });
            })
            .await;
        let method = json!({"credential_provider": {
            "credential_provider_id": "cp-jwt", "scopes": ["agent.invoke"],
            "inject_as": {"type": "custom_header", "name": "X-Agent-Token", "format": "Token {value}"}
        }});
        let surface = surface(method, "reject", None, true);

        let (name, value) = injected(
            fixture
                .resolve(&surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                .await,
        );
        assert_eq!(name, "x-agent-token");
        assert!(value.starts_with("Token ey"), "{value}");
        let logged = fixture.server.requests();
        assert_eq!(logged.len(), 1);
        assert_eq!(logged[0].status, 200);
        assert_eq!(logged[0].scope.as_deref(), Some("agent.invoke"));
    }

    #[tokio::test]
    async fn test_api_key_provider_injects_its_key_without_a_grant() {
        let fixture = Fixture::start().await;
        fixture
            .secret("API_KEY", "key-value", Some("tenant-a"))
            .await;
        fixture
            .provider("cp-key", CredentialProviderType::ApiKey, Some("tenant-a"), |provider| {
                provider.api_key_secret_ref = Some("API_KEY".into());
            })
            .await;
        let surface = surface(provider_method("cp-key"), "reject", Some("tenant-a"), true);
        assert_eq!(
            injected(
                fixture
                    .resolve(&surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                    .await
            ),
            ("authorization".to_string(), "Bearer key-value".to_string())
        );
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            0
        );
    }

    #[tokio::test]
    async fn test_provenance_names_the_provider_and_token_expiry_but_never_the_value() {
        let fixture = Fixture::start().await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        fixture
            .secret("API_KEY", "key-value", None)
            .await;
        fixture
            .provider("cp-key", CredentialProviderType::ApiKey, None, |provider| {
                provider.api_key_secret_ref = Some("API_KEY".into());
            })
            .await;
        fixture
            .secret("STATIC", "static-value", None)
            .await;
        let credential = |outcome| match outcome {
            Ok(TargetCredentialOutcome::Inject(credential)) => credential,
            other => panic!("expected a credential, got {other:?}"),
        };
        let fixture = &fixture;
        let resolve = move |method| {
            let surface = surface(method, "reject", None, true);
            async move {
                fixture
                    .resolve(&surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                    .await
            }
        };

        let before = std::time::SystemTime::now();
        let token = credential(resolve(provider_method("cp-cc")).await);
        assert_eq!(
            token
                .provenance
                .provider_name
                .as_deref(),
            Some("cp-cc")
        );
        let expires_at = token
            .provenance
            .expires_at
            .expect("a gateway token has an expiry");
        assert!(expires_at > before, "the token expires in the future");
        let debug = format!("{token:?}");
        let (_, value) = token.into_pair();
        assert!(!debug.contains(&value[7..]), "Debug never shows the token: {debug}");

        let key = credential(resolve(provider_method("cp-key")).await);
        assert_eq!(
            key.provenance,
            CredentialProvenance {
                provider_name: Some("cp-key".into()),
                expires_at: None
            },
            "an API key provider has no token expiry"
        );
        assert!(!format!("{key:?}").contains("key-value"));

        let static_secret =
            credential(resolve(json!({"static_secret": {"secret_id": "STATIC", "header_name": "X-Key"}})).await);
        assert_eq!(static_secret.provenance, CredentialProvenance::default());
        assert!(!format!("{static_secret:?}").contains("static-value"));
    }

    #[tokio::test]
    async fn test_gateway_token_is_withheld_from_callers_nobody_vouched_for() {
        let fixture = Fixture::start().await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        let open = surface(provider_method("cp-cc"), "reject", None, false);
        let guarded = surface(provider_method("cp-cc"), "reject", None, true);
        for (surface, caller) in [(&open, CallerAssertion::Authenticated), (&guarded, CallerAssertion::Unauthenticated)]
        {
            assert!(matches!(
                fixture
                    .resolve(surface, IN_BASE, TargetLeg::HttpTarget, caller)
                    .await,
                Ok(TargetCredentialOutcome::Withheld(WithheldReason::UnauthenticatedCaller))
            ));
        }
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            0
        );
        let card = "https://agent.example/api/.well-known/agent-card.json";
        injected(
            fixture
                .resolve(&open, card, TargetLeg::HttpTarget, CallerAssertion::GatewayOriginated)
                .await,
        );
    }

    #[tokio::test]
    async fn test_a_variant_without_caller_authentication_never_receives_an_inherited_gateway_token() {
        let fixture = Fixture::start().await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        let mut record = surface(provider_method("cp-cc"), "reject", None, true);
        record.variants = vec![
            serde_json::from_value(json!({
                "id": "v-open", "alias": "open", "name": "open", "description": "", "enabled": true,
                "overrides": {"access_point": {"caller_authentication": {"methods": []}}}
            }))
            .expect("variant JSON"),
        ];
        let open = record
            .resolve_variant(Some("open"))
            .expect("variant resolves");
        assert!(matches!(
            fixture
                .resolve(&open, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                .await,
            Ok(TargetCredentialOutcome::Withheld(WithheldReason::UnauthenticatedCaller))
        ));
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            0
        );
        let base = record
            .resolve_variant(None)
            .expect("base resolves");
        injected(
            fixture
                .resolve(&base, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                .await,
        );
    }

    #[tokio::test]
    async fn test_gateway_originated_vouches_only_for_the_agent_card_fetch() {
        let fixture = Fixture::start().await;
        fixture
            .secret("STATIC", "static-value", None)
            .await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        let static_secret = json!({"static_secret": {"secret_id": "STATIC", "header_name": "X-Key"}});
        for method in [static_secret, provider_method("cp-cc")] {
            for authenticates_callers in [false, true] {
                let surface = surface(method.clone(), "reject", None, authenticates_callers);
                for destination in [
                    "https://agent.example/api/x/discovery",
                    "https://agent.example/api/admin/reports/discovery",
                    "https://agent.example/api/.well-known/ucp",
                    "https://agent.example/api/.well-known/agent-card.json?debug=1",
                ] {
                    assert!(
                        matches!(
                            fixture
                                .resolve(
                                    &surface,
                                    destination,
                                    TargetLeg::HttpTarget,
                                    CallerAssertion::GatewayOriginated
                                )
                                .await,
                            Ok(TargetCredentialOutcome::Withheld(WithheldReason::UnauthenticatedCaller))
                        ),
                        "{destination} on a surface authenticating callers: {authenticates_callers}"
                    );
                }
            }
        }
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            0
        );
        let open = surface(provider_method("cp-cc"), "reject", None, false);
        let (name, _) = injected(
            fixture
                .resolve(
                    &open,
                    "https://agent.example/api/.well-known/agent.json",
                    TargetLeg::HttpTarget,
                    CallerAssertion::GatewayOriginated,
                )
                .await,
        );
        assert_eq!(name, "authorization");
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            1
        );
    }

    #[tokio::test]
    async fn test_a_refused_request_is_audited_and_a_passthrough_request_is_not() {
        use crate::delegation_vault::audit::DelegationAuditAction::RequestRejected;
        let fixture = Fixture::start().await;
        let missing = provider_method("cp-missing");

        for (fallback, audited) in [("reject", true), ("passthrough", false)] {
            let surface = surface(missing.clone(), fallback, None, true);
            let (result, events) = crate::audit::producer::capture(fixture.resolve(
                &surface,
                IN_BASE,
                TargetLeg::HttpTarget,
                CallerAssertion::Authenticated,
            ))
            .await;
            assert_eq!(result.unwrap_err(), TargetCredentialError::ProviderNotFound);
            let rejected: Vec<_> = events
                .iter()
                .filter(|event| matches!(event.event, RequestRejected { .. }))
                .collect();
            assert_eq!(rejected.len(), usize::from(audited), "{fallback}: {events:?}");
            if audited {
                match &rejected[0].event {
                    RequestRejected {
                        stage,
                        reason,
                        http_status,
                        rpc_error_code,
                    } => {
                        assert_eq!(*stage, RejectionStage::Forward);
                        assert_eq!(*reason, RejectionReason::TargetAuthUnavailable);
                        assert_eq!(*http_status, 502);
                        assert_eq!(*rpc_error_code, None);
                    }
                    other => panic!("unexpected {other:?}"),
                }
                assert_eq!(
                    rejected[0]
                        .surface_id
                        .as_deref(),
                    Some("surface-1")
                );
                assert_eq!(
                    rejected[0]
                        .trace_id
                        .as_deref(),
                    Some("trace-1")
                );
            }
        }
    }

    #[tokio::test]
    async fn test_credential_never_leaves_the_target_base_path() {
        let fixture = Fixture::start().await;
        fixture
            .secret("STATIC", "static-value", None)
            .await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        let static_secret = json!({"static_secret": {"secret_id": "STATIC", "header_name": "X-Key"}});
        for method in [static_secret, provider_method("cp-cc")] {
            let surface = surface(method, "passthrough", None, true);
            for destination in [
                "https://agent.example/api/../admin",
                "https://agent.example/api/%2e%2e/admin",
                "https://agent.example/other",
            ] {
                let result = fixture
                    .resolve(&surface, destination, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                    .await;
                assert_eq!(
                    result
                        .as_ref()
                        .map(|_| ())
                        .unwrap_err(),
                    &TargetCredentialError::OutsideTargetBase
                );
                let auth = surface
                    .target_auth()
                    .expect("auth");
                assert!(matches!(apply_target_auth_fallback(auth, result), TargetAuthDecision::Reject));
            }
            injected(
                fixture
                    .resolve(&surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                    .await,
            );
        }
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            1
        );
    }

    #[tokio::test]
    async fn test_cross_tenant_provider_or_secret_is_forbidden_whatever_the_fallback() {
        let fixture = Fixture::start().await;
        fixture
            .client_credentials("cp-global", None)
            .await;
        fixture
            .secret("CP_B_ID", "client-a", None)
            .await;
        fixture
            .secret("CP_B_SECRET", "secret-a", None)
            .await;
        fixture
            .provider("cp-b", CredentialProviderType::OAuth2ClientCredentials, Some("tenant-b"), |provider| {
                provider.client_id_secret_ref = Some("CP_B_ID".into());
                provider.client_secret_secret_ref = Some("CP_B_SECRET".into());
            })
            .await;
        let cases = [
            surface(provider_method("cp-global"), "passthrough", Some("tenant-a"), true),
            surface(provider_method("cp-b"), "passthrough", Some("tenant-a"), true),
            surface(provider_method("cp-b"), "passthrough", Some("tenant-b"), true),
        ];
        for surface in &cases {
            let result = fixture
                .resolve(surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                .await;
            assert_eq!(
                result
                    .as_ref()
                    .map(|_| ())
                    .unwrap_err(),
                &TargetCredentialError::Forbidden
            );
            assert!(matches!(
                apply_target_auth_fallback(
                    surface
                        .target_auth()
                        .expect("auth"),
                    result
                ),
                TargetAuthDecision::Reject
            ));
        }
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            0
        );
    }

    #[tokio::test]
    async fn test_static_secret_outside_the_surface_tenant_is_forbidden_whatever_the_fallback() {
        let fixture = Fixture::start().await;
        fixture
            .secret("SHARED", "shared-value", None)
            .await;
        fixture
            .secret("TENANT_B", "tenant-b-value", Some("tenant-b"))
            .await;
        let method = |secret_id: &str| json!({"static_secret": {"secret_id": secret_id, "header_name": "X-Key"}});
        for (secret_id, tenant) in [("TENANT_B", Some("tenant-a")), ("TENANT_B", None), ("SHARED", Some("tenant-a"))] {
            let surface = surface(method(secret_id), "passthrough", tenant, true);
            let result = fixture
                .resolve(&surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                .await;
            assert_eq!(
                result
                    .as_ref()
                    .map(|_| ())
                    .unwrap_err(),
                &TargetCredentialError::Forbidden,
                "{secret_id} on {tenant:?}"
            );
            assert!(matches!(
                apply_target_auth_fallback(
                    surface
                        .target_auth()
                        .expect("auth"),
                    result
                ),
                TargetAuthDecision::Reject
            ));
        }
        for (secret_id, tenant, value) in
            [("SHARED", None, "shared-value"), ("TENANT_B", Some("tenant-b"), "tenant-b-value")]
        {
            let surface = surface(method(secret_id), "reject", tenant, true);
            assert_eq!(
                injected(
                    fixture
                        .resolve(&surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                        .await
                ),
                ("x-key".to_string(), value.to_string())
            );
        }
    }

    #[tokio::test]
    async fn test_unsupported_types_legs_and_injections_fail_closed() {
        let fixture = Fixture::start().await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        fixture
            .provider("cp-code", CredentialProviderType::OAuth2AuthorizationCode, None, |_| {})
            .await;
        let consent = surface(provider_method("cp-code"), "passthrough", None, true);
        let meta = surface(
            json!({"credential_provider": {"credential_provider_id": "cp-cc", "inject_as": {"type": "meta", "field": "token"}}}),
            "passthrough",
            None,
            true,
        );
        let cc = surface(provider_method("cp-cc"), "passthrough", None, true);
        let cases = [
            (&consent, TargetLeg::HttpTarget),
            (&meta, TargetLeg::HttpTarget),
            (&cc, TargetLeg::FabricForward),
            (&cc, TargetLeg::McpProxy),
            (&cc, TargetLeg::TransitPoint),
        ];
        for (surface, leg) in cases {
            let result = fixture
                .resolve(surface, IN_BASE, leg, CallerAssertion::Authenticated)
                .await;
            assert_eq!(
                result
                    .as_ref()
                    .map(|_| ())
                    .unwrap_err(),
                &TargetCredentialError::Unsupported,
                "{leg:?}"
            );
            assert!(matches!(
                apply_target_auth_fallback(
                    surface
                        .target_auth()
                        .expect("auth"),
                    result
                ),
                TargetAuthDecision::Reject
            ));
        }
        let mut cleartext = cc.clone();
        cleartext.target.endpoint = "http://agent.example/api".into();
        assert_eq!(
            fixture
                .resolve(
                    &cleartext,
                    "http://agent.example/api/x",
                    TargetLeg::HttpTarget,
                    CallerAssertion::Authenticated
                )
                .await
                .map(|_| ())
                .unwrap_err(),
            TargetCredentialError::Forbidden
        );
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            0
        );
    }

    #[tokio::test]
    async fn test_missing_provider_and_failed_grant_honour_the_fallback() {
        let fixture = Fixture::start().await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        fixture
            .server
            .set_fault(Endpoint::Token, Fault::NotFound);
        for (method, expected) in [
            (provider_method("missing"), TargetCredentialError::ProviderNotFound),
            (provider_method("cp-cc"), TargetCredentialError::TokenUnavailable),
        ] {
            for (fallback, passes) in [("passthrough", true), ("reject", false)] {
                let surface = surface(method.clone(), fallback, None, true);
                let result = fixture
                    .resolve(&surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                    .await;
                assert_eq!(
                    result
                        .as_ref()
                        .map(|_| ())
                        .unwrap_err(),
                    &expected
                );
                let decision = apply_target_auth_fallback(
                    surface
                        .target_auth()
                        .expect("auth"),
                    result,
                );
                assert_eq!(matches!(decision, TargetAuthDecision::Continue), passes, "{fallback}");
            }
        }
    }

    #[tokio::test]
    async fn test_static_secret_and_credential_lookup_keep_their_behaviour() {
        let fixture = Fixture::start().await;
        fixture
            .secret("STATIC", "static-value", None)
            .await;
        let static_secret = surface(
            json!({"static_secret": {"secret_id": "STATIC", "header_name": "X-Key", "header_format": "Key {value}"}}),
            "reject",
            None,
            false,
        );
        assert_eq!(
            injected(
                fixture
                    .resolve(&static_secret, IN_BASE, TargetLeg::McpProxy, CallerAssertion::Authenticated)
                    .await
            ),
            ("x-key".to_string(), "Key static-value".to_string())
        );
        let missing = surface(
            json!({"static_secret": {"secret_id": "MISSING", "header_name": "X-Key"}}),
            "passthrough",
            None,
            false,
        );
        let result = fixture
            .resolve(&missing, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
            .await;
        assert_eq!(
            result
                .as_ref()
                .map(|_| ())
                .unwrap_err(),
            &TargetCredentialError::SecretUnavailable
        );
        assert!(matches!(
            apply_target_auth_fallback(
                missing
                    .target_auth()
                    .expect("auth"),
                result
            ),
            TargetAuthDecision::Continue
        ));
        let lookup = surface(json!("credential_lookup"), "reject", None, true);
        assert!(matches!(
            fixture
                .resolve(&lookup, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                .await,
            Ok(TargetCredentialOutcome::Withheld(WithheldReason::NotImplemented))
        ));
    }

    #[tokio::test]
    async fn test_provider_resolution_is_audited_without_user_or_token() {
        let fixture = Fixture::start().await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        let surface = surface(provider_method("cp-cc"), "reject", None, true);
        let ((), events) = crate::audit::producer::capture(async {
            for _ in 0..2 {
                injected(
                    fixture
                        .resolve(&surface, IN_BASE, TargetLeg::HttpTarget, CallerAssertion::Authenticated)
                        .await,
                );
            }
            let _ = fixture
                .resolve(
                    &surface,
                    "https://agent.example/elsewhere",
                    TargetLeg::HttpTarget,
                    CallerAssertion::Authenticated,
                )
                .await;
        })
        .await;
        let (rejected, events): (Vec<_>, Vec<_>) = events
            .into_iter()
            .partition(|event| matches!(event.event, DelegationAuditAction::RequestRejected { .. }));
        assert_eq!(rejected.len(), 1, "the refused request is audited once");
        let details: Vec<Option<&str>> = events
            .iter()
            .map(|event| event.detail.as_deref())
            .collect();
        assert_eq!(
            details,
            vec![Some("target_auth_fresh"), Some("target_auth_cached"), Some("target_auth_outside_target_base")]
        );
        for event in &events {
            assert_eq!(event.provider_id.as_deref(), Some("cp-cc"));
            assert_eq!(event.surface_id.as_deref(), Some("surface-1"));
            assert_eq!(event.trace_id.as_deref(), Some("trace-1"));
            assert_eq!(event.user_identity_hash, None);
            assert_eq!(event.agent_did, None);
            assert_eq!(event.token_id, None);
            let serialized = serde_json::to_string(event).expect("event serializes");
            assert!(!serialized.contains("secret-a"));
            assert!(!serialized.contains("Bearer"));
        }
        assert!(matches!(events[0].event, DelegationAuditAction::TokenInjected));
        assert!(matches!(events[2].event, DelegationAuditAction::TokenNotFound));
    }

    #[tokio::test]
    async fn test_provider_header_already_on_the_request_fails_closed_without_a_grant() {
        let fixture = Fixture::start().await;
        fixture
            .client_credentials("cp-cc", None)
            .await;
        let bearer = surface(provider_method("cp-cc"), "passthrough", None, true);
        let authorization = [HeaderName::from_static("authorization")];
        let ((), events) = crate::audit::producer::capture(async {
            let result = fixture
                .resolve_occupied(
                    &bearer,
                    IN_BASE,
                    TargetLeg::HttpTarget,
                    CallerAssertion::Authenticated,
                    &authorization,
                )
                .await;
            assert_eq!(
                result
                    .as_ref()
                    .map(|_| ())
                    .unwrap_err(),
                &TargetCredentialError::HeaderConflict
            );
            assert!(matches!(
                apply_target_auth_fallback(
                    bearer
                        .target_auth()
                        .expect("auth"),
                    result
                ),
                TargetAuthDecision::Reject
            ));
        })
        .await;
        assert_eq!(
            fixture
                .server
                .token_request_count(),
            0
        );
        let (rejected, events): (Vec<_>, Vec<_>) = events
            .into_iter()
            .partition(|event| matches!(event.event, DelegationAuditAction::RequestRejected { .. }));
        assert_eq!(rejected.len(), 1, "the refused request is audited once");
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].event, DelegationAuditAction::TokenNotFound));
        assert_eq!(events[0].detail.as_deref(), Some("target_auth_header_conflict"));

        let custom = surface(
            json!({"credential_provider": {"credential_provider_id": "cp-cc",
                "inject_as": {"type": "custom_header", "name": "X-Agent-Token", "format": "{value}"}}}),
            "reject",
            None,
            true,
        );
        let (name, _) = injected(
            fixture
                .resolve_occupied(
                    &custom,
                    IN_BASE,
                    TargetLeg::HttpTarget,
                    CallerAssertion::Authenticated,
                    &authorization,
                )
                .await,
        );
        assert_eq!(name, "x-agent-token");
        assert_eq!(
            fixture
                .resolve_occupied(
                    &custom,
                    IN_BASE,
                    TargetLeg::HttpTarget,
                    CallerAssertion::Authenticated,
                    &[HeaderName::from_static("x-agent-token")],
                )
                .await
                .map(|_| ())
                .unwrap_err(),
            TargetCredentialError::HeaderConflict
        );
    }

    #[tokio::test]
    async fn test_static_secret_yields_to_a_header_already_on_the_request() {
        let fixture = Fixture::start().await;
        fixture
            .secret("STATIC", "static-value", None)
            .await;
        let static_secret =
            surface(json!({"static_secret": {"secret_id": "STATIC", "header_name": "X-Key"}}), "reject", None, false);
        assert!(matches!(
            fixture
                .resolve_occupied(
                    &static_secret,
                    IN_BASE,
                    TargetLeg::HttpTarget,
                    CallerAssertion::Authenticated,
                    &[HeaderName::from_static("x-key")],
                )
                .await,
            Ok(TargetCredentialOutcome::Withheld(WithheldReason::HeaderAlreadySet))
        ));
        assert_eq!(
            injected(
                fixture
                    .resolve_occupied(
                        &static_secret,
                        IN_BASE,
                        TargetLeg::HttpTarget,
                        CallerAssertion::Authenticated,
                        &[HeaderName::from_static("authorization")],
                    )
                    .await
            ),
            ("x-key".to_string(), "static-value".to_string())
        );
    }

    #[test]
    fn test_target_auth_header_names_follow_the_method_and_injection() {
        let static_secret: TargetAuthMethod =
            serde_json::from_value(json!({"static_secret": {"secret_id": "S", "header_name": "X-Key"}}))
                .expect("method");
        let bearer: TargetAuthMethod = serde_json::from_value(provider_method("cp")).expect("method");
        let custom: TargetAuthMethod = serde_json::from_value(json!({"credential_provider": {
            "credential_provider_id": "cp", "inject_as": {"type": "custom_header", "name": "X-Agent", "format": "{value}"}}}))
        .expect("method");
        assert_eq!(target_auth_header_name(&static_secret), Some("X-Key"));
        assert_eq!(target_auth_header_name(&bearer), Some("Authorization"));
        assert_eq!(target_auth_header_name(&custom), Some("X-Agent"));
        assert_eq!(target_auth_header_name(&TargetAuthMethod::CredentialLookup), None);
        assert_eq!(injection_header_name(&CredentialInjection::Meta { field: "token".into() }), None);
    }

    #[test]
    fn test_target_injection_accepts_only_safe_headers() {
        assert!(validate_target_injection(&CredentialInjection::BearerHeader).is_ok());
        let custom = |name: &str, format: &str| CredentialInjection::CustomHeader {
            name: name.into(),
            format: format.into(),
        };
        assert!(validate_target_injection(&custom("X-Api-Key", "{value}")).is_ok());
        for rejected in [
            custom("Host", "{value}"),
            custom("content-length", "{value}"),
            custom("Transfer-Encoding", "{value}"),
            custom("Connection", "{value}"),
            custom("Bad Header", "{value}"),
            custom("X-Api-Key", "static"),
            CredentialInjection::Meta { field: "token".into() },
        ] {
            assert!(validate_target_injection(&rejected).is_err(), "{rejected:?}");
        }
    }

    #[test]
    fn test_only_https_or_allowlisted_test_targets_may_receive_a_provider_credential() {
        let guard = crate::component_tests::helpers::test_mode::TestModeEnv::with(
            Some("true"),
            Some("http://127.0.0.1:4000,http://127.0.0.1:5000/path"),
            None,
        );
        assert!(permits_credential_provider_target("https://agent.example/api"));
        assert!(permits_credential_provider_target("http://127.0.0.1:4000/api"));
        assert!(!permits_credential_provider_target("http://127.0.0.1:5000/path"));
        assert!(!permits_credential_provider_target("http://agent.example/api"));
        assert!(!permits_credential_provider_target("fabric://gateway/surface"));
        assert!(!permits_credential_provider_target("proxy://mcp-proxy"));
        drop(guard);
        let _production =
            crate::component_tests::helpers::test_mode::TestModeEnv::with(None, Some("http://127.0.0.1:4000"), None);
        assert!(!permits_credential_provider_target("http://127.0.0.1:4000/api"));
    }

    #[test]
    fn test_jwt_bearer_delegation_needs_caller_authentication_an_https_leg_and_the_target_base() {
        let authenticated = surface(provider_method("provider"), "reject", None, true);
        let anonymous = surface(provider_method("provider"), "reject", None, false);
        assert!(permits_jwt_bearer_leg(&authenticated, TARGET, Some(IN_BASE)));
        assert!(permits_jwt_bearer_leg(&authenticated, "https://partner.example/a2a", None));
        assert!(!permits_jwt_bearer_leg(&anonymous, TARGET, Some(IN_BASE)));
        assert!(!permits_jwt_bearer_leg(&anonymous, "https://partner.example/a2a", None));
        assert!(!permits_jwt_bearer_leg(&authenticated, "http://partner.example/a2a", None));
        assert!(!permits_jwt_bearer_leg(&authenticated, "fabric://peer-gateway/peer-surface", None));
        assert!(!permits_jwt_bearer_leg(&authenticated, TARGET, Some("https://agent.example/other")));
        assert!(!permits_jwt_bearer_leg(&authenticated, TARGET, Some("https://elsewhere.example/api")));
    }
}
