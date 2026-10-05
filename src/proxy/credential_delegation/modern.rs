use serde_json::{Value, json};

use super::{ResolvedCredentialInjection, build_injection_headers};
use crate::config::agent_surface::AgentSurface;
use crate::config::types::{CredentialInjection, CredentialRequirement, OutboundCredentialBinding};
use crate::credential_providers::{CredentialProvider, CredentialProviderType, storage::CredentialProviderStorage};
use crate::delegation_vault::{DelegationToken, VaultLookupResult, storage::DelegationVaultStorage};
use crate::jwt_bearer::{JwtVerificationStrategyStorage, models::JwtVerificationStrategy};
use crate::mcp::continuations::{
    ContinuationError,
    consent::input_required_response,
    delegation::{identity_strategy_digest, make_binding, provider_digest, surface_digest},
    protected::{ContinuationBinding, ContinuationKind, ContinuationPayment, ContinuationRoute},
    service::{ClaimedContinuation, ContinuationService, DelegationClaim},
};
use crate::mcp::modern::{RequiredClientCapability, require_client_capability};
use crate::mcp::request_validation::{McpRequestValidationError, ValidatedModernMessage};
use crate::mcp::resource_server::McpResourceServerConfig;
use crate::source_auth::AuthenticatedIdentity;
use crate::sts::mcp_profile::McpIssuerProfile;

pub struct ModernDelegationContext<'context> {
    pub service: &'context ContinuationService,
    pub deployment: &'context str,
    pub ttl_secs: u64,
    pub surface: &'context AgentSurface,
    pub variant_id: Option<String>,
    pub route: ContinuationRoute,
    pub authorization: &'context McpResourceServerConfig,
    pub identity: &'context AuthenticatedIdentity,
    pub agent_did: &'context str,
    pub profile: &'context McpIssuerProfile,
    pub vault: &'context dyn DelegationVaultStorage,
    pub providers: &'context dyn CredentialProviderStorage,
    pub strategies: &'context dyn JwtVerificationStrategyStorage,
    pub secrets: Option<&'context std::sync::Arc<dyn crate::secrets::SecretsStore>>,
    pub provider_http: Option<&'context reqwest::Client>,
}

pub enum ModernDelegationResult {
    Prepared(Box<PreparedDelegation>),
    InputRequired(Value),
}

pub struct PreparedDelegation {
    pub request: ValidatedModernMessage,
    pub injections: Vec<ResolvedCredentialInjection>,
    pub handled_provider_ids: Vec<String>,
    response_binding: Option<ContinuationBinding>,
    claimed: Option<ClaimedContinuation>,
    payment: Option<ContinuationPayment>,
}

pub enum ModernDelegationError {
    Continuation(ContinuationError),
    Protocol(Box<McpRequestValidationError>),
    Unpaid,
}

impl From<ContinuationError> for ModernDelegationError {
    fn from(error: ContinuationError) -> Self {
        Self::Continuation(error)
    }
}

impl From<Box<McpRequestValidationError>> for ModernDelegationError {
    fn from(error: Box<McpRequestValidationError>) -> Self {
        Self::Protocol(error)
    }
}

impl ModernDelegationError {
    pub fn response(
        self,
        request: &ValidatedModernMessage,
    ) -> axum::response::Response {
        use axum::http::StatusCode;
        match self {
            Self::Protocol(error) => (*error).into_response(),
            Self::Unpaid => Self::Continuation(ContinuationError::Unavailable).response(request),
            Self::Continuation(error) => {
                let (status, code, message) = match error {
                    ContinuationError::Unavailable
                    | ContinuationError::KeyUnavailable
                    | ContinuationError::Capacity => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        crate::mcp::errors::error_codes::INTERNAL_ERROR,
                        "MCP credential service unavailable",
                    ),
                    ContinuationError::BindingMismatch | ContinuationError::Denied => {
                        (StatusCode::FORBIDDEN, -32001, "MCP credential authorization denied")
                    }
                    ContinuationError::PrincipalLimit => (
                        StatusCode::TOO_MANY_REQUESTS,
                        crate::mcp::errors::error_codes::INTERNAL_ERROR,
                        "Too many pending MCP credential requests",
                    ),
                    ContinuationError::Conflict => (
                        StatusCode::CONFLICT,
                        crate::mcp::errors::error_codes::INVALID_PARAMS,
                        "MCP continuation already changed or was claimed",
                    ),
                    _ => (
                        StatusCode::BAD_REQUEST,
                        crate::mcp::errors::error_codes::INVALID_PARAMS,
                        "Invalid MCP continuation",
                    ),
                };
                McpRequestValidationError {
                    status,
                    id: request.id.clone(),
                    code,
                    message: message.into(),
                    data: None,
                }
                .into_response()
            }
        }
    }
}

struct SelectedProvider<'binding> {
    config: &'binding OutboundCredentialBinding,
    provider: CredentialProvider,
    strategy: Option<JwtVerificationStrategy>,
    binding: ContinuationBinding,
}

pub async fn prepare_direct(
    state: &crate::state::ProxyState,
    runtime: &crate::mcp::continuations::config::ContinuationRuntime,
    request: &ValidatedModernMessage,
    authorization: Option<&McpResourceServerConfig>,
    identity: Option<&AuthenticatedIdentity>,
    agent_did: Option<&str>,
    route: ContinuationRoute,
    unpaid: bool,
) -> Result<ModernDelegationResult, ModernDelegationError> {
    let strategies = state
        .source_auth_middleware
        .as_ref()
        .ok_or(ContinuationError::Unavailable)?
        .provider_store();
    if state
        .active_variant_alias
        .is_some()
        && state
            .active_variant_id
            .is_none()
    {
        return Err(ContinuationError::BindingMismatch.into());
    }
    let variant_id = state
        .active_variant_id
        .clone();
    ModernDelegationContext {
        service: &runtime.service,
        deployment: &runtime.config.deployment,
        ttl_secs: runtime.config.ttl_secs,
        surface: &state.surface,
        variant_id,
        route,
        authorization: authorization.ok_or(ContinuationError::BindingMismatch)?,
        identity: identity.ok_or(ContinuationError::BindingMismatch)?,
        agent_did: agent_did.ok_or(ContinuationError::BindingMismatch)?,
        profile: state
            .network_config
            .sts
            .mcp_issuer
            .as_ref()
            .ok_or(ContinuationError::Unavailable)?,
        vault: state
            .delegation_vault_store
            .as_deref()
            .ok_or(ContinuationError::Unavailable)?,
        providers: state
            .credential_provider_store
            .as_deref()
            .ok_or(ContinuationError::Unavailable)?,
        strategies: strategies.as_ref(),
        secrets: state.secrets_store.as_ref(),
        provider_http: None,
    }
    .prepare_with_payment(request, now_secs()?, unpaid)
    .await
}

pub async fn prepare_transit(
    state: &crate::state::OutboundProxyState,
    runtime: &crate::mcp::continuations::config::ContinuationRuntime,
    context: &mut crate::proxy::outbound_handler::OutboundPipelineContext,
    request: &ValidatedModernMessage,
) -> Result<ModernDelegationResult, ModernDelegationError> {
    let identity = context
        .authenticated_identity
        .as_ref()
        .ok_or(ContinuationError::BindingMismatch)?;
    let agent_did = match &context.resolved_identity {
        crate::proxy::backend_identity::ProtectedAgentIdentity::Managed { did, .. } => Some(did.as_str()),
        crate::proxy::backend_identity::ProtectedAgentIdentity::Anonymous => None,
    }
    .or_else(|| {
        context
            .transit_token_claims
            .as_ref()
            .and_then(|claims| claims.sub.as_deref())
    })
    .ok_or(ContinuationError::BindingMismatch)?;
    if context
        .variant_resolution_error
        .is_some()
        || (context
            .active_variant_alias
            .is_some()
            && context
                .active_variant_id
                .is_none())
    {
        return Err(ContinuationError::BindingMismatch.into());
    }
    let variant_id = context
        .active_variant_id
        .clone();
    ModernDelegationContext {
        service: &runtime.service,
        deployment: &runtime.config.deployment,
        ttl_secs: runtime.config.ttl_secs,
        surface: &context.surface,
        variant_id,
        route: ContinuationRoute::TransitPoint {
            alias: context
                .virtual_channel
                .alias
                .clone(),
        },
        authorization: context
            .mcp_resource_authorization
            .as_ref()
            .ok_or(ContinuationError::BindingMismatch)?,
        identity,
        agent_did,
        profile: state
            .network_config
            .sts
            .mcp_issuer
            .as_ref()
            .ok_or(ContinuationError::Unavailable)?,
        vault: state
            .delegation_vault_store
            .as_deref()
            .ok_or(ContinuationError::Unavailable)?,
        providers: state
            .credential_provider_store
            .as_deref()
            .ok_or(ContinuationError::Unavailable)?,
        strategies: state
            .consent_identity_strategies
            .as_deref()
            .ok_or(ContinuationError::Unavailable)?,
        secrets: state.secrets_store.as_ref(),
        provider_http: None,
    }
    .prepare(request, now_secs()?)
    .await
}

pub fn now_secs() -> Result<u64, ContinuationError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ContinuationError::Unavailable)
}

fn validate_injection_destinations<'config>(
    injections: impl Iterator<Item = &'config CredentialInjection>
) -> Result<(), ContinuationError> {
    let mut headers = std::collections::HashSet::new();
    let mut fields = std::collections::HashSet::new();
    for injection in injections {
        let name = match injection {
            CredentialInjection::BearerHeader => axum::http::header::AUTHORIZATION,
            CredentialInjection::CustomHeader { name, format } => {
                let name = axum::http::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| ContinuationError::InvalidRecord)?;
                if !format.contains("{value}") {
                    return Err(ContinuationError::InvalidRecord);
                }
                axum::http::HeaderValue::from_str(&format.replace("{value}", "credential"))
                    .map_err(|_| ContinuationError::InvalidRecord)?;
                name
            }
            CredentialInjection::Meta { field } => {
                crate::mcp::meta::validate_operator_key(
                    field,
                    crate::mcp::meta::McpMetadataContext::legacy(Some(
                        crate::config::McpLegacyMetadataOutput::Canonical,
                    )),
                )
                .map_err(|_| ContinuationError::InvalidRecord)?;
                if !fields.insert(field) {
                    return Err(ContinuationError::InvalidRecord);
                }
                continue;
            }
        };
        if !headers.insert(name) {
            return Err(ContinuationError::InvalidRecord);
        }
    }
    Ok(())
}

impl ModernDelegationContext<'_> {
    async fn select<'context>(
        &'context self,
        request: &ValidatedModernMessage,
    ) -> Result<Vec<SelectedProvider<'context>>, ContinuationError> {
        let mut selected = Vec::new();
        for config in &self
            .surface
            .outbound_credentials
        {
            if let CredentialRequirement::Tools(tools) = &config.required_for
                && (request.method != "tools/call"
                    || !request
                        .params
                        .as_ref()
                        .and_then(|params| params.get("name"))
                        .and_then(Value::as_str)
                        .is_some_and(|name| {
                            tools
                                .iter()
                                .any(|tool| tool == name)
                        }))
            {
                continue;
            }
            let provider = self
                .providers
                .get(&config.credential_provider_id)
                .await
                .map_err(|_| ContinuationError::Unavailable)?
                .ok_or(ContinuationError::NotFound)?;
            let strategy = if provider.provider_type == CredentialProviderType::OAuth2AuthorizationCode {
                let strategy_id = provider
                    .consent_identity_strategy_id
                    .as_deref()
                    .ok_or(ContinuationError::InvalidRecord)?;
                Some(
                    self.strategies
                        .get(strategy_id)
                        .await
                        .map_err(|_| ContinuationError::Unavailable)?
                        .ok_or(ContinuationError::NotFound)?,
                )
            } else {
                None
            };
            if !crate::tenancy::can_reference(
                self.surface
                    .tenant_id
                    .as_deref(),
                provider.tenant_id.as_deref(),
            ) || strategy
                .as_ref()
                .is_some_and(|strategy| {
                    !crate::tenancy::can_reference(provider.tenant_id.as_deref(), strategy.tenant_id.as_deref())
                        || crate::sts::mcp_profile::canonical_https_url(&strategy.expected_issuer).is_err()
                })
                || (provider.provider_type != CredentialProviderType::ApiKey
                    && provider
                        .resource
                        .as_deref()
                        .is_none_or(|resource| crate::sts::mcp_profile::canonical_https_url(resource).is_err()))
            {
                return Err(ContinuationError::BindingMismatch);
            }
            let mut scopes = if config.scopes.is_empty() {
                provider
                    .default_scopes
                    .clone()
            } else {
                config.scopes.clone()
            };
            scopes.sort_unstable();
            scopes.dedup();
            let binding = make_binding(
                self.deployment,
                self.surface,
                self.variant_id.clone(),
                self.route.clone(),
                self.authorization,
                &provider,
                scopes,
                self.agent_did,
                self.identity,
                request,
            )?;
            selected.push(SelectedProvider {
                config,
                provider,
                strategy,
                binding,
            });
        }
        validate_injection_destinations(
            selected
                .iter()
                .map(|provider| &provider.config.inject_as),
        )?;
        Ok(selected)
    }

    pub async fn prepare(
        &self,
        request: &ValidatedModernMessage,
        now: u64,
    ) -> Result<ModernDelegationResult, ModernDelegationError> {
        self.prepare_with_payment(request, now, false)
            .await
    }

    pub async fn prepare_with_payment(
        &self,
        request: &ValidatedModernMessage,
        now: u64,
        unpaid: bool,
    ) -> Result<ModernDelegationResult, ModernDelegationError> {
        let normalized = match self.route {
            ContinuationRoute::AccessPoint
            | ContinuationRoute::Fabric { .. }
            | ContinuationRoute::FabricSend { .. } => {
                crate::proxy::handler::surface_payment::request_without_local_payment(self.surface, request)
            }
            _ => request.clone(),
        };
        let request = &normalized;
        let selected = self.select(request).await?;
        let supports_mrtr = request.kind == crate::mcp::request_validation::McpMessageKind::Request
            && matches!(request.method.as_str(), "tools/call" | "prompts/get" | "resources/read");
        let wraps_continuations = supports_mrtr
            && selected
                .iter()
                .any(|provider| provider.strategy.is_some());
        let mut prepared = PreparedDelegation {
            request: request.clone(),
            injections: Vec::new(),
            handled_provider_ids: self
                .surface
                .outbound_credentials
                .iter()
                .map(|binding| {
                    binding
                        .credential_provider_id
                        .clone()
                })
                .collect(),
            response_binding: selected
                .iter()
                .find(|provider| provider.strategy.is_some() && supports_mrtr)
                .map(|provider| provider.binding.clone()),
            claimed: None,
            payment: None,
        };
        if selected.is_empty() {
            return Ok(ModernDelegationResult::Prepared(Box::new(prepared)));
        }
        self.authorization
            .validate()
            .map_err(|_| ContinuationError::InvalidRecord)?;
        if self
            .identity
            .jwt_claims()
            .and_then(|claims| claims.get("iss"))
            .and_then(Value::as_str)
            != Some(self.profile.issuer.as_str())
        {
            return Err(ContinuationError::BindingMismatch.into());
        }
        let mut resumed_credential = None;
        if let Some(encoded) = request
            .params
            .as_ref()
            .and_then(|params| params.get("requestState"))
            .filter(|_| wraps_continuations)
        {
            let encoded = encoded
                .as_str()
                .ok_or(ContinuationError::InvalidState)?;
            let previous = self
                .service
                .request_binding(encoded, request, now)?;
            let provider = selected
                .iter()
                .find(|provider| provider.provider.id == previous.provider_id)
                .ok_or(ContinuationError::BindingMismatch)?;
            let resumed = self
                .service
                .resume(encoded, &provider.binding, request, now)
                .await?;
            if unpaid && !resumed.has_payment() {
                let ready = if resumed.kind() == ContinuationKind::Consent {
                    require_client_capability(request, RequiredClientCapability::ElicitationUrl)?;
                    self.service
                        .delegation_ready(&resumed, self.vault, now)
                        .await?
                } else {
                    matches!(
                        resumed.phase(),
                        crate::mcp::continuations::ContinuationPhase::PendingInput
                            | crate::mcp::continuations::ContinuationPhase::Ready
                    )
                };
                if ready {
                    return Err(ModernDelegationError::Unpaid);
                }
            }
            let claimed = if resumed.kind() == ContinuationKind::Forwarded {
                self.service
                    .claim_forwarded(resumed, now)
                    .await?
            } else {
                require_client_capability(request, RequiredClientCapability::ElicitationUrl)?;
                match self
                    .service
                    .claim_delegation(resumed, self.vault, now)
                    .await?
                {
                    DelegationClaim::Pending(resumed) => {
                        let issued = self
                            .service
                            .retry(*resumed, now)
                            .await?;
                        return Ok(ModernDelegationResult::InputRequired(json!({"jsonrpc": "2.0", "id": request.id,
                            "result": {"resultType": "input_required", "requestState": issued.state}})));
                    }
                    DelegationClaim::Claimed { continuation, credential } => {
                        resumed_credential = Some(*credential);
                        *continuation
                    }
                }
            };
            prepared.request = claimed.restore_upstream_request(request)?;
            prepared.payment = claimed.payment().cloned();
            prepared.claimed = Some(claimed);
        } else if wraps_continuations
            && request
                .params
                .as_ref()
                .and_then(|params| params.get("inputResponses"))
                .is_some()
        {
            return Err(ContinuationError::InvalidInputResponse.into());
        }
        for provider in selected {
            if provider.strategy.is_none() {
                let token = self
                    .service_credential(&provider, now)
                    .await?;
                prepared.add_credential(&provider.config.inject_as, &token)?;
                continue;
            }
            let credential = if resumed_credential
                .as_ref()
                .is_some_and(|credential| credential.credential_provider_id == provider.provider.id)
            {
                resumed_credential.take()
            } else {
                match self
                    .vault
                    .lookup(
                        self.agent_did,
                        &provider
                            .binding
                            .user_identity_hash,
                        &provider.provider.id,
                    )
                    .await
                    .map_err(|_| ContinuationError::Unavailable)?
                {
                    VaultLookupResult::Found(credential) => Some(credential),
                    VaultLookupResult::ExpiredRefreshable(credential)
                        if provider
                            .provider
                            .token_refresh_enabled
                            && verified_credential_identity(&credential, &provider) =>
                    {
                        self.refresh_credential(&provider, credential, now)
                            .await?
                    }
                    _ => None,
                }
            };
            let credential = credential.filter(|credential| verified_credential(credential, &provider, now));
            let Some(credential) = credential else {
                if !supports_mrtr {
                    return Err(ContinuationError::Denied.into());
                }
                require_client_capability(request, RequiredClientCapability::ElicitationUrl)?;
                let origin = url::Url::parse(&self.profile.issuer)
                    .map_err(|_| ContinuationError::InvalidRecord)?
                    .origin()
                    .ascii_serialization();
                let callback = format!(
                    "{origin}{}/{}",
                    crate::delegation_vault::modern_consent::CALLBACK_PATH,
                    provider.provider.id
                );
                let (issued, connect) = self
                    .service
                    .issue_consent_with_payment(
                        &prepared.request,
                        provider.binding,
                        provider_digest(&provider.provider)?,
                        surface_digest(self.surface)?,
                        identity_strategy_digest(
                            provider
                                .strategy
                                .as_ref()
                                .ok_or(ContinuationError::InvalidRecord)?,
                        )?,
                        callback,
                        prepared.payment.clone(),
                        prepared.continuation_ttl(self.ttl_secs, now)?,
                        now,
                    )
                    .await?;
                let mut consent_url = url::Url::parse(&format!(
                    "{origin}{}/{}",
                    crate::delegation_vault::modern_consent::CONNECT_PATH,
                    provider.provider.id
                ))
                .map_err(|_| ContinuationError::InvalidRecord)?;
                consent_url
                    .query_pairs_mut()
                    .append_pair("state", &connect);
                let response =
                    input_required_response(request, &issued, &consent_url, "Authorize access to the provider")?;
                if let Some(claimed) = prepared.claimed {
                    self.service
                        .complete(claimed, now)
                        .await?;
                }
                return Ok(ModernDelegationResult::InputRequired(response));
            };
            prepared.add_credential(&provider.config.inject_as, &credential.access_token)?;
        }
        Ok(ModernDelegationResult::Prepared(Box::new(prepared)))
    }

    async fn service_credential(
        &self,
        selected: &SelectedProvider<'_>,
        now: u64,
    ) -> Result<String, ContinuationError> {
        let provider = &selected.provider;
        let secrets = self
            .secrets
            .ok_or(ContinuationError::Unavailable)?;
        if provider.provider_type == CredentialProviderType::ApiKey {
            let key = crate::delegation_vault::oauth::resolve_api_key(provider, secrets)
                .await
                .map_err(|_| ContinuationError::Unavailable)?;
            if key.is_empty() {
                return Err(ContinuationError::Unavailable);
            }
            return Ok(key);
        }
        let cache_identity = format!("__mcp_client_credentials__:{}", hex::encode(provider_digest(provider)?));
        if let VaultLookupResult::Found(token) = self
            .vault
            .lookup(self.agent_did, &cache_identity, &provider.id)
            .await
            .map_err(|_| ContinuationError::Unavailable)?
            && token.agent_did == self.agent_did
            && token.user_identity_hash == cache_identity
            && token.credential_provider_id == provider.id
            && !token.access_token.is_empty()
            && token
                .token_type
                .eq_ignore_ascii_case("Bearer")
            && token
                .expires_at
                .is_some_and(|expires| u64::try_from(expires.timestamp()).is_ok_and(|expires| expires > now))
            && selected
                .binding
                .scopes
                .iter()
                .all(|scope| token.scopes.contains(scope))
        {
            return Ok(token.access_token);
        }
        let client = match self.provider_http {
            Some(client) => client.clone(),
            None => crate::http_client::external().map_err(|_| ContinuationError::Unavailable)?,
        };
        let response = crate::delegation_vault::oauth::fetch_scoped_client_credentials_token(
            provider,
            &selected.binding.scopes,
            secrets,
            &client,
        )
        .await
        .map_err(|_| ContinuationError::Unavailable)?;
        let scopes = response
            .scope
            .as_deref()
            .map(|scope| {
                scope
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                selected
                    .binding
                    .scopes
                    .clone()
            });
        if scopes.iter().any(|scope| {
            !selected
                .binding
                .scopes
                .contains(scope)
        }) || selected
            .binding
            .scopes
            .iter()
            .any(|scope| !scopes.contains(scope))
        {
            return Err(ContinuationError::Denied);
        }
        let current = self
            .providers
            .get(&provider.id)
            .await
            .map_err(|_| ContinuationError::Unavailable)?
            .ok_or(ContinuationError::BindingMismatch)?;
        if provider_digest(&current)? != provider_digest(provider)? {
            return Err(ContinuationError::BindingMismatch);
        }
        let created = chrono::Utc::now();
        let expires_at = response
            .expires_in
            .and_then(|seconds| created.checked_add_signed(chrono::Duration::seconds(seconds)))
            .ok_or(ContinuationError::InvalidRecord)?;
        let token = self
            .vault
            .store(DelegationToken {
                id: uuid::Uuid::new_v4().to_string(),
                agent_did: self.agent_did.into(),
                user_identity_hash: cache_identity,
                credential_provider_id: provider.id.clone(),
                provider_id: provider.provider_id.clone(),
                access_token: response.access_token,
                refresh_token: None,
                token_type: response.token_type,
                scopes,
                expires_at: Some(expires_at),
                delegation_vc: None,
                consent_identity: None,
                consent_granted_at: created,
                last_used_at: None,
                created_at: created,
                updated_at: created,
            })
            .await
            .map_err(|_| ContinuationError::Unavailable)?;
        Ok(token.access_token)
    }

    async fn refresh_credential(
        &self,
        provider: &SelectedProvider<'_>,
        credential: DelegationToken,
        now: u64,
    ) -> Result<Option<DelegationToken>, ContinuationError> {
        use crate::delegation_vault::storage::RefreshError;
        let claim = match self
            .vault
            .claim_refresh(&credential, now)
            .await
        {
            Ok(claim) => claim,
            Err(RefreshError::Changed) => {
                return match self
                    .vault
                    .lookup(&credential.agent_did, &credential.user_identity_hash, &credential.credential_provider_id)
                    .await
                    .map_err(|_| ContinuationError::Unavailable)?
                {
                    VaultLookupResult::Found(current) if verified_credential(&current, provider, now) => {
                        Ok(Some(current))
                    }
                    _ => Ok(None),
                };
            }
            Err(RefreshError::Uncertain | RefreshError::NotRefreshable) => return Ok(None),
            Err(_) => return Err(ContinuationError::Unavailable),
        };
        let client = match self.provider_http {
            Some(client) => client.clone(),
            None => crate::http_client::external().map_err(|_| ContinuationError::Unavailable)?,
        };
        let Some(response) = crate::delegation_vault::oauth::refresh_scoped_access_token(
            &provider.provider,
            claim
                .token()
                .refresh_token
                .as_deref()
                .ok_or(ContinuationError::InvalidRecord)?,
            &claim.token().scopes,
            self.secrets
                .ok_or(ContinuationError::Unavailable)?,
            &client,
        )
        .await
        .map_err(|_| ContinuationError::Unavailable)?
        else {
            return Ok(None);
        };
        let current_provider = self
            .providers
            .get(&provider.provider.id)
            .await
            .map_err(|_| ContinuationError::Unavailable)?
            .ok_or(ContinuationError::BindingMismatch)?;
        let strategy = provider
            .strategy
            .as_ref()
            .ok_or(ContinuationError::InvalidRecord)?;
        let current_strategy = self
            .strategies
            .get(&strategy.id)
            .await
            .map_err(|_| ContinuationError::Unavailable)?
            .ok_or(ContinuationError::BindingMismatch)?;
        if provider_digest(&current_provider)? != provider_digest(&provider.provider)?
            || identity_strategy_digest(&current_strategy)? != identity_strategy_digest(strategy)?
        {
            return Err(ContinuationError::BindingMismatch);
        }
        self.vault
            .complete_refresh(claim, response, now_secs()?)
            .await
            .map(Some)
            .map_err(|_| ContinuationError::Unavailable)
    }
}

fn verified_credential(
    credential: &DelegationToken,
    provider: &SelectedProvider<'_>,
    now: u64,
) -> bool {
    verified_credential_identity(credential, provider)
        && credential
            .expires_at
            .is_none_or(|expiry| u64::try_from(expiry.timestamp()).is_ok_and(|expiry| expiry > now))
}

fn verified_credential_identity(
    credential: &DelegationToken,
    provider: &SelectedProvider<'_>,
) -> bool {
    credential.agent_did == provider.binding.agent_did
        && credential.user_identity_hash
            == provider
                .binding
                .user_identity_hash
        && credential.credential_provider_id == provider.provider.id
        && !credential
            .access_token
            .is_empty()
        && credential
            .token_type
            .eq_ignore_ascii_case("Bearer")
        && provider
            .binding
            .scopes
            .iter()
            .all(|scope| {
                credential
                    .scopes
                    .contains(scope)
            })
        && credential
            .consent_identity
            .as_ref()
            .is_some_and(|identity| {
                provider_digest(&provider.provider)
                    .and_then(|provider_digest| {
                        identity_strategy_digest(
                            provider
                                .strategy
                                .as_ref()
                                .ok_or(ContinuationError::InvalidRecord)?,
                        )
                        .map(|strategy_digest| {
                            identity.matches(&provider.binding.principal, provider_digest, strategy_digest)
                        })
                    })
                    .unwrap_or(false)
            })
}

impl PreparedDelegation {
    pub fn payment(&self) -> Option<&ContinuationPayment> {
        self.payment.as_ref()
    }

    fn continuation_ttl(
        &self,
        ttl_secs: u64,
        now: u64,
    ) -> Result<u64, ContinuationError> {
        let remaining = self
            .claimed
            .as_ref()
            .map(|claimed| {
                claimed
                    .expires_at()
                    .checked_sub(now)
                    .filter(|ttl| *ttl > 0)
                    .ok_or(ContinuationError::Expired)
            })
            .transpose()?;
        Ok(remaining.map_or(ttl_secs, |remaining| ttl_secs.min(remaining)))
    }

    pub fn record_local_payment(
        &mut self,
        payment: &crate::proxy::handler::surface_payment::SurfacePayment,
        ttl_secs: u64,
        now: u64,
    ) -> Result<(), ContinuationError> {
        if !payment.consumed || self.payment.is_some() {
            return Ok(());
        }
        let expires_at = now
            .checked_add(self.continuation_ttl(ttl_secs, now)?)
            .ok_or(ContinuationError::InvalidRecord)?;
        let evidence = if let Some(context) = &payment.context {
            ContinuationPayment::X402 {
                receipt: context
                    .response_header
                    .clone(),
                verified_at: now,
                expires_at,
            }
        } else {
            ContinuationPayment::Mpp {
                receipt: payment.mpp_receipt.clone(),
                verified_at: now,
                expires_at,
            }
        };
        evidence.validate(now)?;
        self.payment = Some(evidence);
        Ok(())
    }

    fn add_credential(
        &mut self,
        injection: &CredentialInjection,
        credential: &str,
    ) -> Result<(), ContinuationError> {
        if credential.is_empty() || credential.len() > 32 * 1024 || credential.contains(['\r', '\n']) {
            return Err(ContinuationError::InvalidRecord);
        }
        let injections = build_injection_headers(injection, credential);
        for injection in &injections {
            if let ResolvedCredentialInjection::Header { value, .. } = injection {
                axum::http::HeaderValue::from_str(value).map_err(|_| ContinuationError::InvalidRecord)?;
            }
        }
        self.injections
            .extend(injections);
        Ok(())
    }

    pub fn credential_headers(&self) -> Result<axum::http::HeaderMap, ContinuationError> {
        let mut headers = axum::http::HeaderMap::new();
        for injection in &self.injections {
            if let ResolvedCredentialInjection::Header { name, value } = injection {
                let name = axum::http::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| ContinuationError::InvalidRecord)?;
                let mut value =
                    axum::http::HeaderValue::from_str(value).map_err(|_| ContinuationError::InvalidRecord)?;
                value.set_sensitive(true);
                if headers
                    .insert(name, value)
                    .is_some()
                {
                    return Err(ContinuationError::InvalidRecord);
                }
            }
        }
        Ok(headers)
    }

    pub fn inject_body_credentials(
        &self,
        body: &[u8],
    ) -> Result<bytes::Bytes, ContinuationError> {
        let mut body = bytes::Bytes::copy_from_slice(body);
        for injection in &self.injections {
            if let ResolvedCredentialInjection::McpMeta { field, value } = injection {
                body = super::inject_delegated_credential_into_mcp_meta(&body, field, value)
                    .map(bytes::Bytes::from)
                    .map_err(|_| ContinuationError::InvalidRecord)?;
            }
        }
        Ok(body)
    }

    pub fn rewrite_body(
        &self,
        body: &[u8],
    ) -> Result<bytes::Bytes, ContinuationError> {
        if self.claimed.is_none() {
            return Ok(bytes::Bytes::copy_from_slice(body));
        }
        let mut body: Value = serde_json::from_slice(body).map_err(|_| ContinuationError::InvalidRecord)?;
        let params = body
            .get_mut("params")
            .and_then(Value::as_object_mut)
            .ok_or(ContinuationError::InvalidRecord)?;
        for name in ["requestState", "inputResponses"] {
            params.remove(name);
            if let Some(value) = self
                .request
                .params
                .as_ref()
                .and_then(|params| params.get(name))
            {
                params.insert(name.into(), value.clone());
            }
        }
        serde_json::to_vec(&body)
            .map(bytes::Bytes::from)
            .map_err(|_| ContinuationError::InvalidRecord)
    }

    pub async fn finish(
        self,
        service: &ContinuationService,
        response: Value,
        ttl_secs: u64,
        now: u64,
    ) -> Result<Value, ContinuationError> {
        let response = if response
            .get("result")
            .and_then(|result| result.get("resultType"))
            .and_then(Value::as_str)
            == Some("input_required")
        {
            let ttl_secs = self.continuation_ttl(ttl_secs, now)?;
            if let Some(binding) = self.response_binding {
                service
                    .wrap_upstream_response_with_payment(&self.request, binding, response, self.payment, ttl_secs, now)
                    .await?
            } else {
                response
            }
        } else {
            response
        };
        if let Some(claimed) = self.claimed {
            service
                .complete(claimed, now)
                .await?;
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::credential_providers::storage::FileSystemCredentialProviderStore;
    use crate::delegation_vault::storage::FileSystemDelegationVaultStore;
    use crate::jwt_bearer::storage::FileSystemJwtVerificationStrategyStore;
    use crate::mcp::continuations::{
        embedded::EmbeddedContinuations,
        protected::{ContinuationCipher, ContinuationKey},
    };
    use crate::mcp::request_validation::McpMessageKind;

    #[test]
    fn modern_injection_destinations_reject_collisions_and_invalid_configuration() {
        let header = |name: &str| CredentialInjection::CustomHeader {
            name: name.into(),
            format: "{value}".into(),
        };
        let metadata = |field: &str| CredentialInjection::Meta { field: field.into() };
        let distinct = [CredentialInjection::BearerHeader, header("X-Provider-Key"), metadata("X-Provider-Key")];
        assert_eq!(validate_injection_destinations(distinct.iter()), Ok(()));
        for injections in [
            vec![CredentialInjection::BearerHeader, header("aUThorization")],
            vec![header("X-Provider-Key"), header("x-provider-key")],
            vec![metadata("com.example/token"), metadata("com.example/token")],
            vec![metadata("io.modelcontextprotocol/protocolVersion")],
            vec![metadata("invalid field")],
            vec![header("bad\r\nheader")],
            vec![CredentialInjection::CustomHeader {
                name: "X-Key".into(),
                format: "constant".into(),
            }],
            vec![CredentialInjection::CustomHeader {
                name: "X-Key".into(),
                format: "{value}\r\nother".into(),
            }],
        ] {
            assert_eq!(validate_injection_destinations(injections.iter()), Err(ContinuationError::InvalidRecord));
        }
    }

    #[test]
    fn modern_credentials_reject_invalid_bytes_and_duplicate_final_headers() {
        let mut prepared = PreparedDelegation {
            request: ValidatedModernMessage {
                protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
                client_capabilities: None,
                client_info: None,
                method: "tools/list".into(),
                id: Some(json!(1)),
                kind: McpMessageKind::Request,
                params: None,
            },
            injections: Vec::new(),
            handled_provider_ids: Vec::new(),
            response_binding: None,
            claimed: None,
            payment: None,
        };
        let custom = CredentialInjection::CustomHeader {
            name: "X-Provider-Key".into(),
            format: "{value}".into(),
        };
        for credential in ["", "secret\r\nother", "secret\n", "secret\u{0000}", &"x".repeat(32 * 1024 + 1)] {
            assert_eq!(prepared.add_credential(&custom, credential), Err(ContinuationError::InvalidRecord));
            assert!(prepared.injections.is_empty());
        }
        assert_eq!(prepared.add_credential(&custom, "secret"), Ok(()));
        assert_eq!(prepared.add_credential(&CredentialInjection::BearerHeader, "token"), Ok(()));
        let headers = prepared
            .credential_headers()
            .unwrap();
        assert_eq!(headers["x-provider-key"], "secret");
        assert_eq!(headers["authorization"], "Bearer token");
        assert!(headers["authorization"].is_sensitive());
        assert!(headers["x-provider-key"].is_sensitive());
        prepared
            .injections
            .push(ResolvedCredentialInjection::Header {
                name: "x-provider-key".into(),
                value: "replacement".into(),
            });
        assert_eq!(prepared.credential_headers(), Err(ContinuationError::InvalidRecord));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn modern_refresh_is_single_flight_and_revocation_blocks_publication() {
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        struct RefreshProvider {
            requests: tokio::sync::mpsc::Sender<HashMap<String, String>>,
            release: tokio::sync::Semaphore,
            calls: AtomicUsize,
        }

        for revoke in [false, true] {
            let (requests, mut observed) = tokio::sync::mpsc::channel(2);
            let upstream = Arc::new(RefreshProvider {
                requests,
                release: tokio::sync::Semaphore::new(0),
                calls: AtomicUsize::new(0),
            });
            let provider_app = axum::Router::new()
                .fallback(axum::routing::post(
                    |axum::extract::State(provider): axum::extract::State<Arc<RefreshProvider>>,
                     axum::Form(form): axum::Form<HashMap<String, String>>| async move {
                        provider
                            .calls
                            .fetch_add(1, Ordering::SeqCst);
                        provider
                            .requests
                            .send(form)
                            .await
                            .unwrap();
                        provider
                            .release
                            .acquire()
                            .await
                            .unwrap()
                            .forget();
                        axum::Json(json!({"access_token": "renewed-access", "refresh_token": "rotated-refresh",
                        "token_type": "Bearer", "expires_in": 3600, "scope": "read"}))
                    },
                ))
                .with_state(upstream.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let client = reqwest::Client::builder()
                .no_proxy()
                .proxy(reqwest::Proxy::http(format!("http://{}", listener.local_addr().unwrap())).unwrap())
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(async move {
                axum::serve(listener, provider_app)
                    .await
                    .unwrap();
            });
            let directory = tempfile::tempdir().unwrap();
            let providers = FileSystemCredentialProviderStore::new(
                directory
                    .path()
                    .join("providers"),
            )
            .await
            .unwrap();
            let strategies = FileSystemJwtVerificationStrategyStore::new(
                directory
                    .path()
                    .join("strategies"),
            )
            .await
            .unwrap();
            let vault = FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap();
            let other_vault = FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                .await
                .unwrap();
            let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
                crate::secrets::FilesystemSecretsStore::new(
                    directory
                        .path()
                        .join("secrets")
                        .to_str()
                        .unwrap(),
                )
                .unwrap(),
            );
            for (secret_id, value) in [("client-id", "refresh-client"), ("client-secret", "fixture-secret")] {
                secrets
                    .create(crate::secrets::CreateSecretRequest {
                        tenant_id: None,
                        name: secret_id.into(),
                        secret_id: secret_id.into(),
                        description: None,
                        value: value.into(),
                        secret_type: "General".into(),
                        tags: vec![],
                    })
                    .await
                    .unwrap();
            }
            let strategy = strategies
                .create(
                    crate::sts::handlers::gateway_self_trust_strategy(
                        "https://identity.example/",
                        &json!({"keys": []}),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let provider = providers.create(serde_json::from_value(json!({
                "id": "provider", "name": "Provider", "provider_id": "provider", "resource": "https://provider.example/api",
                "token_endpoint": "http://192.0.2.1/token", "client_id_secret_ref": "client-id", "client_secret_secret_ref": "client-secret",
                "consent_identity_strategy_id": strategy.id, "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
            })).unwrap()).await.unwrap();
            let surface: AgentSurface = serde_json::from_value(json!({
                "surface_id": "surface", "name": "Surface", "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
                "target": {"endpoint": "https://provider.example/api"}, "outbound_credentials": [{"credential_provider_id": "provider", "scopes": ["read"]}]
            })).unwrap();
            let authorization = McpResourceServerConfig {
                resource: "https://gateway.example/mcp".into(),
                scopes: vec!["read".into()],
            };
            let profile = McpIssuerProfile {
                issuer: "https://gateway.example/oauth2/mcp".into(),
            };
            let caller = AuthenticatedIdentity::JwtBearer {
                subject: "user".into(),
                claims: json!({"iss": profile.issuer, "sub": "user", "scope": "read"}),
            };
            let now = now_secs().unwrap();
            let service = ContinuationService::new(
                ContinuationCipher::new(
                    "deployment".into(),
                    "key".into(),
                    vec![ContinuationKey::new("key".into(), [7; 32], now - 1, now + 3600, now + 4500).unwrap()],
                )
                .unwrap(),
                Arc::new(EmbeddedContinuations::new(32).unwrap()),
            );
            let context = ModernDelegationContext {
                service: &service,
                deployment: "deployment",
                ttl_secs: 300,
                surface: &surface,
                variant_id: None,
                route: ContinuationRoute::AccessPoint,
                authorization: &authorization,
                identity: &caller,
                agent_did: "did:web:agent.example",
                profile: &profile,
                vault: &vault,
                providers: &providers,
                strategies: &strategies,
                secrets: Some(&secrets),
                provider_http: Some(&client),
            };
            let other_context = ModernDelegationContext {
                vault: &other_vault,
                route: context.route.clone(),
                variant_id: context.variant_id.clone(),
                ..context
            };
            let request = ValidatedModernMessage {
                protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
                client_capabilities: None,
                client_info: None,
                method: "tools/call".into(),
                id: Some(json!(1)),
                kind: McpMessageKind::Request,
                params: Some(json!({"name": "read", "arguments": {"value": 1}})),
            };
            let selected = context
                .select(&request)
                .await
                .unwrap();
            let token = vault.store(serde_json::from_value(json!({
                "id": "refresh-token", "agent_did": context.agent_did, "user_identity_hash": selected[0].binding.user_identity_hash,
                "credential_provider_id": "provider", "provider_id": "provider", "access_token": "expired-access", "refresh_token": "original-refresh",
                "scopes": ["read"], "expires_at": chrono::DateTime::from_timestamp(now as i64 - 60, 0),
                "consent_granted_at": "2026-09-01T00:00:00Z", "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z",
                "consent_identity": {"principal": selected[0].binding.principal,
                    "provider_digest": provider_digest(&provider).unwrap(), "strategy_digest": identity_strategy_digest(&strategy).unwrap()}
            })).unwrap()).await.unwrap();
            let (result, ()) = tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(context.prepare(&request, now), async {
                    let form = observed.recv().await.unwrap();
                    assert_eq!(form["grant_type"], "refresh_token");
                    assert_eq!(form["refresh_token"], "original-refresh");
                    assert_eq!(
                        form["resource"],
                        provider
                            .resource
                            .as_deref()
                            .unwrap()
                    );
                    assert_eq!(form["scope"], "read");
                    assert_eq!(form["client_id"], "refresh-client");
                    assert!(matches!(
                        other_context
                            .prepare(&request, now)
                            .await,
                        Err(ModernDelegationError::Continuation(ContinuationError::Unavailable))
                    ));
                    if revoke {
                        other_vault
                            .delete(&token.id)
                            .await
                            .unwrap();
                    }
                    upstream
                        .release
                        .add_permits(1);
                })
            })
            .await
            .unwrap();
            assert_eq!(
                upstream
                    .calls
                    .load(Ordering::SeqCst),
                1
            );
            if revoke {
                assert!(matches!(result, Err(ModernDelegationError::Continuation(ContinuationError::Unavailable))));
                assert!(
                    vault
                        .get(&token.id)
                        .await
                        .unwrap()
                        .is_none()
                );
            } else {
                let ModernDelegationResult::Prepared(prepared) = result.ok().unwrap() else {
                    panic!("refresh must prepare the request");
                };
                assert_eq!(
                    prepared
                        .credential_headers()
                        .unwrap()["authorization"],
                    "Bearer renewed-access"
                );
                let stored = other_vault
                    .get(&token.id)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    stored
                        .refresh_token
                        .as_deref(),
                    Some("rotated-refresh")
                );
                assert_eq!(stored.consent_identity, token.consent_identity);
                assert!(stored.updated_at > token.updated_at);
                assert!(matches!(
                    other_context
                        .prepare(&request, now_secs().unwrap())
                        .await,
                    Ok(ModernDelegationResult::Prepared(_))
                ));
                assert_eq!(
                    upstream
                        .calls
                        .load(Ordering::SeqCst),
                    1
                );
                let mut configured = provider.clone();
                configured.provider_type = CredentialProviderType::ApiKey;
                configured.consent_identity_strategy_id = None;
                configured.api_key_secret_ref = Some("client-secret".into());
                providers
                    .update(configured.clone())
                    .await
                    .unwrap();
                let ModernDelegationResult::Prepared(prepared) = context
                    .prepare(&request, now_secs().unwrap())
                    .await
                    .ok()
                    .unwrap()
                else {
                    panic!("API key credentials must not request browser consent");
                };
                assert_eq!(prepared.handled_provider_ids, vec!["provider"]);
                assert_eq!(
                    prepared
                        .credential_headers()
                        .unwrap()["authorization"],
                    "Bearer fixture-secret"
                );
                assert!(
                    prepared
                        .response_binding
                        .is_none()
                );
                configured.api_key_secret_ref = Some("missing-secret".into());
                providers
                    .update(configured.clone())
                    .await
                    .unwrap();
                assert!(matches!(
                    context
                        .prepare(&request, now_secs().unwrap())
                        .await,
                    Err(ModernDelegationError::Continuation(ContinuationError::Unavailable))
                ));
                assert_eq!(
                    upstream
                        .calls
                        .load(Ordering::SeqCst),
                    1
                );

                configured.provider_type = CredentialProviderType::OAuth2ClientCredentials;
                configured.api_key_secret_ref = None;
                providers
                    .update(configured.clone())
                    .await
                    .unwrap();
                for resource in ["https://provider.example/api", "https://provider.example/other"] {
                    configured.resource = Some(resource.into());
                    providers
                        .update(configured.clone())
                        .await
                        .unwrap();
                    upstream
                        .release
                        .add_permits(1);
                    let ModernDelegationResult::Prepared(prepared) =
                        tokio::time::timeout(Duration::from_secs(5), context.prepare(&request, now_secs().unwrap()))
                            .await
                            .unwrap()
                            .ok()
                            .unwrap()
                    else {
                        panic!("machine credentials must not request browser consent");
                    };
                    assert_eq!(
                        prepared
                            .credential_headers()
                            .unwrap()["authorization"],
                        "Bearer renewed-access"
                    );
                    assert_eq!(prepared.handled_provider_ids, vec!["provider"]);
                    assert!(
                        prepared
                            .response_binding
                            .is_none()
                    );
                    let form = observed.recv().await.unwrap();
                    assert_eq!(form["grant_type"], "client_credentials");
                    assert_eq!(form["resource"], resource);
                    assert_eq!(form["scope"], "read");
                    assert!(!form.contains_key("refresh_token"));
                    let count = upstream
                        .calls
                        .load(Ordering::SeqCst);
                    assert!(matches!(
                        other_context
                            .prepare(&request, now_secs().unwrap())
                            .await,
                        Ok(ModernDelegationResult::Prepared(_))
                    ));
                    assert_eq!(
                        upstream
                            .calls
                            .load(Ordering::SeqCst),
                        count
                    );
                }
                assert_eq!(
                    upstream
                        .calls
                        .load(Ordering::SeqCst),
                    3
                );
            }
            tasks.shutdown().await;
        }
    }

    #[tokio::test]
    async fn preparation_requires_request_capability_and_rejects_unverified_credentials_and_replays() {
        let directory = tempfile::tempdir().unwrap();
        let providers = FileSystemCredentialProviderStore::new(
            directory
                .path()
                .join("providers"),
        )
        .await
        .unwrap();
        let strategies = FileSystemJwtVerificationStrategyStore::new(
            directory
                .path()
                .join("strategies"),
        )
        .await
        .unwrap();
        let vault = FileSystemDelegationVaultStore::new(directory.path().join("vault"))
            .await
            .unwrap();
        let strategy = strategies
            .create(
                crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &json!({"keys": []}))
                    .unwrap(),
            )
            .await
            .unwrap();
        let provider: CredentialProvider = serde_json::from_value(json!({
            "id": "provider", "name": "Provider", "provider_id": "provider", "resource": "https://provider.example/api",
            "consent_identity_strategy_id": strategy.id, "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        })).unwrap();
        providers
            .create(provider)
            .await
            .unwrap();
        let surface: AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface", "name": "Surface", "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://provider.example/api"}, "outbound_credentials": [{"credential_provider_id": "provider", "scopes": ["read"]}]
        })).unwrap();
        let authorization = McpResourceServerConfig {
            resource: "https://gateway.example/mcp".into(),
            scopes: vec!["read".into()],
        };
        let profile = McpIssuerProfile {
            issuer: "https://gateway.example/oauth2/mcp".into(),
        };
        let caller = AuthenticatedIdentity::JwtBearer {
            subject: "user".into(),
            claims: json!({"iss": profile.issuer, "sub": "user", "scope": "read"}),
        };
        let service = ContinuationService::new(
            ContinuationCipher::new(
                "deployment".into(),
                "key".into(),
                vec![ContinuationKey::new("key".into(), [7; 32], 1, 1000, 1900).unwrap()],
            )
            .unwrap(),
            Arc::new(EmbeddedContinuations::new(32).unwrap()),
        );
        let context = ModernDelegationContext {
            service: &service,
            deployment: "deployment",
            ttl_secs: 100,
            surface: &surface,
            variant_id: None,
            route: ContinuationRoute::AccessPoint,
            authorization: &authorization,
            identity: &caller,
            agent_did: "did:web:agent.example",
            profile: &profile,
            vault: &vault,
            providers: &providers,
            strategies: &strategies,
            secrets: None,
            provider_http: None,
        };
        let mut request = ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: None,
            client_info: None,
            method: "tools/call".into(),
            id: Some(json!(1)),
            kind: McpMessageKind::Request,
            params: Some(json!({"name": "read", "arguments": {"value": 1}})),
        };
        assert!(matches!(context.prepare(&request, 10).await, Err(ModernDelegationError::Protocol(error))
            if error.code == crate::mcp::errors::error_codes::MISSING_REQUIRED_CLIENT_CAPABILITY));
        let mut listing = request.clone();
        listing.method = "tools/list".into();
        assert!(matches!(
            context
                .prepare(&listing, 10)
                .await,
            Err(ModernDelegationError::Continuation(ContinuationError::Denied))
        ));
        let listing_binding = context
            .select(&listing)
            .await
            .unwrap()
            .remove(0)
            .binding;
        assert!(matches!(
            service
                .issue(&listing, listing_binding, 100, 10)
                .await,
            Err(ContinuationError::BindingMismatch)
        ));
        let selected = context
            .select(&request)
            .await
            .unwrap();
        let token: DelegationToken = serde_json::from_value(json!({
            "id": "legacy-token", "agent_did": context.agent_did,
            "user_identity_hash": selected[0].binding.user_identity_hash,
            "credential_provider_id": "provider", "provider_id": "provider",
            "access_token": "legacy-credential", "scopes": ["read"],
            "consent_granted_at": "2026-09-01T00:00:00Z",
            "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        }))
        .unwrap();
        vault
            .store(token)
            .await
            .unwrap();
        request.client_capabilities = Some(json!({"elicitation": {"url": {}}}));
        let ModernDelegationResult::InputRequired(response) = context
            .prepare(&request, 10)
            .await
            .ok()
            .unwrap()
        else {
            panic!("legacy vault token must require consent");
        };
        assert_eq!(response["result"]["resultType"], "input_required");
        let encoded = response["result"]["requestState"]
            .as_str()
            .unwrap();
        request.id = Some(json!(2));
        request
            .params
            .as_mut()
            .unwrap()["requestState"] = json!(encoded);
        let ModernDelegationResult::InputRequired(pending) = context
            .prepare(&request, 11)
            .await
            .ok()
            .unwrap()
        else {
            panic!("consent must remain pending");
        };
        assert!(
            pending["result"]
                .get("inputRequests")
                .is_none()
        );
        assert_ne!(pending["result"]["requestState"], encoded);
        assert!(matches!(
            context
                .prepare(&request, 11)
                .await,
            Err(ModernDelegationError::Continuation(ContinuationError::Conflict))
        ));
        request.id = Some(json!(3));
        request
            .params
            .as_mut()
            .unwrap()["requestState"] = pending["result"]["requestState"].clone();
        request
            .params
            .as_mut()
            .unwrap()["arguments"]["value"] = json!(2);
        assert!(matches!(
            context
                .prepare(&request, 12)
                .await,
            Err(ModernDelegationError::Continuation(ContinuationError::BindingMismatch))
        ));
        request
            .params
            .as_mut()
            .unwrap()["requestState"] = json!("opaque-upstream-token");
        assert!(matches!(
            context
                .prepare(&request, 12)
                .await,
            Err(ModernDelegationError::Continuation(ContinuationError::InvalidState))
        ));
        let mut credential = vault
            .get("legacy-token")
            .await
            .unwrap()
            .unwrap();
        credential.consent_identity = Some(
            serde_json::from_value(json!({
                "principal": selected[0].binding.principal,
                "provider_digest": provider_digest(&selected[0].provider).unwrap(),
                "strategy_digest": identity_strategy_digest(selected[0].strategy.as_ref().unwrap()).unwrap()
            }))
            .unwrap(),
        );
        vault
            .update(credential)
            .await
            .unwrap();
        for method in ["tools/list", "server/discover", "subscriptions/listen", "tasks/get"] {
            listing.method = method.into();
            let ModernDelegationResult::Prepared(listing_prepared) = context
                .prepare(&listing, 12)
                .await
                .ok()
                .unwrap()
            else {
                panic!("verified credentials must be reusable without elicitation for {method}");
            };
            assert_eq!(listing_prepared.handled_provider_ids, vec!["provider"]);
            assert!(
                listing_prepared
                    .response_binding
                    .is_none()
            );
            assert_eq!(
                listing_prepared
                    .credential_headers()
                    .unwrap()["authorization"],
                "Bearer legacy-credential"
            );
        }
        request.id = Some(json!(4));
        request.params = Some(json!({"name": "read", "arguments": {"value": 1}}));
        let ModernDelegationResult::Prepared(prepared) = context
            .prepare(&request, 12)
            .await
            .ok()
            .unwrap()
        else {
            panic!("verified credentials must prepare the request");
        };
        assert_eq!(prepared.handled_provider_ids, vec!["provider"]);
        assert_eq!(
            prepared.injections,
            vec![ResolvedCredentialInjection::Header {
                name: "Authorization".into(),
                value: "Bearer legacy-credential".into()
            }]
        );
        let response = prepared
            .finish(
                &service,
                json!({"jsonrpc": "2.0", "id": request.id,
                "result": {"resultType": "input_required", "requestState": "opaque-upstream-state",
                    "inputRequests": {"upstream-input": {"method": "elicitation/create", "params": {
                        "mode": "url", "url": "https://upstream.example/consent", "message": "Authorize"
                    }}}}}),
                100,
                12,
            )
            .await
            .unwrap();
        request.id = Some(json!(5));
        request
            .params
            .as_mut()
            .unwrap()["requestState"] = response["result"]["requestState"].clone();
        request
            .params
            .as_mut()
            .unwrap()["inputResponses"] =
            json!({"upstream-input": {"action": "accept"}, "ignored": {"action": "cancel"}});
        for _attempt in 0..2 {
            assert!(matches!(
                context
                    .prepare_with_payment(&request, 13, true)
                    .await,
                Err(ModernDelegationError::Unpaid)
            ));
        }
        let ModernDelegationResult::Prepared(prepared) = context
            .prepare(&request, 13)
            .await
            .ok()
            .unwrap()
        else {
            panic!("upstream retry must reuse verified credentials");
        };
        assert_eq!(
            prepared
                .request
                .params
                .as_ref()
                .unwrap()["requestState"],
            "opaque-upstream-state"
        );
        assert_eq!(
            prepared
                .request
                .params
                .as_ref()
                .unwrap()["inputResponses"],
            json!({"upstream-input": {"action": "accept"}})
        );
        let enriched = json!({"jsonrpc": "2.0", "id": request.id, "method": request.method,
            "params": {"name": "read", "arguments": {"value": 1}, "requestState": "gateway-state",
                "_meta": {"com.example/verified": true}}});
        let restored: Value = serde_json::from_slice(
            &prepared
                .rewrite_body(&serde_json::to_vec(&enriched).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(restored["params"]["_meta"], enriched["params"]["_meta"]);
        assert_eq!(restored["params"]["requestState"], "opaque-upstream-state");
        assert_eq!(restored["params"]["arguments"], enriched["params"]["arguments"]);
        assert!(matches!(
            context
                .prepare(&request, 13)
                .await,
            Err(ModernDelegationError::Continuation(ContinuationError::Conflict))
        ));
        let complete = json!({"jsonrpc": "2.0", "id": request.id, "result": {"resultType": "complete", "content": []}});
        assert_eq!(
            prepared
                .finish(&service, complete.clone(), 100, 13)
                .await
                .unwrap(),
            complete
        );
        let mut filtered_surface = surface.clone();
        filtered_surface.outbound_credentials[0].required_for = CredentialRequirement::Tools(vec!["other".into()]);
        filtered_surface.outbound_credentials[0].credential_provider_id = "unneeded-provider".into();
        let filtered = ModernDelegationContext {
            surface: &filtered_surface,
            route: context.route.clone(),
            variant_id: context.variant_id.clone(),
            ..context
        };
        let ModernDelegationResult::Prepared(prepared) = filtered
            .prepare(&listing, 14)
            .await
            .ok()
            .unwrap()
        else {
            panic!("nonmatching credentials must not request consent");
        };
        assert_eq!(prepared.handled_provider_ids, vec!["unneeded-provider"]);
        assert!(prepared.injections.is_empty());
        assert!(
            prepared
                .response_binding
                .is_none()
        );
        let body =
            bytes::Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":"task"}}"#);
        assert_eq!(
            prepared
                .rewrite_body(&body)
                .unwrap(),
            body
        );
    }
}
