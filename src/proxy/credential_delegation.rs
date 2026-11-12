//! Credential delegation integration for the proxy pipeline.
//!
//! Intercepts outbound requests on channels with `outbound_credentials` bindings,
//! looks up the delegation vault for cached tokens, refreshes expired tokens, and
//! injects credentials into upstream requests — or signals consent_required to the caller.

use crate::config::types::{
    ConsentMode, CredentialInjection, CredentialRequirement, ElicitFallback, OutboundCredentialBinding,
};
use crate::credential_providers::CredentialProvider;
use crate::credential_providers::CredentialProviderType;
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::delegation_vault::audit::{self, AuditCallerContext, DelegationAuditAction};
use crate::delegation_vault::consent_confirmation::ConsentCaller;
use crate::delegation_vault::service_token::{
    self, Freshness, IssuedToken, ServiceTokenContext, ServiceTokenError, ServiceTokenKey,
};
use crate::delegation_vault::{DelegationToken, VaultLookupResult, oauth, storage::DelegationVaultStorage};
use crate::secrets::SecretsStore;
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod modern;

/// Rich context attached to every audit event emitted during delegation resolution
#[derive(Debug, Clone, Default)]
pub struct DelegationAuditContext {
    /// Caller identity context (from source auth)
    pub caller: Option<AuditCallerContext>,
    /// Human-readable channel name
    pub channel_name: Option<String>,
    /// Target endpoint the channel proxies to
    pub target_endpoint: Option<String>,
    /// Protocol of the channel (a2a, mcp, etc.)
    pub protocol: Option<String>,
    /// MCP tool name (if this is an MCP tool call)
    pub mcp_tool_name: Option<String>,
    /// Actual DID identity of the agent (from identity store lookup)
    pub agent_identity_did: Option<String>,
    /// Identity binding VP (signed proof of user→agent binding)
    pub vp_jwt: Option<String>,
    /// MCP Streamable HTTP session id (`Mcp-Session-Id`). Required to run
    /// `ConsentMode::Elicit` — without it we cannot route an
    /// `elicitation/create` request to the client.
    pub mcp_session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedCredentialInjection {
    Header { name: String, value: String },
    McpMeta { field: String, value: String },
}

/// A vault record created by modern consent carries the `(issuer, subject)` it
/// was consented by. The legacy lookup key is `(agent_did, user_identity_hash,
/// provider_id)` and `user_identity_hash` has no issuer in it, so without this
/// check a caller whose `sub` collides with another issuer's user would be
/// handed that user's token. Records with no consent identity are legacy and
/// keep their existing behaviour.
fn consent_identity_permits(
    consent_identity: Option<&crate::delegation_vault::modern_consent::identity::VerifiedConsentIdentity>,
    consent_principal: Option<&str>,
) -> bool {
    match consent_identity {
        None => true,
        Some(consent) => consent_principal.is_some_and(|principal| consent.matches_principal(principal)),
    }
}

/// What a caller is told when a delegated credential its request needs cannot be
/// resolved; why is logged.
pub(crate) const DELEGATION_UNAVAILABLE: &str = "Delegated credentials unavailable";

/// What a request that arrived over Fabric is told when its caller has no grant
/// yet: consent is never started through a partner, so the person connects to
/// this gateway directly first.
pub(crate) const PARTNER_CONSENT_UNAVAILABLE: &str =
    "Delegated credentials need the user's consent, which cannot be given through a partner";

/// The fixed reason [`PARTNER_CONSENT_UNAVAILABLE`] is answered with.
pub(crate) const PARTNER_CONSENT_UNAVAILABLE_REASON: &str = "consent_not_available_for_partners";

/// A problem JSON refusing a request's delegated credentials with `status`,
/// `detail` and the fixed `reason` the caller is told.
pub(crate) fn refusal_problem(
    status: axum::http::StatusCode,
    detail: &str,
    reason: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        status,
        [
            (axum::http::header::CONTENT_TYPE, "application/problem+json"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        serde_json::json!({
            "type": "https://affinidi.com/atg/errors/delegated-credentials-refused",
            "title": "Delegated Credentials Refused",
            "status": status.as_u16(),
            "detail": detail,
            "reason": reason,
        })
        .to_string(),
    )
        .into_response()
}

/// The `503` body refusing a request whose delegated credential cannot be
/// resolved, with its content type: on an MCP surface a JSON-RPC error answering
/// the request's id, otherwise a problem JSON.
pub(crate) fn delegation_unavailable_body(
    mcp: bool,
    request_body: &[u8],
) -> (&'static str, String) {
    if mcp {
        let id = serde_json::from_slice::<serde_json::Value>(request_body)
            .ok()
            .and_then(|body| body.get("id").cloned())
            .unwrap_or(serde_json::Value::Null);
        return (
            "application/json",
            crate::mcp::errors::create_mcp_error_envelope(
                Some(id),
                crate::mcp::errors::error_codes::INTERNAL_ERROR,
                DELEGATION_UNAVAILABLE,
                None,
            )
            .to_string(),
        );
    }
    (
        "application/problem+json",
        serde_json::json!({
            "type": "https://affinidi.com/atg/errors/delegated-credentials-unavailable",
            "title": "Delegated Credentials Unavailable",
            "status": 503,
            "detail": DELEGATION_UNAVAILABLE,
        })
        .to_string(),
    )
}

/// Result of a delegation credential lookup for a single binding
pub enum DelegationLookupResult {
    /// Token found — inject these credentials into the upstream request
    Inject(Vec<ResolvedCredentialInjection>),
    /// User has not yet consented — return consent_required to caller
    ConsentRequired { authorization_url: String, provider_name: String, scopes: Vec<String> },
    /// Binding doesn't apply to this request (e.g. tool filter)
    NotApplicable,
    /// The credential cannot be supplied, including an elicitation the user
    /// declined, cancelled or left unanswered — refuse the request without
    /// contacting the target
    Unavailable,
}

/// Snake-case action taken by the gateway for a single delegation binding.
///
/// Surfaced into the workload-binding VP under the `delegationAction` field
/// when workload-binding attestation is enabled, so verifiers can see exactly
/// what the gateway did (injected a token, returned consent_required, the user
/// declined an elicitation, …) per binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationActionOutcome {
    /// A token was injected into the upstream request (cached, freshly
    /// minted client-credentials, API key, or post-elicitation refresh).
    TokenInjected,
    /// An existing token was refreshed before injection.
    TokenRefreshed,
    /// The caller will receive `consent_required` so the user can authorize.
    ConsentRequired,
    /// The MCP client accepted the elicitation prompt but the OAuth
    /// callback has not yet populated the vault. The caller still receives
    /// a `consent_required` payload so the client can resume.
    ElicitationAcceptedPending,
    /// The user explicitly declined the elicitation prompt.
    ElicitationDeclined,
    /// The user cancelled the elicitation prompt.
    ElicitationCancelled,
    /// The elicitation prompt timed out before the user replied.
    ElicitationTimedOut,
    /// The MCP client did not advertise the `elicitation` capability and
    /// the binding's fallback is `fail`.
    ElicitationUnsupported,
    /// Binding skipped because it does not apply to this request (tool filter).
    NotApplicable,
    /// The binding's credential provider cannot be used: it was deleted, its
    /// record cannot be read, or no authorization URL can be built from it. The
    /// request is refused rather than forwarded without the credential.
    ProviderUnavailable,
    /// The stored credential was consented by a different principal than the
    /// one making this request, so it was not released.
    ConsentIdentityMismatch,
    /// Token refresh attempt failed — caller is asked to re-consent.
    RefreshFailed,
    /// The vault lookup itself raised an error.
    LookupError,
    /// API-key secret resolution failed.
    ApiKeyResolutionFailed,
    /// OAuth2 client-credentials token fetch failed.
    ClientCredentialsFailed,
    /// OAuth2 JWT Bearer grant failed.
    JwtBearerFailed,
    /// OAuth2 client-credentials token fetch with a JWT client assertion failed.
    ClientCredentialsJwtAuthFailed,
}

/// Audit-grade per-binding record produced by the resolver.
///
/// Carries enough metadata to (a) drive the proxy pipeline (via `result`)
/// and (b) populate the `delegationAction` array inside the workload-binding
/// VP when attestation is enabled, without re-deriving the outcome from the
/// result variant.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DelegationAction {
    /// Local `credential_provider_id` from the binding.
    #[serde(rename = "providerId")]
    pub provider_id: String,
    /// Display name when the provider could be loaded.
    #[serde(rename = "providerName", skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// Snake-case outcome (see [`DelegationActionOutcome`]).
    pub outcome: DelegationActionOutcome,
    /// Optional free-text detail (e.g. `provider_not_found`, `elicit_id=…`,
    /// underlying error message). Never contains a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A resolved binding — the recorded action plus the concrete result the
/// proxy pipeline must act on (inject / consent_required / skip).
pub struct DelegationResolution {
    pub action: DelegationAction,
    pub result: DelegationLookupResult,
}

/// Build the `delegationAction` JSON array surfaced inside the
/// workload-binding VP when attestation is enabled. Returns `None` when no
/// bindings were evaluated, so the field is omitted entirely for channels
/// without `outbound_credentials`.
pub fn delegation_actions_value(resolutions: &[DelegationResolution]) -> Option<serde_json::Value> {
    if resolutions.is_empty() {
        return None;
    }
    let actions: Vec<&DelegationAction> = resolutions
        .iter()
        .map(|r| &r.action)
        .collect();
    serde_json::to_value(actions).ok()
}

impl DelegationResolution {
    fn new(
        binding: &OutboundCredentialBinding,
        provider_name: Option<&str>,
        outcome: DelegationActionOutcome,
        detail: Option<String>,
        result: DelegationLookupResult,
    ) -> Self {
        Self {
            action: DelegationAction {
                provider_id: binding
                    .credential_provider_id
                    .clone(),
                provider_name: provider_name.map(String::from),
                outcome,
                detail,
            },
            result,
        }
    }
}

/// Appended to an audit detail when the provider's token endpoint breaks the https rule and
/// is let through only because `credential_policy.token_endpoint_https` is `warn`.
const INSECURE_TOKEN_ENDPOINT_DETAIL: &str = " insecure_token_endpoint";

/// The grant name used in audit details, and the outcome recorded when it fails.
fn service_grant(provider_type: &CredentialProviderType) -> (&'static str, DelegationActionOutcome) {
    match provider_type {
        CredentialProviderType::OAuth2ClientCredentials => {
            ("client_credentials", DelegationActionOutcome::ClientCredentialsFailed)
        }
        CredentialProviderType::OAuth2JwtBearer => ("jwt_bearer", DelegationActionOutcome::JwtBearerFailed),
        CredentialProviderType::OAuth2ClientCredentialsJwtAuth => {
            ("client_credentials_jwt_auth", DelegationActionOutcome::ClientCredentialsJwtAuthFailed)
        }
        CredentialProviderType::ApiKey => ("api_key", DelegationActionOutcome::ApiKeyResolutionFailed),
        CredentialProviderType::OAuth2AuthorizationCode => {
            ("authorization_code", DelegationActionOutcome::ProviderUnavailable)
        }
    }
}

/// Enrich an audit event with delegation-specific context
fn enrich_audit_event(
    evt: &mut audit::DelegationAuditEvent,
    ctx: Option<&DelegationAuditContext>,
    binding: &OutboundCredentialBinding,
    provider_name: Option<&str>,
) {
    if let Some(ctx) = ctx {
        evt.caller = ctx.caller.clone();
        evt.channel_name = ctx.channel_name.clone();
        evt.target_endpoint = ctx.target_endpoint.clone();
        evt.protocol = ctx.protocol.clone();
        evt.mcp_tool_name = ctx.mcp_tool_name.clone();
        evt.agent_identity_did = ctx.agent_identity_did.clone();
        evt.vp_jwt = ctx.vp_jwt.clone();
    }
    if let Some(name) = provider_name {
        evt.provider_name = Some(name.to_string());
    }
    evt.inject_as = Some(format!("{:?}", binding.inject_as).to_lowercase());
}

/// Check all outbound credential bindings for a channel and return injection headers
/// or a consent_required signal.
///
/// # Arguments
/// * `bindings` — the channel's `outbound_credentials` configuration
/// * `user_identity_hash` — SHA-256 hash of the caller's identity claim
/// * `agent_did` — the DID of the agent this channel proxies to
/// * `channel_id` — for logging
/// * `surface_tenancy` — the tenant of the surface the bindings belong to; a provider of
///   another tenant, or an appliance-wide one that sends the gateway's own credential once
///   `tenant_credential_isolation` is `enforce`, is refused with `provider_forbidden`
/// * `mcp_tool_name` — if this is an MCP tool call, the tool name (for `Tools` requirement filter)
/// * `vault_store` — delegation vault storage
/// * `provider_store` — credential provider storage
/// * `secrets_store` — secrets storage (for refreshing tokens)
/// * `gateway_base_url` — for building OAuth authorization URLs
/// * `via_fabric` — true when this resolution is happening on the GW2 side of a fabric request
/// * `caller` — who a consent link is minted for: an Access Point caller, with the
///   strategies that may confirm it at its identity provider, or a Transit or Fabric
///   request, whose consent is not confirmed
/// * `consent_principal` — the authenticated caller's consent principal, when this request
///   carries one. A vault record created by modern consent is released only to its own
///   principal; callers that cannot establish one (Transit, fabric) pass `None` and are
///   refused such records.
pub async fn resolve_delegation_credentials(
    bindings: &[OutboundCredentialBinding],
    user_identity_hash: &str,
    agent_did: &str,
    channel_id: &str,
    surface_tenancy: crate::tenancy::SurfaceTenancy<'_>,
    mcp_tool_name: Option<&str>,
    vault_store: &Arc<dyn DelegationVaultStorage>,
    provider_store: &Arc<dyn CredentialProviderStorage>,
    secrets_store: &Arc<dyn SecretsStore>,
    gateway_base_url: &str,
    via_fabric: bool,
    caller: ConsentCaller<'_>,
    audit_ctx: Option<&DelegationAuditContext>,
    consent_principal: Option<&str>,
) -> Vec<DelegationResolution> {
    let consent_caller = ConsentLinkFor {
        caller,
        tenant_id: surface_tenancy.tenant_id,
    };
    let mut results: Vec<DelegationResolution> = Vec::new();
    let surface_variant = crate::observability::policy_audit::current_request_variant();
    let surface_variant = surface_variant.as_deref();

    for binding in bindings {
        if binding.is_external() {
            warn!(
                target: "credential_delegation",
                surface_variant,
                provider_id = %binding.credential_provider_id,
                "A consent_mode external binding is served only by its grant by binding - refusing the request"
            );
            results.push(DelegationResolution::new(
                binding,
                None,
                DelegationActionOutcome::ProviderUnavailable,
                Some("binding_needs_external_consent".to_string()),
                DelegationLookupResult::Unavailable,
            ));
            continue;
        }
        // Check if this binding applies to the current request
        match &binding.required_for {
            CredentialRequirement::All => {}
            CredentialRequirement::Tools(tools) => {
                if let Some(tool) = mcp_tool_name {
                    if !tools
                        .iter()
                        .any(|t| t == tool)
                    {
                        results.push(DelegationResolution::new(
                            binding,
                            None,
                            DelegationActionOutcome::NotApplicable,
                            Some("tool_filter".to_string()),
                            DelegationLookupResult::NotApplicable,
                        ));
                        continue;
                    }
                } else {
                    // Not a tool call, and this binding is only for specific tools
                    results.push(DelegationResolution::new(
                        binding,
                        None,
                        DelegationActionOutcome::NotApplicable,
                        Some("tool_filter_no_tool".to_string()),
                        DelegationLookupResult::NotApplicable,
                    ));
                    continue;
                }
            }
        }

        // Load provider to determine type
        let provider = match provider_store
            .get(&binding.credential_provider_id)
            .await
        {
            Ok(Some(p)) => p,
            Ok(None) => {
                warn!(
                    target: "credential_delegation",
                    surface_variant,
                    provider_id = %binding.credential_provider_id,
                    "Credential provider not found - refusing the request"
                );
                results.push(DelegationResolution::new(
                    binding,
                    None,
                    DelegationActionOutcome::ProviderUnavailable,
                    Some("provider_not_found".to_string()),
                    DelegationLookupResult::Unavailable,
                ));
                continue;
            }
            Err(e) => {
                warn!(
                    target: "credential_delegation",
                    surface_variant,
                    provider_id = %binding.credential_provider_id,
                    error = %e,
                    "Failed to load credential provider - refusing the request"
                );
                results.push(DelegationResolution::new(
                    binding,
                    None,
                    DelegationActionOutcome::ProviderUnavailable,
                    Some(format!("provider_load_error: {}", e)),
                    DelegationLookupResult::Unavailable,
                ));
                continue;
            }
        };

        if provider.is_external_consent() {
            warn!(
                target: "credential_delegation",
                surface_variant,
                provider_id = %binding.credential_provider_id,
                "A provider with an issuer serves only consent_mode external bindings - refusing the request"
            );
            results.push(DelegationResolution::new(
                binding,
                Some(&provider.name),
                DelegationActionOutcome::ProviderUnavailable,
                Some("provider_needs_external_consent".to_string()),
                DelegationLookupResult::Unavailable,
            ));
            continue;
        }
        if !provider.usable_by(surface_tenancy) {
            warn!(
                target: "credential_delegation",
                surface_variant,
                surface_id = %channel_id,
                provider_id = %binding.credential_provider_id,
                "Credential provider is outside the surface's tenant - refusing the request"
            );
            results.push(DelegationResolution::new(
                binding,
                Some(&provider.name),
                DelegationActionOutcome::ProviderUnavailable,
                Some("provider_forbidden".to_string()),
                DelegationLookupResult::Unavailable,
            ));
            continue;
        }
        let appliance_wide = provider.breaks_tenant_isolation_for(surface_tenancy.tenant_id);
        if appliance_wide {
            warn!(
                target: "credential_delegation",
                surface_variant,
                surface_id = %channel_id,
                provider_id = %binding.credential_provider_id,
                tenant_id = ?surface_tenancy.tenant_id,
                "Credential provider is appliance-wide on a tenant surface; refused once tenant_credential_isolation is enforce"
            );
        }
        let with_note = |detail: String| {
            if appliance_wide {
                format!("{detail} (appliance_wide_credential)")
            } else {
                detail
            }
        };

        // Route by provider type
        match &provider.provider_type {
            CredentialProviderType::ApiKey => {
                // Direct secret resolution — no OAuth, no vault
                match oauth::resolve_api_key(&provider, secrets_store, oauth::isolation_mode()).await {
                    Ok(api_key) => {
                        debug!(
                            target: "credential_delegation",
                            surface_variant,
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            "API key resolved — injecting into upstream request"
                        );
                        audit::emit("token_injected", || {
                            let mut evt = audit::audit_event(
                                DelegationAuditAction::TokenInjected,
                                Some(agent_did),
                                Some(user_identity_hash),
                                Some(&binding.credential_provider_id),
                                Some(channel_id),
                            );
                            evt.via_fabric = via_fabric;
                            evt.detail = Some(with_note("api_key".to_string()));
                            enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                            evt
                        });
                        let headers = build_injection_headers(&binding.inject_as, &api_key);
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::TokenInjected,
                            Some(with_note("api_key".to_string())),
                            DelegationLookupResult::Inject(headers),
                        ));
                    }
                    Err(e) => {
                        warn!(
                            target: "credential_delegation",
                            surface_variant,
                            provider_id = %binding.credential_provider_id,
                            error = %e,
                            "Failed to resolve API key - refusing the request"
                        );
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::ApiKeyResolutionFailed,
                            Some(e.to_string()),
                            DelegationLookupResult::Unavailable,
                        ));
                    }
                }
                continue;
            }
            CredentialProviderType::OAuth2ClientCredentials
            | CredentialProviderType::OAuth2JwtBearer
            | CredentialProviderType::OAuth2ClientCredentialsJwtAuth => {
                let m2m_user_hash = "__client_credentials__";
                let (grant, failure) = service_grant(&provider.provider_type);
                let effective_scopes = if binding.scopes.is_empty() {
                    &provider.default_scopes
                } else {
                    &binding.scopes
                };
                let context = ServiceTokenContext {
                    secrets: secrets_store,
                    providers: provider_store.as_ref(),
                    vault: vault_store.as_ref(),
                    egress: None,
                };
                let key = ServiceTokenKey {
                    agent_did,
                    purpose: m2m_user_hash,
                };
                let acquired = service_token::acquire(&provider, effective_scopes, &context, key, Utc::now())
                    .await
                    .and_then(|mut token| match token.issued.take() {
                        Some(IssuedToken {
                            id,
                            freshness,
                            insecure_endpoint,
                            ..
                        }) => Ok((id, freshness, insecure_endpoint, token)),
                        // Unreachable: acquire issues a vault token for each of these OAuth types.
                        None => Err(ServiceTokenError::Unsupported),
                    });
                match acquired {
                    Ok((token_id, freshness, insecure_endpoint, token)) => {
                        let detail = with_note(format!(
                            "{grant}_{}{}",
                            freshness.as_str(),
                            if insecure_endpoint {
                                INSECURE_TOKEN_ENDPOINT_DETAIL
                            } else {
                                ""
                            }
                        ));
                        debug!(
                            target: "credential_delegation",
                            surface_variant,
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            detail = %detail,
                            "Service token resolved — injecting into upstream request"
                        );
                        if freshness != Freshness::Fresh
                            && let Err(e) = vault_store
                                .mark_used(&token_id)
                                .await
                        {
                            warn!(
                                target: "credential_delegation",
                                surface_variant,
                                token_id = %token_id,
                                error = %e,
                                "Failed to mark service token as used"
                            );
                        }
                        audit::emit("token_injected", || {
                            let mut evt = audit::audit_event(
                                DelegationAuditAction::TokenInjected,
                                Some(agent_did),
                                Some(m2m_user_hash),
                                Some(&binding.credential_provider_id),
                                Some(channel_id),
                            );
                            evt.token_id = Some(token_id.clone());
                            evt.via_fabric = via_fabric;
                            evt.detail = Some(detail.clone());
                            enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                            evt
                        });
                        let headers = build_injection_headers(&binding.inject_as, token.value());
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::TokenInjected,
                            Some(detail),
                            DelegationLookupResult::Inject(headers),
                        ));
                    }
                    Err(error) => {
                        warn!(
                            target: "credential_delegation",
                            surface_variant,
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            grant = %grant,
                            %error,
                            "Service token unavailable - refusing the request"
                        );
                        let detail = error.to_string();
                        audit::emit("token_not_found", || {
                            let mut evt = audit::audit_event(
                                DelegationAuditAction::TokenNotFound,
                                Some(agent_did),
                                Some(m2m_user_hash),
                                Some(&binding.credential_provider_id),
                                Some(channel_id),
                            );
                            evt.via_fabric = via_fabric;
                            evt.detail = Some(detail.clone());
                            enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                            evt
                        });
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            failure,
                            Some(detail),
                            DelegationLookupResult::Unavailable,
                        ));
                    }
                }
                continue;
            }
            CredentialProviderType::OAuth2AuthorizationCode => {
                // Existing 3LO flow — vault lookup → inject or consent
            }
        }

        // ── OAuth2 Authorization Code flow (3LO) ────────────────────────

        // Lookup in vault — trait signature: lookup(agent_did, user_identity_hash, provider_id)
        let lookup_result = vault_store
            .lookup(agent_did, user_identity_hash, &binding.credential_provider_id)
            .await;

        let consented_by_other_principal = match &lookup_result {
            Ok(VaultLookupResult::Found(token)) | Ok(VaultLookupResult::ExpiredRefreshable(token)) => {
                !consent_identity_permits(
                    token
                        .consent_identity
                        .as_ref(),
                    consent_principal,
                )
            }
            _ => false,
        };
        if consented_by_other_principal {
            warn!(
                target: "credential_delegation",
                surface_variant,
                surface_id = %channel_id,
                provider_id = %binding.credential_provider_id,
                user_hash = %user_identity_hash,
                "Delegation token was consented by a different principal — refusing to release"
            );
            results.push(DelegationResolution::new(
                binding,
                None,
                DelegationActionOutcome::ConsentIdentityMismatch,
                Some("consent_identity_mismatch".to_string()),
                DelegationLookupResult::Unavailable,
            ));
            continue;
        }

        match lookup_result {
            Ok(VaultLookupResult::Found(token)) => {
                debug!(
                    target: "credential_delegation",
                    surface_variant,
                    surface_id = %channel_id,
                    provider_id = %binding.credential_provider_id,
                    user_hash = %user_identity_hash,
                    "Delegation token found — injecting into upstream request"
                );

                // Mark as used
                if let Err(e) = vault_store
                    .mark_used(&token.id)
                    .await
                {
                    warn!(
                        target: "credential_delegation",
                        surface_variant,
                        token_id = %token.id,
                        error = %e,
                        "Failed to mark delegation token as used"
                    );
                }

                // Audit: token injected
                audit::emit("token_injected", || {
                    let mut evt = audit::audit_event(
                        DelegationAuditAction::TokenInjected,
                        Some(agent_did),
                        Some(user_identity_hash),
                        Some(&binding.credential_provider_id),
                        Some(channel_id),
                    );
                    evt.token_id = Some(token.id.clone());
                    evt.via_fabric = via_fabric;
                    enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                    evt
                });

                let headers = build_injection_headers(&binding.inject_as, &token.access_token);
                results.push(DelegationResolution::new(
                    binding,
                    Some(&provider.name),
                    DelegationActionOutcome::TokenInjected,
                    None,
                    DelegationLookupResult::Inject(headers),
                ));
            }
            Ok(VaultLookupResult::ExpiredRefreshable(mut token)) => {
                if token
                    .consent_identity
                    .is_some()
                {
                    match refresh_verified_credential(
                        vault_store.as_ref(),
                        provider_store.as_ref(),
                        &provider,
                        &token,
                        secrets_store,
                    )
                    .await
                    {
                        Ok(refreshed) => {
                            for action in [DelegationAuditAction::TokenRefreshed, DelegationAuditAction::TokenInjected]
                            {
                                audit::emit(audit::action_category(&action), || {
                                    let mut event = audit::audit_event(
                                        action,
                                        Some(agent_did),
                                        Some(user_identity_hash),
                                        Some(&binding.credential_provider_id),
                                        Some(channel_id),
                                    );
                                    event.token_id = Some(refreshed.id.clone());
                                    event.via_fabric = via_fabric;
                                    enrich_audit_event(&mut event, audit_ctx, binding, Some(&provider.name));
                                    event
                                });
                            }
                            results.push(DelegationResolution::new(
                                binding,
                                Some(&provider.name),
                                DelegationActionOutcome::TokenRefreshed,
                                None,
                                DelegationLookupResult::Inject(build_injection_headers(
                                    &binding.inject_as,
                                    &refreshed.access_token,
                                )),
                            ));
                        }
                        Err(()) => results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::RefreshFailed,
                            Some("coordinated_refresh_unavailable".into()),
                            DelegationLookupResult::Unavailable,
                        )),
                    }
                    continue;
                }
                info!(
                    target: "credential_delegation",
                    surface_variant,
                    surface_id = %channel_id,
                    provider_id = %binding.credential_provider_id,
                    user_hash = %user_identity_hash,
                    "Delegation token expired — attempting refresh"
                );

                // Load provider to get token endpoint
                match provider_store
                    .get(&binding.credential_provider_id)
                    .await
                {
                    Ok(Some(provider)) => {
                        match oauth::refresh_access_token(
                            &provider,
                            token
                                .refresh_token
                                .as_deref()
                                .unwrap_or_default(),
                            secrets_store,
                        )
                        .await
                        {
                            Ok(oauth::RefreshedToken {
                                response: refreshed,
                                insecure_endpoint,
                            }) => {
                                token.access_token = refreshed.access_token.clone();
                                if let Some(rt) = &refreshed.refresh_token {
                                    token.refresh_token = Some(rt.clone());
                                }
                                if let Some(exp) = refreshed.expires_in {
                                    token.expires_at = Some(chrono::Utc::now() + chrono::Duration::seconds(exp));
                                }
                                token = match vault_store
                                    .update(token)
                                    .await
                                {
                                    Ok(stored) => stored,
                                    Err(error) => {
                                        results.push(refreshed_token_rejected(
                                            binding,
                                            &provider,
                                            &error,
                                            surface_variant,
                                        ));
                                        continue;
                                    }
                                };
                                if let Err(e) = vault_store
                                    .mark_used(&token.id)
                                    .await
                                {
                                    warn!(
                                        target: "credential_delegation",
                                        surface_variant,
                                        token_id = %token.id,
                                        error = %e,
                                        "Failed to mark refreshed token as used"
                                    );
                                }

                                info!(
                                    target: "credential_delegation",
                                    surface_variant,
                                    surface_id = %channel_id,
                                    provider_id = %binding.credential_provider_id,
                                    "Token refreshed successfully"
                                );

                                let refresh_detail = if insecure_endpoint {
                                    INSECURE_TOKEN_ENDPOINT_DETAIL
                                } else {
                                    ""
                                };

                                // Audit: token refreshed
                                audit::emit("token_refreshed", || {
                                    let mut evt = audit::audit_event(
                                        DelegationAuditAction::TokenRefreshed,
                                        Some(agent_did),
                                        Some(user_identity_hash),
                                        Some(&binding.credential_provider_id),
                                        Some(channel_id),
                                    );
                                    evt.token_id = Some(token.id.clone());
                                    evt.via_fabric = via_fabric;
                                    enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                                    evt
                                });

                                audit::emit("token_injected", || {
                                    let mut evt = audit::audit_event(
                                        DelegationAuditAction::TokenInjected,
                                        Some(agent_did),
                                        Some(user_identity_hash),
                                        Some(&binding.credential_provider_id),
                                        Some(channel_id),
                                    );
                                    evt.token_id = Some(token.id.clone());
                                    evt.via_fabric = via_fabric;
                                    evt.detail = Some(format!("after_refresh{refresh_detail}"));
                                    enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                                    evt
                                });

                                let headers = build_injection_headers(&binding.inject_as, &token.access_token);
                                results.push(DelegationResolution::new(
                                    binding,
                                    Some(&provider.name),
                                    DelegationActionOutcome::TokenRefreshed,
                                    None,
                                    DelegationLookupResult::Inject(headers),
                                ));
                            }
                            Err(e) => {
                                warn!(
                                    target: "credential_delegation",
                                    surface_variant,
                                    surface_id = %channel_id,
                                    provider_id = %binding.credential_provider_id,
                                    error = %e,
                                    "Token refresh failed — requesting new consent"
                                );
                                // Audit: refresh failed
                                audit::emit("refresh_failed", || {
                                    let mut evt = audit::audit_event(
                                        DelegationAuditAction::RefreshFailed,
                                        Some(agent_did),
                                        Some(user_identity_hash),
                                        Some(&binding.credential_provider_id),
                                        Some(channel_id),
                                    );
                                    evt.via_fabric = via_fabric;
                                    evt.detail = Some(e.to_string());
                                    enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                                    evt
                                });
                                // Fall through to consent_required
                                let cr = build_consent_required(
                                    binding,
                                    user_identity_hash,
                                    agent_did,
                                    channel_id,
                                    consent_caller,
                                    provider_store,
                                    secrets_store,
                                    gateway_base_url,
                                    surface_variant,
                                )
                                .await;
                                results.push(DelegationResolution::new(
                                    binding,
                                    Some(&provider.name),
                                    DelegationActionOutcome::RefreshFailed,
                                    Some(e.to_string()),
                                    cr,
                                ));
                            }
                        }
                    }
                    _ => {
                        warn!(
                            target: "credential_delegation",
                            surface_variant,
                            provider_id = %binding.credential_provider_id,
                            "Cannot refresh — credential provider not found"
                        );
                        let cr = build_consent_required(
                            binding,
                            user_identity_hash,
                            agent_did,
                            channel_id,
                            consent_caller,
                            provider_store,
                            secrets_store,
                            gateway_base_url,
                            surface_variant,
                        )
                        .await;
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::RefreshFailed,
                            Some("provider_missing_for_refresh".to_string()),
                            cr,
                        ));
                    }
                }
            }
            Ok(VaultLookupResult::ExpiredNoRefresh(_)) | Ok(VaultLookupResult::NotFound) => {
                info!(
                    target: "credential_delegation",
                    surface_variant,
                    surface_id = %channel_id,
                    provider_id = %binding.credential_provider_id,
                    user_hash = %user_identity_hash,
                    "No valid delegation token — consent required"
                );
                // NOTE: the per-binding `ConsentRequired` audit event used to
                // be emitted here, but that produced two audit rows per
                // request (one per binding + one request-level summary from
                // the handler). The request-level summary already carries the
                // signed workload-binding VP with a `delegationAction` array
                // that lists every binding's outcome when attestation is
                // enabled, so the per-binding row was redundant and confusing
                // in the UI. Provider-level
                // terminal events (`ElicitationSent`, `ElicitationDeclined`,
                // etc.) are still emitted below where applicable.

                // Branch on consent mode. For `Elicit`, drive an MCP
                // `elicitation/create` round-trip and (on Accept) park
                // until the OAuth callback wakes us via the vault
                // notifier. All other modes fall through to the legacy
                // consent_required path.
                let elicit_result = if binding.consent_mode == ConsentMode::Elicit {
                    try_elicit_flow(
                        binding,
                        user_identity_hash,
                        agent_did,
                        channel_id,
                        consent_caller,
                        &provider,
                        vault_store,
                        provider_store,
                        secrets_store,
                        gateway_base_url,
                        audit_ctx,
                        via_fabric,
                        surface_variant,
                    )
                    .await
                } else {
                    None
                };

                if let Some((outcome, detail, r)) = elicit_result {
                    results.push(DelegationResolution::new(binding, Some(&provider.name), outcome, detail, r));
                } else {
                    let cr = build_consent_required(
                        binding,
                        user_identity_hash,
                        agent_did,
                        channel_id,
                        consent_caller,
                        provider_store,
                        secrets_store,
                        gateway_base_url,
                        surface_variant,
                    )
                    .await;
                    let outcome = match cr {
                        DelegationLookupResult::ConsentRequired { .. } => DelegationActionOutcome::ConsentRequired,
                        _ => DelegationActionOutcome::ProviderUnavailable,
                    };
                    results.push(DelegationResolution::new(binding, Some(&provider.name), outcome, None, cr));
                }
            }
            Err(e) => {
                warn!(
                    target: "credential_delegation",
                    surface_variant,
                    surface_id = %channel_id,
                    provider_id = %binding.credential_provider_id,
                    error = %e,
                    "Vault lookup failed"
                );
                // Audit: token not found (vault error)
                audit::emit("token_not_found", || {
                    let mut evt = audit::audit_event(
                        DelegationAuditAction::TokenNotFound,
                        Some(agent_did),
                        Some(user_identity_hash),
                        Some(&binding.credential_provider_id),
                        Some(channel_id),
                    );
                    evt.via_fabric = via_fabric;
                    evt.detail = Some(e.to_string());
                    enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                    evt
                });
                results.push(DelegationResolution::new(
                    binding,
                    Some(&provider.name),
                    DelegationActionOutcome::LookupError,
                    Some(e.to_string()),
                    DelegationLookupResult::Unavailable,
                ));
            }
        }
    }

    results
}

async fn refresh_verified_credential(
    vault: &dyn DelegationVaultStorage,
    providers: &dyn CredentialProviderStorage,
    provider: &CredentialProvider,
    token: &DelegationToken,
    secrets: &Arc<dyn SecretsStore>,
) -> Result<DelegationToken, ()> {
    if !provider.token_refresh_enabled {
        return Err(());
    }
    let now = modern::now_secs().map_err(|_| ())?;
    let claim = vault
        .claim_refresh(token, now)
        .await
        .map_err(|_| ())?;
    let response = oauth::refresh_scoped_access_token(
        provider,
        claim
            .token()
            .refresh_token
            .as_deref()
            .ok_or(())?,
        &claim.token().scopes,
        secrets,
        &oauth::TokenEgress::from_environment(),
    )
    .await
    .map_err(|_| ())?
    .ok_or(())?;
    let current_provider = providers
        .get(&provider.id)
        .await
        .map_err(|_| ())?
        .ok_or(())?;
    if crate::mcp::continuations::delegation::provider_digest(&current_provider).map_err(|_| ())?
        != crate::mcp::continuations::delegation::provider_digest(provider).map_err(|_| ())?
    {
        return Err(());
    }
    vault
        .complete_refresh(claim, response, modern::now_secs().map_err(|_| ())?)
        .await
        .map_err(|_| ())
}

/// The resolution for a refreshed token the vault would not store, e.g. because
/// the authorization was revoked while the provider was refreshing it.
fn refreshed_token_rejected(
    binding: &OutboundCredentialBinding,
    provider: &CredentialProvider,
    error: &anyhow::Error,
    surface_variant: Option<&str>,
) -> DelegationResolution {
    warn!(
        target: "credential_delegation",
        surface_variant,
        provider_id = %binding.credential_provider_id,
        error = %error,
        "Refreshed credential rejected by vault"
    );
    DelegationResolution::new(
        binding,
        Some(&provider.name),
        DelegationActionOutcome::RefreshFailed,
        Some("vault_update_rejected".to_string()),
        DelegationLookupResult::Unavailable,
    )
}

pub(crate) fn build_injection_headers(
    inject_as: &CredentialInjection,
    access_token: &str,
) -> Vec<ResolvedCredentialInjection> {
    match inject_as {
        CredentialInjection::BearerHeader => {
            vec![ResolvedCredentialInjection::Header {
                name: "Authorization".to_string(),
                value: format!("Bearer {}", access_token),
            }]
        }
        CredentialInjection::CustomHeader { name, format } => {
            let value = format.replace("{value}", access_token);
            let clean_name: String = name
                .chars()
                .filter(|c| *c != '\r' && *c != '\n')
                .collect();
            let clean_value: String = value
                .chars()
                .filter(|c| *c != '\r' && *c != '\n')
                .collect();
            vec![ResolvedCredentialInjection::Header {
                name: clean_name,
                value: clean_value,
            }]
        }
        CredentialInjection::Meta { field } => {
            vec![ResolvedCredentialInjection::McpMeta {
                field: field.clone(),
                value: access_token.to_string(),
            }]
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum McpMetaInjectionError {
    #[error("MCP request body is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("MCP request body root must be a JSON object")]
    RootNotObject,
    #[error("{0}")]
    InvalidMetadata(#[from] crate::mcp::meta::McpMetadataError),
}

pub fn inject_delegated_credential_into_mcp_meta(
    body_bytes: &[u8],
    field: &str,
    access_token: &str,
) -> Result<Vec<u8>, McpMetaInjectionError> {
    let mut json_body = serde_json::from_slice::<serde_json::Value>(body_bytes)?;
    if !json_body.is_object() {
        return Err(McpMetaInjectionError::RootNotObject);
    }
    let context = crate::mcp::meta::McpMetadataContext::default();
    crate::mcp::meta::validate_operator_key(field, context)?;
    let metadata = crate::mcp::meta::metadata_mut(&mut json_body, context, crate::mcp::meta::McpMetaTarget::Params)?;
    metadata.insert(field.to_string(), serde_json::Value::String(access_token.to_string()));
    Ok(serde_json::to_vec(&json_body)?)
}

/// Who a consent link is minted for, and the tenant of the surface their
/// `user_identity_hash` was computed under.
#[derive(Clone, Copy)]
struct ConsentLinkFor<'a> {
    caller: ConsentCaller<'a>,
    tenant_id: Option<&'a str>,
}

/// Build a consent_required response for a binding that has no valid token
#[allow(clippy::too_many_arguments)]
async fn build_consent_required(
    binding: &OutboundCredentialBinding,
    user_identity_hash: &str,
    agent_did: &str,
    channel_id: &str,
    caller: ConsentLinkFor<'_>,
    provider_store: &Arc<dyn CredentialProviderStorage>,
    secrets_store: &Arc<dyn SecretsStore>,
    gateway_base_url: &str,
    surface_variant: Option<&str>,
) -> DelegationLookupResult {
    match provider_store
        .get(&binding.credential_provider_id)
        .await
    {
        Ok(Some(provider)) => {
            let scopes = if binding.scopes.is_empty() {
                provider
                    .default_scopes
                    .clone()
            } else {
                binding.scopes.clone()
            };

            match oauth::mint_consent_link(
                &provider,
                agent_did,
                user_identity_hash,
                channel_id,
                caller.tenant_id,
                caller.caller,
                &scopes,
                gateway_base_url,
                secrets_store,
                provider_store.as_ref(),
            )
            .await
            {
                Ok(url) => DelegationLookupResult::ConsentRequired {
                    authorization_url: url,
                    provider_name: provider.name.clone(),
                    scopes,
                },
                Err(e) => {
                    warn!(
                        target: "credential_delegation",
                        surface_variant,
                        provider_id = %binding.credential_provider_id,
                        error = %e,
                        "Failed to build authorization URL - refusing the request"
                    );
                    DelegationLookupResult::Unavailable
                }
            }
        }
        _ => {
            warn!(
                target: "credential_delegation",
                surface_variant,
                provider_id = %binding.credential_provider_id,
                "Credential provider not found for consent_required - refusing the request"
            );
            DelegationLookupResult::Unavailable
        }
    }
}

/// Drive an MCP `elicitation/create` round-trip for a binding configured with
/// `consent_mode = elicit`. Returns:
///   - `Some((TokenInjected, _, Inject))` if the user accepted AND the OAuth
///     callback populated the vault before the timeout elapsed.
///   - `Some((ElicitationAcceptedPending, _, ConsentRequired))` if the user
///     accepted but the OAuth flow hasn't completed yet — caller surfaces
///     the URL so the client can resume.
///   - `Some((ElicitationDeclined|Cancelled|TimedOut|Unsupported, _, Unavailable))`
///     when the user rejected, the deadline expired, or the prompt could not
///     be delivered under fallback `fail`; the tool call is refused.
///   - `None` if we should fall through to the legacy consent_required path
///     (no session id, client doesn't advertise elicitation cap and fallback
///     is `OnDemand`, provider not found, etc.).
#[allow(clippy::too_many_arguments)]
async fn try_elicit_flow(
    binding: &OutboundCredentialBinding,
    user_identity_hash: &str,
    agent_did: &str,
    channel_id: &str,
    caller: ConsentLinkFor<'_>,
    provider: &CredentialProvider,
    vault_store: &Arc<dyn DelegationVaultStorage>,
    provider_store: &Arc<dyn CredentialProviderStorage>,
    secrets_store: &Arc<dyn SecretsStore>,
    gateway_base_url: &str,
    audit_ctx: Option<&DelegationAuditContext>,
    via_fabric: bool,
    surface_variant: Option<&str>,
) -> Option<(DelegationActionOutcome, Option<String>, DelegationLookupResult)> {
    let session_id = audit_ctx.and_then(|c| c.mcp_session_id.as_deref())?;

    // Check the client advertised the `elicitation` capability during
    // `initialize`. If it didn't, honour the binding's `elicit_fallback`.
    let cap_registry = crate::mcp::elicitation::global_capability_registry();
    let caps = cap_registry
        .get(channel_id, session_id)
        .await;
    let supports_elicitation = caps
        .as_ref()
        .map(|c| c.elicitation)
        .unwrap_or(false);

    if !supports_elicitation {
        match binding.elicit_fallback {
            ElicitFallback::OnDemand => return None, // fall through to legacy consent_required
            ElicitFallback::Fail => {
                // The client was never asked, so this is not an
                // `elicitation_declined`.
                return Some((
                    DelegationActionOutcome::ElicitationUnsupported,
                    Some("client_capability_missing".to_string()),
                    DelegationLookupResult::Unavailable,
                ));
            }
        }
    }

    // Build the authorization URL so we can embed it in the elicitation
    // message (the user clicks it to start OAuth).
    let scopes = if binding.scopes.is_empty() {
        provider
            .default_scopes
            .clone()
    } else {
        binding.scopes.clone()
    };
    let authorization_url = match oauth::mint_consent_link(
        provider,
        agent_did,
        user_identity_hash,
        channel_id,
        caller.tenant_id,
        caller.caller,
        &scopes,
        gateway_base_url,
        secrets_store,
        provider_store.as_ref(),
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            warn!(
                target: "credential_delegation",
                surface_variant,
                provider_id = %binding.credential_provider_id,
                error = %e,
                "Elicit: failed to build authorization URL; falling back to consent_required"
            );
            return None;
        }
    };

    // Register a pending elicitation against the session and build the
    // spec-compliant `elicitation/create` request.
    let pending_registry = crate::mcp::elicitation::global_pending_elicitation_registry();
    let (elicit_id, waiter) = pending_registry
        .register(channel_id, session_id)
        .await;
    let request = crate::mcp::elicitation::build_oauth_consent_elicitation(
        serde_json::Value::String(elicit_id.clone()),
        &provider.name,
        audit_ctx.and_then(|c| c.mcp_tool_name.as_deref()),
        &scopes,
        &authorization_url,
    );

    // Serialize and write onto the session's SSE stream.
    let sse_registry = crate::mcp::streamable_sse::global_streamable_session_registry();
    let serialized = match serde_json::to_string(&request) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                target: "credential_delegation",
                surface_variant,
                error = %e,
                "Elicit: failed to serialize elicitation/create request"
            );
            return None;
        }
    };
    let sent = sse_registry
        .send(channel_id, session_id, axum::response::sse::Event::default().data(serialized))
        .await;
    if !sent {
        // Client never opened the GET notification stream — we cannot
        // deliver. Fall back per binding policy.
        debug!(
            target: "credential_delegation",
            surface_variant,
            session_id = %crate::observability::loggable::secret(session_id),
            "Elicit: no open SSE stream for session; honouring fallback"
        );
        match binding.elicit_fallback {
            ElicitFallback::OnDemand => return None,
            ElicitFallback::Fail => {
                return Some((
                    DelegationActionOutcome::ElicitationUnsupported,
                    Some("sse_stream_unavailable".to_string()),
                    DelegationLookupResult::Unavailable,
                ));
            }
        }
    }

    audit::emit("elicitation_sent", || {
        let mut sent_evt = audit::audit_event(
            DelegationAuditAction::ElicitationSent,
            Some(agent_did),
            Some(user_identity_hash),
            Some(&binding.credential_provider_id),
            Some(channel_id),
        );
        sent_evt.via_fabric = via_fabric;
        sent_evt.detail = Some(format!("elicit_id={}", elicit_id));
        enrich_audit_event(&mut sent_evt, audit_ctx, binding, Some(&provider.name));
        sent_evt
    });

    // Park on the elicitation response with a timeout. We deliberately do
    // NOT race the vault notifier here: per spec we must wait for the
    // client's accept/decline/cancel reply before doing anything else.
    let timeout_duration = std::time::Duration::from_secs(binding.elicit_timeout_secs);
    let elicit_outcome = tokio::time::timeout(timeout_duration, waiter).await;

    let result = match elicit_outcome {
        Ok(Ok(crate::mcp::elicitation::ElicitationResult::Accept { .. })) => {
            audit::emit("elicitation_accepted", || {
                let mut evt = audit::audit_event(
                    DelegationAuditAction::ElicitationAccepted,
                    Some(agent_did),
                    Some(user_identity_hash),
                    Some(&binding.credential_provider_id),
                    Some(channel_id),
                );
                evt.via_fabric = via_fabric;
                evt.detail = Some(format!("elicit_id={}", elicit_id));
                enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                evt
            });

            // Race the OAuth completion (vault notifier) against the
            // remaining elicit budget. If we wake, re-run vault lookup;
            // on hit, Inject. Otherwise surface consent_required so the
            // client can poll/retry.
            let notifier_handle = crate::delegation_vault::notifier::global_vault_population_notifier()
                .subscribe(agent_did, user_identity_hash, &binding.credential_provider_id)
                .await;
            let oauth_wait = tokio::time::timeout(timeout_duration, notifier_handle.notified()).await;

            if oauth_wait.is_ok() {
                // Vault populated — re-lookup and inject.
                match vault_store
                    .lookup(agent_did, user_identity_hash, &binding.credential_provider_id)
                    .await
                {
                    Ok(VaultLookupResult::Found(token)) => {
                        let headers = build_injection_headers(&binding.inject_as, &token.access_token);
                        audit::emit("token_injected", || {
                            let mut inj = audit::audit_event(
                                DelegationAuditAction::TokenInjected,
                                Some(agent_did),
                                Some(user_identity_hash),
                                Some(&binding.credential_provider_id),
                                Some(channel_id),
                            );
                            inj.via_fabric = via_fabric;
                            inj.detail = Some("post_elicitation".to_string());
                            enrich_audit_event(&mut inj, audit_ctx, binding, Some(&provider.name));
                            inj
                        });
                        Some((
                            DelegationActionOutcome::TokenInjected,
                            Some(format!("post_elicitation elicit_id={}", elicit_id)),
                            DelegationLookupResult::Inject(headers),
                        ))
                    }
                    _ => Some((
                        DelegationActionOutcome::ElicitationAcceptedPending,
                        Some(format!("elicit_id={}", elicit_id)),
                        DelegationLookupResult::ConsentRequired {
                            authorization_url,
                            provider_name: provider.name.clone(),
                            scopes,
                        },
                    )),
                }
            } else {
                Some((
                    DelegationActionOutcome::ElicitationAcceptedPending,
                    Some(format!("elicit_id={} oauth_pending", elicit_id)),
                    DelegationLookupResult::ConsentRequired {
                        authorization_url,
                        provider_name: provider.name.clone(),
                        scopes,
                    },
                ))
            }
        }
        Ok(Ok(crate::mcp::elicitation::ElicitationResult::Decline)) => {
            audit::emit("elicitation_declined", || {
                let mut evt = audit::audit_event(
                    DelegationAuditAction::ElicitationDeclined,
                    Some(agent_did),
                    Some(user_identity_hash),
                    Some(&binding.credential_provider_id),
                    Some(channel_id),
                );
                evt.via_fabric = via_fabric;
                evt.detail = Some(format!("elicit_id={}", elicit_id));
                enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                evt
            });
            Some((
                DelegationActionOutcome::ElicitationDeclined,
                Some(format!("elicit_id={}", elicit_id)),
                DelegationLookupResult::Unavailable,
            ))
        }
        Ok(Ok(crate::mcp::elicitation::ElicitationResult::Cancel)) => {
            audit::emit("elicitation_cancelled", || {
                let mut evt = audit::audit_event(
                    DelegationAuditAction::ElicitationCancelled,
                    Some(agent_did),
                    Some(user_identity_hash),
                    Some(&binding.credential_provider_id),
                    Some(channel_id),
                );
                evt.via_fabric = via_fabric;
                evt.detail = Some(format!("elicit_id={}", elicit_id));
                enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                evt
            });
            Some((
                DelegationActionOutcome::ElicitationCancelled,
                Some(format!("elicit_id={}", elicit_id)),
                DelegationLookupResult::Unavailable,
            ))
        }
        Ok(Err(_canceled)) => {
            // Sender dropped without sending — treat as cancel.
            Some((
                DelegationActionOutcome::ElicitationCancelled,
                Some("waiter_dropped".to_string()),
                DelegationLookupResult::Unavailable,
            ))
        }
        Err(_elapsed) => {
            audit::emit("elicitation_timed_out", || {
                let mut evt = audit::audit_event(
                    DelegationAuditAction::ElicitationTimedOut,
                    Some(agent_did),
                    Some(user_identity_hash),
                    Some(&binding.credential_provider_id),
                    Some(channel_id),
                );
                evt.via_fabric = via_fabric;
                evt.detail = Some(format!("elicit_id={} timeout_secs={}", elicit_id, binding.elicit_timeout_secs));
                enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                evt
            });
            Some((
                DelegationActionOutcome::ElicitationTimedOut,
                Some(format!("elicit_id={} timeout_secs={}", elicit_id, binding.elicit_timeout_secs)),
                DelegationLookupResult::Unavailable,
            ))
        }
    };

    // Clean up the registry entry so the oneshot sender doesn't leak.
    let pending_registry = crate::mcp::elicitation::global_pending_elicitation_registry();
    pending_registry
        .remove(channel_id, session_id, &elicit_id)
        .await;

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::config::types::{ConsentMode, CredentialInjection, CredentialRequirement, OutboundCredentialBinding};
    use crate::credential_providers::CredentialProvider;
    use crate::delegation_vault::{DelegationToken, VaultLookupResult};
    use crate::jwt_bearer::JwtVerificationStrategyStorage;
    use crate::secrets::{CreateSecretRequest, Secret, SecretListItem, UpdateSecretRequest};
    use crate::source_auth::AuthenticatedIdentity;

    /// An Access Point caller of a gateway with no STS issuer.
    fn access_point<'a>(
        identity: Option<&'a AuthenticatedIdentity>,
        strategies: Option<&'a dyn JwtVerificationStrategyStorage>,
    ) -> ConsentCaller<'a> {
        ConsentCaller::AccessPoint {
            identity,
            strategies,
            gateway_issuer: None,
        }
    }

    // ── Mock vault store ──────────────────────────────────────────────────

    struct MockVaultStore {
        result: tokio::sync::Mutex<VaultLookupResult>,
    }

    impl MockVaultStore {
        fn new(result: VaultLookupResult) -> Arc<Self> {
            Arc::new(Self {
                result: tokio::sync::Mutex::new(result),
            })
        }
    }

    #[async_trait]
    impl DelegationVaultStorage for MockVaultStore {
        async fn store(
            &self,
            token: DelegationToken,
        ) -> Result<DelegationToken> {
            Ok(token)
        }
        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<DelegationToken>> {
            Ok(None)
        }
        /// A found service token stored under its purpose alone answers every key of that
        /// purpose, so a test need not compute the hashed identity.
        async fn lookup(
            &self,
            _agent_did: &str,
            user_identity_hash: &str,
            _provider_id: &str,
        ) -> Result<VaultLookupResult> {
            let mut result = self
                .result
                .lock()
                .await
                .clone();
            if let VaultLookupResult::Found(token) = &mut result
                && user_identity_hash
                    .strip_prefix(
                        token
                            .user_identity_hash
                            .as_str(),
                    )
                    .is_some_and(|rest| rest.starts_with(':'))
            {
                token.user_identity_hash = user_identity_hash.to_string();
            }
            Ok(result)
        }
        async fn list_all(&self) -> Result<Vec<DelegationToken>> {
            Ok(vec![])
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<bool> {
            Ok(true)
        }
        async fn delete_by_user(
            &self,
            _user_identity_hash: &str,
        ) -> Result<usize> {
            Ok(0)
        }
        async fn update(
            &self,
            token: DelegationToken,
        ) -> Result<DelegationToken> {
            Ok(token)
        }
        async fn mark_used(
            &self,
            _id: &str,
        ) -> Result<()> {
            Ok(())
        }
    }

    // ── Mock credential provider store ────────────────────────────────────

    struct MockProviderStore {
        providers: HashMap<String, CredentialProvider>,
    }

    impl MockProviderStore {
        fn empty() -> Arc<Self> {
            Arc::new(Self { providers: HashMap::new() })
        }

        fn with_oauth_provider(id: &str) -> Arc<Self> {
            Self::with_provider(id, CredentialProviderType::OAuth2AuthorizationCode)
        }

        fn with_provider(
            id: &str,
            provider_type: CredentialProviderType,
        ) -> Arc<Self> {
            let mut providers = HashMap::new();
            providers.insert(id.to_string(), make_credential_provider(id, provider_type));
            Arc::new(Self { providers })
        }

        fn with_stored(provider: CredentialProvider) -> Arc<Self> {
            let mut providers = HashMap::new();
            providers.insert(provider.id.clone(), provider);
            Arc::new(Self { providers })
        }
    }

    #[async_trait]
    impl CredentialProviderStorage for MockProviderStore {
        async fn get_checked(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<crate::credential_providers::CredentialProvider>> {
            self.get(id).await
        }

        async fn create(
            &self,
            provider: CredentialProvider,
        ) -> Result<CredentialProvider> {
            Ok(provider)
        }
        async fn get(
            &self,
            id: &str,
        ) -> Result<Option<CredentialProvider>> {
            Ok(self
                .providers
                .get(id)
                .cloned())
        }
        async fn list(&self) -> Result<Vec<CredentialProvider>> {
            Ok(self
                .providers
                .values()
                .cloned()
                .collect())
        }
        async fn update(
            &self,
            provider: CredentialProvider,
        ) -> Result<CredentialProvider> {
            Ok(provider)
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<bool> {
            Ok(true)
        }
        async fn find_by_provider_id(
            &self,
            _tenant_id: Option<&str>,
            _provider_id: &str,
        ) -> Result<Option<CredentialProvider>> {
            Ok(None)
        }
    }

    // ── Mock secrets store ────────────────────────────────────────────────

    /// Lists the `CLIENT_ID` and `CLIENT_SECRET` references of `make_credential_provider` in
    /// `tenant_id` and answers a lookup of either with an empty value, or holds no secret at
    /// all when `empty`.
    #[derive(Default)]
    struct MockSecretsStore {
        tenant_id: Option<String>,
        empty: bool,
    }

    fn empty_secrets() -> Arc<dyn SecretsStore> {
        Arc::new(MockSecretsStore {
            empty: true,
            ..Default::default()
        })
    }

    #[async_trait]
    impl crate::secrets::store::SecretsStore for MockSecretsStore {
        async fn create(
            &self,
            _request: CreateSecretRequest,
        ) -> Result<Secret> {
            unimplemented!()
        }
        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<Secret>> {
            Ok(None)
        }
        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> Result<Option<Secret>> {
            Ok(self
                .list_all()
                .await?
                .into_iter()
                .find(|secret| secret.secret_id == secret_id)
                .map(|item| Secret {
                    id: item.id,
                    tenant_id: item.tenant_id,
                    name: item.name,
                    secret_id: item.secret_id,
                    description: None,
                    value: String::new(),
                    secret_type: item.secret_type,
                    tags: vec![],
                    created_at: item.created_at,
                    updated_at: item.updated_at,
                }))
        }
        async fn list_all(&self) -> Result<Vec<SecretListItem>> {
            if self.empty {
                return Ok(Vec::new());
            }
            let at = chrono::DateTime::<Utc>::UNIX_EPOCH;
            Ok(["CLIENT_ID", "CLIENT_SECRET"]
                .into_iter()
                .map(|secret_id| SecretListItem {
                    id: secret_id.to_lowercase(),
                    tenant_id: self.tenant_id.clone(),
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    secret_type: "General".into(),
                    tags: vec![],
                    created_at: at,
                    updated_at: at,
                })
                .collect())
        }
        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> Result<Secret> {
            unimplemented!()
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<()> {
            Ok(())
        }
        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> Result<Vec<SecretListItem>> {
            Ok(vec![])
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    #[test]
    fn inject_delegated_credential_into_mcp_meta_creates_params_meta() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"schedule_meeting"}}"#;

        let modified = super::inject_delegated_credential_into_mcp_meta(body, "calendar", "bdd-token")
            .expect("metadata injection succeeds");
        let parsed: serde_json::Value = serde_json::from_slice(&modified).expect("valid JSON");

        assert_eq!(parsed["params"]["_meta"]["calendar"].as_str(), Some("bdd-token"));
        assert_eq!(parsed["params"]["name"].as_str(), Some("schedule_meeting"));
    }

    #[test]
    fn inject_delegated_credential_into_mcp_meta_rejects_non_object_root() {
        let result = super::inject_delegated_credential_into_mcp_meta(br#"[]"#, "calendar", "bdd-token");

        assert!(
            matches!(result, Err(super::McpMetaInjectionError::RootNotObject)),
            "expected non-object JSON roots to fail injection, got {result:?}"
        );
    }

    #[test]
    fn meta_injection_builds_typed_metadata_target() {
        let injections =
            super::build_injection_headers(&CredentialInjection::Meta { field: "calendar".to_string() }, "bdd-token");

        assert_eq!(
            injections,
            vec![super::ResolvedCredentialInjection::McpMeta {
                field: "calendar".to_string(),
                value: "bdd-token".to_string(),
            }]
        );
    }

    #[test]
    fn custom_header_with_legacy_meta_prefix_stays_header() {
        let injections = super::build_injection_headers(
            &CredentialInjection::CustomHeader {
                name: "X-Delegation-Meta-calendar".to_string(),
                format: "token {value}".to_string(),
            },
            "bdd-token",
        );

        assert_eq!(
            injections,
            vec![super::ResolvedCredentialInjection::Header {
                name: "X-Delegation-Meta-calendar".to_string(),
                value: "token bdd-token".to_string(),
            }]
        );
    }

    fn make_credential_provider(
        id: &str,
        provider_type: CredentialProviderType,
    ) -> CredentialProvider {
        let now = Utc::now();
        CredentialProvider {
            id: id.to_string(),
            tenant_id: None,
            name: format!("Test Provider {}", id),
            provider_id: format!("test-{}", id),
            provider_type,
            authorization_endpoint: Some("https://auth.example.com/authorize".to_string()),
            token_endpoint: Some("https://auth.example.com/token".to_string()),
            client_id_secret_ref: Some("CLIENT_ID".to_string()),
            client_secret_secret_ref: Some("CLIENT_SECRET".to_string()),
            default_scopes: vec!["repo".to_string()],
            callback_path: format!("/oauth/callback/test-{}", id),
            token_refresh_enabled: true,
            additional_params: HashMap::new(),
            api_key_secret_ref: None,
            jwt: Default::default(),
            description: None,
            consent_confirmation: None,
            created_at: now,
            updated_at: now,
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
            issuer: None,
            revocation_endpoint: None,
            token_endpoint_auth_method: None,
            client_id: None,
            allow_unadvertised_pkce: false,
            authorization_response_iss_parameter_supported: None,
            authorization_response_issuer: None,
            scope_comparison: Default::default(),
            revocation_ends_authorization: false,
            send_resource: true,
        }
    }

    fn make_binding(provider_id: &str) -> OutboundCredentialBinding {
        OutboundCredentialBinding {
            credential_provider_id: provider_id.to_string(),
            scopes: vec!["repo".to_string()],
            required_for: CredentialRequirement::All,
            consent_mode: ConsentMode::OnDemand,
            inject_as: CredentialInjection::BearerHeader,
            elicit_timeout_secs: 300,
            elicit_fallback: crate::config::types::ElicitFallback::OnDemand,
            subject: None,
        }
    }

    fn make_tool_binding(
        provider_id: &str,
        tools: Vec<String>,
    ) -> OutboundCredentialBinding {
        OutboundCredentialBinding {
            credential_provider_id: provider_id.to_string(),
            scopes: vec!["repo".to_string()],
            required_for: CredentialRequirement::Tools(tools),
            consent_mode: ConsentMode::OnDemand,
            inject_as: CredentialInjection::BearerHeader,
            elicit_timeout_secs: 300,
            elicit_fallback: crate::config::types::ElicitFallback::OnDemand,
            subject: None,
        }
    }

    fn make_token(
        expired: bool,
        has_refresh: bool,
    ) -> DelegationToken {
        let now = Utc::now();
        DelegationToken {
            id: "tok-1".to_string(),
            agent_did: "did:web:agent.example".to_string(),
            user_identity_hash: "sha256:user1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            access_token: "gho_test_access_token_12345".to_string(),
            refresh_token: if has_refresh {
                Some("gho_test_refresh_token".to_string())
            } else {
                None
            },
            token_type: "bearer".to_string(),
            scopes: vec!["repo".to_string()],
            expires_at: if expired {
                Some(now - Duration::seconds(60))
            } else {
                Some(now + Duration::hours(1))
            },
            delegation_vc: None,
            consent_identity: None,
            consent_granted_at: now,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn refreshed_credentials_rejected_after_revocation_are_not_injectable() {
        let directory = tempfile::tempdir().unwrap();
        let vault = crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let binding = make_binding("cp-1");
        let provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2AuthorizationCode);
        let token = vault
            .store(make_token(true, true))
            .await
            .unwrap();
        let mut refreshed = token.clone();
        refreshed.access_token = "new-provider-credential".into();
        refreshed.expires_at = Some(Utc::now() + Duration::hours(1));
        assert!(
            vault
                .delete(&token.id)
                .await
                .unwrap()
        );
        let Err(error) = vault.update(refreshed).await else {
            panic!("a provider response must not revive revoked authorization");
        };
        let rejected = refreshed_token_rejected(&binding, &provider, &error, None);
        assert!(matches!(rejected.result, DelegationLookupResult::Unavailable));
        assert_eq!(rejected.action.outcome, DelegationActionOutcome::RefreshFailed);
        assert_eq!(
            rejected
                .action
                .detail
                .as_deref(),
            Some("vault_update_rejected")
        );
        assert!(
            vault
                .get(&token.id)
                .await
                .unwrap()
                .is_none()
        );

        let token = vault
            .store(make_token(true, true))
            .await
            .unwrap();
        let mut refreshed = token.clone();
        refreshed.access_token = "persisted-provider-credential".into();
        let Ok(stored) = vault.update(refreshed).await else {
            panic!("an unchanged authorization must accept its refreshed token");
        };
        assert_eq!(stored.access_token, "persisted-provider-credential");
        assert!(stored.updated_at > token.updated_at);
        assert_eq!(
            vault
                .get(&token.id)
                .await
                .unwrap()
                .unwrap()
                .access_token,
            stored.access_token
        );
    }

    #[tokio::test]
    async fn legacy_resolution_cannot_bypass_a_verified_credential_refresh_claim() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(
            crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().into())
                .await
                .unwrap(),
        );
        let mut token = make_token(true, true);
        token.consent_identity = Some(
            serde_json::from_value(serde_json::json!({
                "principal": "verified-user", "provider_digest": ([1; 32]), "strategy_digest": ([2; 32])
            }))
            .unwrap(),
        );
        let token = vault
            .store(token)
            .await
            .unwrap();
        let held = vault
            .claim_refresh(&token, modern::now_secs().unwrap())
            .await
            .unwrap();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let providers: Arc<dyn CredentialProviderStorage> = MockProviderStore::with_oauth_provider("cp-1");
        let store: Arc<dyn DelegationVaultStorage> = vault.clone();
        let results = resolve_delegation_credentials(
            &[make_binding("cp-1")],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &store,
            &providers,
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            Some("verified-user"),
        )
        .await;
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, DelegationLookupResult::Unavailable));
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some("coordinated_refresh_unavailable")
        );
        assert_eq!(
            vault
                .get(&token.id)
                .await
                .unwrap()
                .unwrap()
                .updated_at,
            token.updated_at
        );
        assert_eq!(held.token().refresh_token, token.refresh_token);
    }

    async fn resolve_consented_token(
        consent_principal: Option<&str>,
        consented_by: Option<&str>,
    ) -> Vec<DelegationResolution> {
        let mut token = make_token(false, false);
        token.consent_identity = consented_by.map(|principal| {
            serde_json::from_value(serde_json::json!({
                "principal": principal, "provider_digest": ([1; 32]), "strategy_digest": ([2; 32])
            }))
            .unwrap()
        });
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        resolve_delegation_credentials(
            &[make_binding("cp-1")],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            consent_principal,
        )
        .await
    }

    #[tokio::test]
    async fn verified_consent_credentials_are_released_only_to_their_principal() {
        // The legacy lookup key has no issuer in it, so an unauthenticated or
        // differently-issued caller must not receive a consented credential.
        for caller in [None, Some("another-user")] {
            let results = resolve_consented_token(caller, Some("verified-user")).await;
            assert_eq!(results.len(), 1);
            assert!(matches!(results[0].result, DelegationLookupResult::Unavailable), "caller {caller:?}");
            assert_eq!(
                results[0].action.outcome,
                DelegationActionOutcome::ConsentIdentityMismatch,
                "caller {caller:?}"
            );
            assert_eq!(
                results[0]
                    .action
                    .detail
                    .as_deref(),
                Some("consent_identity_mismatch"),
                "caller {caller:?}"
            );
        }

        let results = resolve_consented_token(Some("verified-user"), Some("verified-user")).await;
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, DelegationLookupResult::Inject(_)));
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::TokenInjected);

        // A legacy record carries no consent identity and is unaffected.
        let results = resolve_consented_token(None, None).await;
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, DelegationLookupResult::Inject(_)));
    }

    #[tokio::test]
    async fn test_found_token_injects_bearer_header() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        match &results[0].result {
            DelegationLookupResult::Inject(injections) => {
                assert_eq!(injections.len(), 1);
                assert_eq!(
                    injections[0],
                    ResolvedCredentialInjection::Header {
                        name: "Authorization".to_string(),
                        value: "Bearer gho_test_access_token_12345".to_string(),
                    }
                );
            }
            _ => panic!("Expected Inject, got {:?}", result_tag(&results[0].result)),
        }
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(results[0].action.provider_id, "cp-1");
    }

    #[test]
    fn an_unresolvable_credential_is_refused_in_the_shape_of_the_surface_protocol() {
        let (content_type, body) =
            delegation_unavailable_body(true, br#"{"jsonrpc":"2.0","id":42,"method":"tools/call"}"#);
        assert_eq!(content_type, "application/json");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"jsonrpc": "2.0", "id": 42,
                "error": {"code": -32603, "message": "Delegated credentials unavailable"}})
        );

        let (_, body) = delegation_unavailable_body(true, b"not json");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"], serde_json::Value::Null);

        let (content_type, body) = delegation_unavailable_body(false, br#"{"jsonrpc":"2.0","id":42}"#);
        assert_eq!(content_type, "application/problem+json");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"type": "https://affinidi.com/atg/errors/delegated-credentials-unavailable",
                "title": "Delegated Credentials Unavailable", "status": 503,
                "detail": "Delegated credentials unavailable"})
        );
    }

    #[tokio::test]
    async fn a_binding_whose_provider_is_gone_is_unavailable() {
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "Unavailable");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ProviderUnavailable);
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some("provider_not_found")
        );
    }

    #[tokio::test]
    async fn a_cached_client_credentials_token_is_injected_without_a_token_request() {
        let mut token = make_token(false, false);
        token.user_identity_hash = "__client_credentials__".to_string();
        token.access_token = "cached-service-token".to_string();
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_provider("cp-1", CredentialProviderType::OAuth2ClientCredentials);
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());

        let results = resolve_delegation_credentials(
            &[make_binding("cp-1")],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        match &results[0].result {
            DelegationLookupResult::Inject(injections) => assert_eq!(
                injections,
                &vec![ResolvedCredentialInjection::Header {
                    name: "Authorization".to_string(),
                    value: "Bearer cached-service-token".to_string(),
                }]
            ),
            _ => panic!("Expected Inject, got {:?}", result_tag(&results[0].result)),
        }
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some("client_credentials_cached")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_renewal_injects_the_cached_client_credentials_token_as_stale() {
        let now = Utc::now();
        let mut token = make_token(false, false);
        token.user_identity_hash = "__client_credentials__".to_string();
        token.access_token = "cached-service-token".to_string();
        token.created_at = now - Duration::seconds(3400);
        token.expires_at = Some(now + Duration::seconds(200));
        let vault: Arc<dyn DelegationVaultStorage> = MockVaultStore::new(VaultLookupResult::Found(token));
        let directory = tempfile::tempdir().unwrap();
        let secrets: Arc<dyn SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                directory
                    .path()
                    .to_str()
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        for secret_id in ["CLIENT_ID", "CLIENT_SECRET"] {
            secrets
                .create(CreateSecretRequest {
                    tenant_id: None,
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: "value".into(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        let app = axum::Router::new()
            .fallback(axum::routing::post(|| async { axum::http::StatusCode::INTERNAL_SERVER_ERROR }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let mut server = tokio::task::JoinSet::new();
        server.spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        let mut provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2ClientCredentials);
        provider.token_endpoint = Some(token_endpoint.clone());
        let providers: Arc<dyn CredentialProviderStorage> = MockProviderStore::with_stored(provider);
        let egress = oauth::TokenEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: Some(token_endpoint),
            policy: Default::default(),
        };

        let results = egress
            .scope(resolve_delegation_credentials(
                &[make_binding("cp-1")],
                "sha256:user1",
                "did:web:agent.example",
                "ch-1",
                crate::tenancy::SurfaceTenancy::configured(None),
                None,
                &vault,
                &providers,
                &secrets,
                "https://gw.example.com",
                false,
                access_point(None, None),
                None,
                None,
            ))
            .await;

        assert_eq!(results.len(), 1);
        match &results[0].result {
            DelegationLookupResult::Inject(injections) => assert_eq!(
                injections,
                &vec![ResolvedCredentialInjection::Header {
                    name: "Authorization".to_string(),
                    value: "Bearer cached-service-token".to_string(),
                }]
            ),
            _ => panic!("Expected Inject, got {:?}", result_tag(&results[0].result)),
        }
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some("client_credentials_stale")
        );
    }

    #[tokio::test]
    async fn a_token_from_an_http_token_endpoint_is_named_in_the_audit_detail_in_warn_mode() {
        let mut token = make_token(false, false);
        token.user_identity_hash = "__client_credentials__".to_string();
        token.access_token = "cached-service-token".to_string();
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let mut provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2ClientCredentials);
        provider.token_endpoint = Some("http://auth.example.com/token".into());
        let providers = Arc::new(MockProviderStore {
            providers: HashMap::from([("cp-1".to_string(), provider)]),
        });
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());

        let results = resolve_delegation_credentials(
            &[make_binding("cp-1")],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "Inject");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some("client_credentials_cached insecure_token_endpoint")
        );
    }

    #[tokio::test]
    async fn api_key_and_client_credentials_failures_are_unavailable() {
        for (provider_type, outcome, error) in [
            (
                CredentialProviderType::ApiKey,
                DelegationActionOutcome::ApiKeyResolutionFailed,
                ServiceTokenError::SecretUnavailable,
            ),
            (
                CredentialProviderType::OAuth2ClientCredentials,
                DelegationActionOutcome::ClientCredentialsFailed,
                ServiceTokenError::SecretUnavailable,
            ),
            (
                CredentialProviderType::OAuth2JwtBearer,
                DelegationActionOutcome::JwtBearerFailed,
                ServiceTokenError::TokenRequestFailed,
            ),
            (
                CredentialProviderType::OAuth2ClientCredentialsJwtAuth,
                DelegationActionOutcome::ClientCredentialsJwtAuthFailed,
                ServiceTokenError::SecretUnavailable,
            ),
        ] {
            let vault = MockVaultStore::new(VaultLookupResult::NotFound);
            let providers = MockProviderStore::with_provider("cp-1", provider_type.clone());
            let secrets = empty_secrets();

            let results = resolve_delegation_credentials(
                &[make_binding("cp-1")],
                "sha256:user1",
                "did:web:agent.example",
                "ch-1",
                crate::tenancy::SurfaceTenancy::configured(None),
                None,
                &(vault as Arc<dyn DelegationVaultStorage>),
                &(providers as Arc<dyn CredentialProviderStorage>),
                &secrets,
                "https://gw.example.com",
                false,
                access_point(None, None),
                None,
                None,
            )
            .await;

            assert_eq!(results.len(), 1);
            assert_eq!(result_tag(&results[0].result), "Unavailable", "{provider_type:?}");
            assert_eq!(results[0].action.outcome, outcome, "{provider_type:?}");
            // The audit detail is the typed service-token error, never the issuer's response.
            if provider_type != CredentialProviderType::ApiKey {
                assert_eq!(
                    results[0]
                        .action
                        .detail
                        .as_deref(),
                    Some(error.to_string().as_str()),
                    "{provider_type:?}"
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_endpoint_the_egress_policy_blocks_is_named_in_the_audit_detail() {
        let directory = tempfile::tempdir().unwrap();
        let secrets: Arc<dyn SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new(
                directory
                    .path()
                    .to_str()
                    .unwrap(),
            )
            .unwrap(),
        );
        for secret_id in ["CLIENT_ID", "CLIENT_SECRET"] {
            secrets
                .create(CreateSecretRequest {
                    tenant_id: None,
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: "value".into(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        let mut provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2ClientCredentials);
        provider.token_endpoint = Some("http://127.0.0.1:9/token".into());
        let providers = Arc::new(MockProviderStore {
            providers: HashMap::from([("cp-1".to_string(), provider)]),
        });
        let vault: Arc<dyn DelegationVaultStorage> = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers: Arc<dyn CredentialProviderStorage> = providers;

        // A refusal starts no backoff, so the second resolve is refused again rather than held back.
        for _ in 0..2 {
            let results = resolve_delegation_credentials(
                &[make_binding("cp-1")],
                "sha256:user1",
                "did:web:agent.example",
                "ch-1",
                crate::tenancy::SurfaceTenancy::configured(None),
                None,
                &vault,
                &providers,
                &secrets,
                "https://gw.example.com",
                false,
                access_point(None, None),
                None,
                None,
            )
            .await;

            assert_eq!(results.len(), 1);
            assert_eq!(result_tag(&results[0].result), "Unavailable");
            assert_eq!(results[0].action.outcome, DelegationActionOutcome::ClientCredentialsFailed);
            assert_eq!(
                results[0]
                    .action
                    .detail
                    .as_deref(),
                Some(
                    ServiceTokenError::TokenEndpointRefused
                        .to_string()
                        .as_str()
                )
            );
        }
    }

    #[tokio::test]
    async fn a_refused_refresh_logs_and_audits_only_the_oauth_error_code() {
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let directory = tempfile::tempdir().unwrap();
        let secrets: Arc<dyn SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                directory
                    .path()
                    .to_str()
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        for secret_id in ["CLIENT_ID", "CLIENT_SECRET"] {
            secrets
                .create(CreateSecretRequest {
                    tenant_id: None,
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: "value".into(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        let app = axum::Router::new().fallback(axum::routing::post(|| async {
            (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "description-marker",
                    "error_uri": "https://idp.example/uri-marker"
                })),
            )
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let mut server = tokio::task::JoinSet::new();
        server.spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        let mut provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2AuthorizationCode);
        provider.token_endpoint = Some(token_endpoint.clone());
        let providers: Arc<dyn CredentialProviderStorage> = MockProviderStore::with_stored(provider);
        let vault: Arc<dyn DelegationVaultStorage> =
            MockVaultStore::new(VaultLookupResult::ExpiredRefreshable(make_token(true, true)));
        let egress = oauth::TokenEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: Some(token_endpoint),
            policy: Default::default(),
        };

        let (results, events) = crate::audit::producer::capture(egress.scope(resolve_delegation_credentials(
            &[make_binding("cp-1")],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &vault,
            &providers,
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )))
        .await;

        let expected = "Token refresh failed (HTTP 400 Bad Request): invalid_grant";
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::RefreshFailed);
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some(expected)
        );
        let refresh_failed: Vec<_> = events
            .iter()
            .filter(|event| matches!(event.event, DelegationAuditAction::RefreshFailed))
            .collect();
        assert_eq!(refresh_failed.len(), 1, "{events:?}");
        assert_eq!(
            refresh_failed[0]
                .detail
                .as_deref(),
            Some(expected)
        );
        let text = logs.text();
        let line = text
            .lines()
            .find(|line| line.contains("Token refresh failed — requesting new consent"))
            .unwrap_or_else(|| panic!("the refused refresh is logged: {text}"));
        assert!(line.contains("invalid_grant"), "{line}");
        for marker in ["description-marker", "uri-marker"] {
            assert!(!text.contains(marker), "{marker} reached the log: {text}");
            assert!(!format!("{events:?}").contains(marker), "{marker} reached the audit: {events:?}");
        }
    }

    async fn resolve_for_tenant(
        provider_type: CredentialProviderType,
        provider_tenant: Option<&str>,
        mode: crate::config::credential_policy::RuleMode,
    ) -> DelegationResolution {
        let mut token = make_token(false, false);
        token.user_identity_hash = "__client_credentials__".to_string();
        token.access_token = "cached-service-token".to_string();
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let mut provider = make_credential_provider("cp-1", provider_type);
        provider.tenant_id = provider_tenant.map(String::from);
        let providers = MockProviderStore::with_stored(provider);
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore {
            tenant_id: provider_tenant.map(String::from),
            empty: false,
        });
        resolve_delegation_credentials(
            &[make_binding("cp-1")],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy {
                tenant_id: Some("tenant-a"),
                mode,
            },
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await
        .remove(0)
    }

    #[tokio::test]
    async fn a_tenant_surface_never_sends_another_tenants_gateway_credential() {
        use crate::config::credential_policy::RuleMode::{Enforce, Warn};
        for mode in [Warn, Enforce] {
            for provider_type in [
                CredentialProviderType::ApiKey,
                CredentialProviderType::OAuth2ClientCredentials,
                CredentialProviderType::OAuth2JwtBearer,
                CredentialProviderType::OAuth2ClientCredentialsJwtAuth,
            ] {
                let resolution = resolve_for_tenant(provider_type.clone(), Some("tenant-b"), mode).await;
                assert_eq!(result_tag(&resolution.result), "Unavailable", "{provider_type:?}");
                assert_eq!(resolution.action.outcome, DelegationActionOutcome::ProviderUnavailable);
                assert_eq!(
                    resolution
                        .action
                        .detail
                        .as_deref(),
                    Some("provider_forbidden")
                );
            }
        }
    }

    #[tokio::test]
    async fn an_appliance_wide_gateway_credential_is_refused_on_a_tenant_surface_only_when_enforced() {
        use crate::config::credential_policy::RuleMode::{Enforce, Warn};
        for provider_type in [
            CredentialProviderType::ApiKey,
            CredentialProviderType::OAuth2ClientCredentials,
            CredentialProviderType::OAuth2JwtBearer,
            CredentialProviderType::OAuth2ClientCredentialsJwtAuth,
        ] {
            let refused = resolve_for_tenant(provider_type.clone(), None, Enforce).await;
            assert_eq!(result_tag(&refused.result), "Unavailable", "{provider_type:?}");
            assert_eq!(refused.action.outcome, DelegationActionOutcome::ProviderUnavailable);
            assert_eq!(
                refused
                    .action
                    .detail
                    .as_deref(),
                Some("provider_forbidden")
            );
        }

        let warned = resolve_for_tenant(CredentialProviderType::OAuth2ClientCredentials, None, Warn).await;
        assert_eq!(result_tag(&warned.result), "Inject");
        assert_eq!(warned.action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(
            warned
                .action
                .detail
                .as_deref(),
            Some("client_credentials_cached (appliance_wide_credential)")
        );

        let own = resolve_for_tenant(CredentialProviderType::OAuth2ClientCredentials, Some("tenant-a"), Enforce).await;
        assert_eq!(result_tag(&own.result), "Inject");
        assert_eq!(own.action.detail.as_deref(), Some("client_credentials_cached"));
    }

    #[tokio::test]
    async fn an_appliance_wide_authorization_code_provider_stays_usable_on_a_tenant_surface() {
        let resolution = resolve_for_tenant(
            CredentialProviderType::OAuth2AuthorizationCode,
            None,
            crate::config::credential_policy::RuleMode::Enforce,
        )
        .await;
        assert_ne!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("provider_forbidden")
        );
        assert_ne!(resolution.action.outcome, DelegationActionOutcome::ProviderUnavailable);
    }

    #[tokio::test]
    async fn a_delegation_line_names_the_request_variant() {
        use crate::observability::policy_audit::{RequestScope, in_request, set_request_variant};
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let vault: Arc<dyn DelegationVaultStorage> = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers: Arc<dyn CredentialProviderStorage> = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![make_binding("cp-1")];

        in_request(RequestScope::new("0123456789abcdef".to_string()), async {
            set_request_variant("beta");
            resolve_delegation_credentials(
                &bindings,
                "sha256:user1",
                "did:web:agent.example",
                "ch-1",
                crate::tenancy::SurfaceTenancy::configured(None),
                None,
                &vault,
                &providers,
                &secrets,
                "https://gw.example.com",
                false,
                access_point(None, None),
                None,
                None,
            )
            .await
        })
        .await;

        let line = logs
            .text()
            .lines()
            .find(|line| line.contains("Credential provider not found"))
            .map(str::to_string)
            .expect("the missing provider is logged");
        assert!(line.contains("surface_variant=\"beta\""), "{line}");
    }

    #[tokio::test]
    async fn test_tool_filter_skips_non_matching_binding() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![make_tool_binding("cp-1", vec!["list_repos".to_string()])];

        // Call with a different tool name
        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            Some("create_issue"),
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0].result, DelegationLookupResult::NotApplicable),
            "Non-matching tool should produce NotApplicable"
        );
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::NotApplicable);
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some("tool_filter")
        );
    }

    #[tokio::test]
    async fn test_tool_filter_matches_correct_tool() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![make_tool_binding("cp-1", vec!["list_repos".to_string()])];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            Some("list_repos"),
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0].result, DelegationLookupResult::Inject(_)), "Matching tool should produce Inject");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::TokenInjected);
    }

    #[tokio::test]
    async fn test_tool_binding_skips_when_no_tool_name() {
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![make_tool_binding("cp-1", vec!["list_repos".to_string()])];

        // No tool name (non-MCP request)
        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0].result, DelegationLookupResult::NotApplicable),
            "Tool binding with no tool name should produce NotApplicable"
        );
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some("tool_filter_no_tool")
        );
    }

    #[tokio::test]
    async fn test_empty_bindings_returns_empty() {
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());

        let results = resolve_delegation_credentials(
            &[],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert!(results.is_empty(), "Empty bindings should return empty results");
    }

    #[tokio::test]
    async fn test_custom_header_injection() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![OutboundCredentialBinding {
            credential_provider_id: "cp-1".to_string(),
            scopes: vec![],
            required_for: CredentialRequirement::All,
            consent_mode: ConsentMode::OnDemand,
            inject_as: CredentialInjection::CustomHeader {
                name: "X-GitHub-Token".to_string(),
                format: "token {value}".to_string(),
            },
            elicit_timeout_secs: 300,
            elicit_fallback: crate::config::types::ElicitFallback::OnDemand,
            subject: None,
        }];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        match &results[0].result {
            DelegationLookupResult::Inject(injections) => {
                assert_eq!(
                    injections[0],
                    ResolvedCredentialInjection::Header {
                        name: "X-GitHub-Token".to_string(),
                        value: "token gho_test_access_token_12345".to_string(),
                    }
                );
            }
            _ => panic!("Expected Inject with custom header"),
        }
    }

    /// A `consent_mode: external` binding is served only by its grant by
    /// binding: an agent-keyed path that reaches one, whatever its provider,
    /// refuses the request and never builds an authorization URL or reads an
    /// agent-keyed token.
    #[tokio::test]
    async fn an_external_consent_binding_is_never_resolved_by_agent() {
        let vault = MockVaultStore::new(VaultLookupResult::Found(make_token(false, false)));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let mut binding = make_binding("cp-1");
        binding.consent_mode = ConsentMode::External;
        binding.subject = Some(crate::config::agent_surface::GrantSubject::Owner);

        let results = resolve_delegation_credentials(
            &[binding],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].result, DelegationLookupResult::Unavailable));
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ProviderUnavailable);
    }

    #[tokio::test]
    async fn a_vault_read_error_is_unavailable() {
        struct ErrorVaultStore;

        #[async_trait]
        impl DelegationVaultStorage for ErrorVaultStore {
            async fn store(
                &self,
                token: DelegationToken,
            ) -> Result<DelegationToken> {
                Ok(token)
            }
            async fn get(
                &self,
                _id: &str,
            ) -> Result<Option<DelegationToken>> {
                Ok(None)
            }
            async fn lookup(
                &self,
                _a: &str,
                _b: &str,
                _c: &str,
            ) -> Result<VaultLookupResult> {
                Err(anyhow::anyhow!("storage unreachable"))
            }
            async fn list_all(&self) -> Result<Vec<DelegationToken>> {
                Ok(vec![])
            }
            async fn delete(
                &self,
                _id: &str,
            ) -> Result<bool> {
                Ok(true)
            }
            async fn delete_by_user(
                &self,
                _: &str,
            ) -> Result<usize> {
                Ok(0)
            }
            async fn update(
                &self,
                token: DelegationToken,
            ) -> Result<DelegationToken> {
                Ok(token)
            }
            async fn mark_used(
                &self,
                _id: &str,
            ) -> Result<()> {
                Ok(())
            }
        }

        let vault: Arc<dyn DelegationVaultStorage> = Arc::new(ErrorVaultStore);
        // Use a real provider so we reach the vault lookup (instead of
        // short-circuiting on provider_not_found).
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &vault,
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "Unavailable");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::LookupError);
    }

    #[tokio::test]
    async fn test_expired_no_refresh_triggers_consent_required_path() {
        // Expired with no refresh token → should attempt consent_required.
        // Since MockProviderStore is empty, the binding is unavailable.
        let vault = MockVaultStore::new(VaultLookupResult::ExpiredNoRefresh(make_token(true, false)));
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            true, // via_fabric
            ConsentCaller::TransitOrFabric,
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "Unavailable");
    }

    #[tokio::test]
    async fn test_multiple_bindings_processed_independently() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());

        let bindings = vec![make_binding("cp-1"), make_tool_binding("cp-2", vec!["special_tool".to_string()])];

        // No tool name → first binding matches (All), second is filtered (Tools with no tool)
        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None,
            None,
        )
        .await;

        assert_eq!(results.len(), 2);
        assert!(matches!(&results[0].result, DelegationLookupResult::Inject(_)));
        assert!(matches!(&results[1].result, DelegationLookupResult::NotApplicable));
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(results[1].action.outcome, DelegationActionOutcome::NotApplicable);
    }

    fn result_tag(r: &DelegationLookupResult) -> &'static str {
        match r {
            DelegationLookupResult::Inject(_) => "Inject",
            DelegationLookupResult::ConsentRequired { .. } => "ConsentRequired",
            DelegationLookupResult::NotApplicable => "NotApplicable",
            DelegationLookupResult::Unavailable => "Unavailable",
        }
    }

    // ── ConsentMode::Elicit branches ──────────────────────────────────

    fn elicit_binding(
        provider_id: &str,
        fallback: crate::config::types::ElicitFallback,
    ) -> OutboundCredentialBinding {
        OutboundCredentialBinding {
            credential_provider_id: provider_id.to_string(),
            scopes: vec!["repo".to_string()],
            required_for: CredentialRequirement::All,
            consent_mode: ConsentMode::Elicit,
            inject_as: CredentialInjection::BearerHeader,
            elicit_timeout_secs: 1,
            elicit_fallback: fallback,
            subject: None,
        }
    }

    #[tokio::test]
    async fn test_elicit_without_session_id_falls_through_to_consent_required() {
        // ConsentMode::Elicit + NO audit_ctx.mcp_session_id → try_elicit_flow
        // returns None and the caller invokes build_consent_required.
        // An empty MockSecretsStore cannot resolve the OAuth client_id secret, so no
        // consent link is minted and the binding is unavailable.
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets = empty_secrets();
        let bindings = vec![elicit_binding("cp-1", crate::config::types::ElicitFallback::OnDemand)];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            None, // audit_ctx = None → no mcp_session_id
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "Unavailable");
    }

    #[tokio::test]
    async fn test_elicit_no_capability_fail_fallback_refuses_the_request() {
        // ConsentMode::Elicit + session_id present + client did NOT advertise
        // elicitation capability + fallback = Fail → Unavailable + audit.
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let bindings = vec![elicit_binding("cp-1", crate::config::types::ElicitFallback::Fail)];

        let ctx = DelegationAuditContext {
            mcp_session_id: Some("session-with-no-cap".to_string()),
            ..Default::default()
        };

        let (results, events) = crate::audit::producer::capture(resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            Some(&ctx),
            None,
        ))
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "Unavailable");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ElicitationUnsupported);
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some("client_capability_missing")
        );
        // The client was never asked, so nothing was declined.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.event, DelegationAuditAction::ElicitationDeclined)),
            "a client without the elicitation capability did not decline: {events:?}"
        );
    }

    #[tokio::test]
    async fn test_elicit_no_capability_on_demand_fallback_falls_through() {
        // ConsentMode::Elicit + session_id + no elicitation cap + fallback =
        // OnDemand → falls through to consent_required.
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets = empty_secrets();
        let bindings = vec![elicit_binding("cp-1", crate::config::types::ElicitFallback::OnDemand)];

        let ctx = DelegationAuditContext {
            mcp_session_id: Some("session-on-demand-fallback".to_string()),
            ..Default::default()
        };

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            Some(&ctx),
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        // As above: fallthrough → build_consent_required → secret resolution
        // fails on an empty MockSecretsStore → no consent link → Unavailable.
        assert_eq!(result_tag(&results[0].result), "Unavailable");
    }

    #[tokio::test]
    async fn test_elicit_with_capability_no_sse_falls_back_per_policy() {
        // ConsentMode::Elicit + session_id + client DID advertise elicitation
        // capability, but NO SSE stream is registered for the session, so
        // send() returns false. With fallback = Fail → Unavailable.
        let session_id = "session-elicit-no-sse";
        crate::mcp::elicitation::global_capability_registry()
            .record(
                "ch-1",
                session_id,
                crate::mcp::elicitation::McpClientCapabilities {
                    elicitation: true,
                    sampling: false,
                    roots: false,
                },
            )
            .await;

        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets = empty_secrets();
        let bindings = vec![elicit_binding("cp-1", crate::config::types::ElicitFallback::Fail)];

        let ctx = DelegationAuditContext {
            mcp_session_id: Some(session_id.to_string()),
            ..Default::default()
        };

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(None, None),
            Some(&ctx),
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        // With an empty MockSecretsStore the consent link is not minted before we
        // ever attempt SSE delivery, so try_elicit_flow returns None and the
        // caller falls through to build_consent_required, which also fails
        // on secrets → Unavailable.
        assert_eq!(result_tag(&results[0].result), "Unavailable");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ProviderUnavailable);
    }

    /// No consent link is minted for a provider whose redirect URI another
    /// provider has: the start page would refuse it, so the binding is
    /// unavailable at once.
    #[tokio::test]
    async fn a_provider_sharing_its_redirect_uri_mints_no_consent_link() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = crate::secrets::FilesystemSecretsStore::new_async(
            directory
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        secrets
            .create(
                serde_json::from_value(serde_json::json!({
                    "name": "Client id", "secret_id": "CLIENT_ID", "value": "client-id"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let secrets: Arc<dyn SecretsStore> = Arc::new(secrets);
        let provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2AuthorizationCode);
        let mut other_tenant = provider.clone();
        other_tenant.id = "cp-1-tenant-b".to_string();
        other_tenant.tenant_id = Some("tenant-b".to_string());
        let resolve = |providers: Arc<MockProviderStore>| {
            let secrets = secrets.clone();
            async move {
                resolve_delegation_credentials(
                    &[elicit_binding("cp-1", crate::config::types::ElicitFallback::OnDemand)],
                    "sha256:user1",
                    "did:web:agent.example",
                    "ch-1",
                    crate::tenancy::SurfaceTenancy::configured(None),
                    None,
                    &(MockVaultStore::new(VaultLookupResult::NotFound) as Arc<dyn DelegationVaultStorage>),
                    &(providers as Arc<dyn CredentialProviderStorage>),
                    &secrets,
                    "https://gw.example.com",
                    false,
                    access_point(None, None),
                    None,
                    None,
                )
                .await
            }
        };

        let alone = resolve(MockProviderStore::with_stored(provider.clone())).await;
        assert_start_url(&alone[0].result);

        let shared = resolve(Arc::new(MockProviderStore {
            providers: [(provider.id.clone(), provider), (other_tenant.id.clone(), other_tenant)].into(),
        }))
        .await;
        assert_eq!(result_tag(&shared[0].result), "Unavailable");
        assert_eq!(shared[0].action.outcome, DelegationActionOutcome::ProviderUnavailable);
    }

    /// The start state a consent link minted for `caller` seals.
    async fn minted_start_state(
        provider: &CredentialProvider,
        caller: Option<&AuthenticatedIdentity>,
        user_identity_hash: &str,
        strategies: Option<&dyn JwtVerificationStrategyStorage>,
    ) -> crate::delegation_vault::OAuthState {
        let result = consent_lookup(provider, caller, user_identity_hash, strategies).await;
        let DelegationLookupResult::ConsentRequired { authorization_url, .. } = &result else {
            panic!("expected a consent result, got {}", result_tag(&result));
        };
        let state = url::Url::parse(authorization_url)
            .unwrap()
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        crate::delegation_vault::oauth::decode_start_state(&state).unwrap()
    }

    async fn consent_lookup(
        provider: &CredentialProvider,
        caller: Option<&AuthenticatedIdentity>,
        user_identity_hash: &str,
        strategies: Option<&dyn JwtVerificationStrategyStorage>,
    ) -> DelegationLookupResult {
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        let results = resolve_delegation_credentials(
            &[make_binding(&provider.id)],
            user_identity_hash,
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(MockVaultStore::new(VaultLookupResult::NotFound) as Arc<dyn DelegationVaultStorage>),
            &(MockProviderStore::with_stored(provider.clone()) as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(caller, strategies),
            None,
            None,
        )
        .await;
        results
            .into_iter()
            .next()
            .unwrap()
            .result
    }

    /// A consent link confirms its caller only when the provider's
    /// `consent_confirmation` strategy recomputes the caller's vault key. A
    /// caller the setting does not cover gets the link the provider mints
    /// without the setting; a setting that confirms no caller mints no link.
    #[tokio::test]
    async fn a_consent_link_confirms_only_a_caller_its_strategy_recomputes() {
        use crate::delegation_vault::{ConsentConfirmBinding, ConsentStage, OAuthState};
        use crate::jwt_bearer::models::{JwksSource, JwtVerificationStrategy};
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let directory = tempfile::tempdir().unwrap();
        let store = crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(
            directory
                .path()
                .join("strategies"),
        )
        .await
        .unwrap();
        let create = |issuer: &str, tenant_id: Option<&str>| JwtVerificationStrategy {
            id: String::new(),
            tenant_id: tenant_id.map(String::from),
            name: "Callers".to_string(),
            expected_issuer: issuer.to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: format!("{issuer}/jwks"),
            },
            principal_claim: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let issuer = "https://idp.example";
        let entra = "https://login.microsoftonline.com/tenant/v2.0";
        let strategy = store
            .create(create(issuer, None))
            .await
            .unwrap();
        let other_tenant = store
            .create(create(issuer, Some("tenant-b")))
            .await
            .unwrap();
        let entra_by_sub = store
            .create(create(entra, None))
            .await
            .unwrap();
        let confirming = |strategy_id: &str| {
            let mut provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2AuthorizationCode);
            provider.consent_confirmation = Some(
                serde_json::from_value(serde_json::json!({
                    "client_id_secret_ref": "LOGIN_CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET",
                    "authorization_endpoint": "https://idp.example/authorize",
                    "token_endpoint": "https://idp.example/token",
                    "jwt_verification_strategy_id": strategy_id
                }))
                .unwrap(),
            );
            provider
        };
        let without_setting = make_credential_provider("cp-1", CredentialProviderType::OAuth2AuthorizationCode);
        let jwt = |iss: &str, principal_claim: &str| AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            principal_claim: principal_claim.to_string(),
            claims: serde_json::json!({"iss": iss, principal_claim: "alice"}),
            strategy_id: Some(strategy.id.clone()),
            verification: Default::default(),
        };
        let alice = jwt(issuer, "sub");
        let alice_hash = alice
            .principal_hash(None)
            .unwrap();

        let confirmed = minted_start_state(&confirming(&strategy.id), Some(&alice), &alice_hash, Some(&store)).await;
        assert_eq!(
            confirmed.stage,
            Some(ConsentStage::ConfirmStart(ConsentConfirmBinding {
                strategy_id: strategy.id.clone(),
                strategy_digest: strategy
                    .verification_digest()
                    .unwrap(),
                tenant_id: None,
            }))
        );
        assert_eq!(confirmed.user_identity_hash, alice_hash);

        let api_key = AuthenticatedIdentity::ApiKey {
            key_name: "key".to_string(),
            provider_agent_id: None,
        };
        let api_key_hash = api_key
            .principal_hash(None)
            .unwrap();
        let other_issuer = jwt("https://other.example", "sub");
        let other_claim = jwt(issuer, "email");
        let entra_alice = jwt(entra, "sub");
        let hash = |identity: &AuthenticatedIdentity| {
            identity
                .principal_hash(None)
                .unwrap()
        };
        let unconfirmed: [(&str, CredentialProvider, Option<&AuthenticatedIdentity>, String); 6] = [
            ("an API key caller", confirming(&strategy.id), Some(&api_key), api_key_hash.clone()),
            ("no caller", confirming(&strategy.id), None, "sha256:user1".to_string()),
            ("another issuer", confirming(&strategy.id), Some(&other_issuer), hash(&other_issuer)),
            ("another principal claim", confirming(&strategy.id), Some(&other_claim), hash(&other_claim)),
            ("another vault key", confirming(&strategy.id), Some(&alice), "sha256:someone-else".to_string()),
            ("an API key caller of a deleted strategy", confirming("gone"), Some(&api_key), api_key_hash.clone()),
        ];
        let as_minted_today = |state: OAuthState| OAuthState {
            nonce: String::new(),
            expires_at: chrono::DateTime::<Utc>::UNIX_EPOCH,
            ..state
        };
        for (case, provider, caller, user_hash) in &unconfirmed {
            let minted = minted_start_state(provider, *caller, user_hash, Some(&store)).await;
            let today = minted_start_state(&without_setting, *caller, user_hash, Some(&store)).await;
            assert_eq!(minted.stage, None, "{case}");
            assert!(as_minted_today(minted) == as_minted_today(today), "{case}");
        }

        let confirms_nobody: [(&str, CredentialProvider, &AuthenticatedIdentity, String, bool); 4] = [
            ("a deleted strategy", confirming("gone"), &alice, alice_hash.clone(), true),
            ("a strategy of another tenant", confirming(&other_tenant.id), &alice, alice_hash.clone(), true),
            (
                "an Entra strategy naming callers by sub",
                confirming(&entra_by_sub.id),
                &entra_alice,
                hash(&entra_alice),
                true,
            ),
            ("no strategy store", confirming(&strategy.id), &alice, alice_hash.clone(), false),
        ];
        for (case, provider, caller, user_hash, with_store) in &confirms_nobody {
            let strategies = with_store.then_some(&store as &dyn JwtVerificationStrategyStorage);
            let refused = consent_lookup(provider, Some(*caller), user_hash, strategies).await;
            assert!(matches!(refused, DelegationLookupResult::Unavailable), "{case}: {}", result_tag(&refused));
        }

        crate::identity::credential_identity::configure_pepper_for_tests(false);
        let refused = consent_lookup(&confirming(&strategy.id), Some(&alice), &alice_hash, Some(&store)).await;
        assert!(
            matches!(refused, DelegationLookupResult::Unavailable),
            "without a configured pepper: {}",
            result_tag(&refused)
        );
        let today = minted_start_state(&without_setting, Some(&alice), &alice_hash, Some(&store)).await;
        assert_eq!(today.stage, None, "a provider without the setting still mints without a pepper");
        let minted = minted_start_state(&confirming(&strategy.id), Some(&api_key), &api_key_hash, Some(&store)).await;
        let today = minted_start_state(&without_setting, Some(&api_key), &api_key_hash, Some(&store)).await;
        assert_eq!(minted.stage, None, "an API key caller without a configured pepper");
        assert!(
            as_minted_today(minted) == as_minted_today(today),
            "an API key caller is minted a link as before without a configured pepper"
        );
    }

    /// A strategy store whose every read fails.
    struct UnreadableStrategies;

    #[async_trait]
    impl JwtVerificationStrategyStorage for UnreadableStrategies {
        async fn create(
            &self,
            _strategy: crate::jwt_bearer::models::JwtVerificationStrategy,
        ) -> Result<crate::jwt_bearer::models::JwtVerificationStrategy> {
            anyhow::bail!("strategy store unavailable")
        }
        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<crate::jwt_bearer::models::JwtVerificationStrategy>> {
            anyhow::bail!("strategy store unavailable")
        }
        async fn list(&self) -> Result<Vec<crate::jwt_bearer::models::JwtVerificationStrategy>> {
            anyhow::bail!("strategy store unavailable")
        }
        async fn update(
            &self,
            _strategy: crate::jwt_bearer::models::JwtVerificationStrategy,
        ) -> Result<crate::jwt_bearer::models::JwtVerificationStrategy> {
            anyhow::bail!("strategy store unavailable")
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<()> {
            anyhow::bail!("strategy store unavailable")
        }
    }

    /// A store holding one strategy for `https://idp.example` under
    /// `tenant_id`, a provider of `tenant_id` whose `consent_confirmation`
    /// names it, and Alice, a caller that strategy verified.
    async fn confirming_fixture(
        directory: &std::path::Path,
        tenant_id: Option<&str>,
    ) -> (
        crate::jwt_bearer::FileSystemJwtVerificationStrategyStore,
        crate::jwt_bearer::models::JwtVerificationStrategy,
        CredentialProvider,
        AuthenticatedIdentity,
    ) {
        let store = crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(directory.join("strategies"))
            .await
            .unwrap();
        let strategy = store
            .create(crate::jwt_bearer::models::JwtVerificationStrategy {
                id: String::new(),
                tenant_id: tenant_id.map(String::from),
                name: "Callers".to_string(),
                expected_issuer: "https://idp.example".to_string(),
                jwks_source: crate::jwt_bearer::models::JwksSource::Remote {
                    jwks_uri: "https://idp.example/jwks".to_string(),
                },
                principal_claim: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .await
            .unwrap();
        let mut provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2AuthorizationCode);
        provider.tenant_id = tenant_id.map(String::from);
        provider.consent_confirmation = Some(
            serde_json::from_value(serde_json::json!({
                "client_id_secret_ref": "LOGIN_CLIENT_ID", "client_secret_secret_ref": "CLIENT_SECRET",
                "authorization_endpoint": "https://idp.example/authorize",
                "token_endpoint": "https://idp.example/token",
                "jwt_verification_strategy_id": strategy.id
            }))
            .unwrap(),
        );
        let alice = AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            principal_claim: "sub".to_string(),
            claims: serde_json::json!({"iss": "https://idp.example", "sub": "alice"}),
            strategy_id: Some(strategy.id.clone()),
            verification: Default::default(),
        };
        (store, strategy, provider, alice)
    }

    /// Resolve `provider`'s binding for `caller` on a surface of `tenant_id`,
    /// with the vault answering `vault`.
    async fn resolve_for_caller(
        provider: &CredentialProvider,
        caller: &AuthenticatedIdentity,
        tenant_id: Option<&str>,
        strategies: &dyn JwtVerificationStrategyStorage,
        vault: VaultLookupResult,
    ) -> DelegationResolution {
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        resolve_delegation_credentials(
            &[make_binding(&provider.id)],
            &caller
                .principal_hash(tenant_id)
                .unwrap(),
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(tenant_id),
            None,
            &(MockVaultStore::new(vault) as Arc<dyn DelegationVaultStorage>),
            &(MockProviderStore::with_stored(provider.clone()) as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(Some(caller), Some(strategies)),
            None,
            None,
        )
        .await
        .remove(0)
    }

    /// The stage of the start state a consent result's link seals.
    fn start_stage(result: &DelegationLookupResult) -> Option<crate::delegation_vault::ConsentStage> {
        let DelegationLookupResult::ConsentRequired { authorization_url, .. } = result else {
            panic!("expected a consent result, got {}", result_tag(result));
        };
        let state = url::Url::parse(authorization_url)
            .unwrap()
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        crate::delegation_vault::oauth::decode_start_state(&state)
            .unwrap()
            .stage
    }

    /// The consent link that follows a failed refresh confirms its caller like
    /// the one minted when the vault holds nothing.
    #[tokio::test]
    async fn the_consent_link_after_a_failed_refresh_confirms_its_caller() {
        use crate::delegation_vault::{ConsentConfirmBinding, ConsentStage};
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let directory = tempfile::tempdir().unwrap();
        let (store, strategy, mut provider, alice) = confirming_fixture(directory.path(), None).await;
        let app = axum::Router::new().fallback(axum::routing::post(|| async {
            (axum::http::StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "invalid_grant"})))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let token_endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let mut server = tokio::task::JoinSet::new();
        server.spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        provider.token_endpoint = Some(token_endpoint.clone());
        let egress = oauth::TokenEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: Some(token_endpoint),
            policy: Default::default(),
        };

        let refreshed = egress
            .scope(resolve_for_caller(
                &provider,
                &alice,
                None,
                &store,
                VaultLookupResult::ExpiredRefreshable(make_token(true, true)),
            ))
            .await;

        assert_eq!(refreshed.action.outcome, DelegationActionOutcome::RefreshFailed);
        assert_eq!(
            start_stage(&refreshed.result),
            Some(ConsentStage::ConfirmStart(ConsentConfirmBinding {
                strategy_id: strategy.id.clone(),
                strategy_digest: strategy
                    .verification_digest()
                    .unwrap(),
                tenant_id: None,
            }))
        );
    }

    /// A strategy that cannot be read refuses the consent link of a provider
    /// with `consent_confirmation` rather than minting one that does not
    /// confirm its caller; a provider without the setting never reads it.
    #[tokio::test]
    async fn an_unreadable_strategy_refuses_only_a_confirming_consent_link() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let directory = tempfile::tempdir().unwrap();
        let (_store, _strategy, provider, alice) = confirming_fixture(directory.path(), None).await;

        let refused =
            resolve_for_caller(&provider, &alice, None, &UnreadableStrategies, VaultLookupResult::NotFound).await;
        assert_eq!(refused.action.outcome, DelegationActionOutcome::ProviderUnavailable);
        assert!(matches!(refused.result, DelegationLookupResult::Unavailable), "{}", result_tag(&refused.result));

        let without_setting = CredentialProvider {
            consent_confirmation: None,
            ..provider
        };
        let minted =
            resolve_for_caller(&without_setting, &alice, None, &UnreadableStrategies, VaultLookupResult::NotFound)
                .await;
        assert_eq!(minted.action.outcome, DelegationActionOutcome::ConsentRequired);
        assert_eq!(start_stage(&minted.result), None);
    }

    /// A provider whose consent confirmation sets `require` mints no consent
    /// link for a caller it cannot confirm, and still confirms one it can.
    #[tokio::test]
    async fn a_provider_requiring_confirmation_refuses_a_caller_it_cannot_confirm() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let directory = tempfile::tempdir().unwrap();
        let (store, _strategy, mut provider, alice) = confirming_fixture(directory.path(), None).await;
        provider
            .consent_confirmation
            .as_mut()
            .unwrap()
            .require = true;
        let api_key = AuthenticatedIdentity::ApiKey {
            key_name: "key".to_string(),
            provider_agent_id: None,
        };
        let api_key_hash = api_key
            .principal_hash(None)
            .unwrap();
        let refused = consent_lookup(&provider, Some(&api_key), &api_key_hash, Some(&store)).await;
        assert!(matches!(refused, DelegationLookupResult::Unavailable), "{}", result_tag(&refused));

        let alice_hash = alice
            .principal_hash(None)
            .unwrap();
        let refused = consent_lookup(&provider, Some(&alice), "sha256:someone-else", Some(&store)).await;
        assert!(matches!(refused, DelegationLookupResult::Unavailable), "{}", result_tag(&refused));
        let confirmed = minted_start_state(&provider, Some(&alice), &alice_hash, Some(&store)).await;
        assert!(matches!(confirmed.stage, Some(crate::delegation_vault::ConsentStage::ConfirmStart(_))));
    }

    /// On a surface of a tenant the caller's vault key is computed under that
    /// tenant, and the confirm binding records it.
    #[tokio::test]
    async fn a_tenant_surfaces_consent_link_confirms_its_caller_under_its_tenant() {
        use crate::delegation_vault::ConsentStage;
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let directory = tempfile::tempdir().unwrap();
        let (store, strategy, provider, alice) = confirming_fixture(directory.path(), Some("tenant-a")).await;

        let minted = resolve_for_caller(&provider, &alice, Some("tenant-a"), &store, VaultLookupResult::NotFound).await;

        assert!(
            matches!(
                start_stage(&minted.result),
                Some(ConsentStage::ConfirmStart(binding))
                    if binding.strategy_id == strategy.id && binding.tenant_id.as_deref() == Some("tenant-a")
            ),
            "the start state confirms the caller under tenant-a"
        );
    }

    /// Transit and Fabric consent is not confirmed: the caller a confirming
    /// strategy verified gets a link that does not confirm them there.
    #[tokio::test]
    async fn a_transit_or_fabric_consent_link_does_not_confirm_its_caller() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let directory = tempfile::tempdir().unwrap();
        let (_store, _strategy, provider, alice) = confirming_fixture(directory.path(), None).await;
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore::default());
        for via_fabric in [false, true] {
            let resolved = resolve_delegation_credentials(
                &[make_binding(&provider.id)],
                &alice
                    .principal_hash(None)
                    .unwrap(),
                "did:web:agent.example",
                "ch-1",
                crate::tenancy::SurfaceTenancy::configured(None),
                None,
                &(MockVaultStore::new(VaultLookupResult::NotFound) as Arc<dyn DelegationVaultStorage>),
                &(MockProviderStore::with_stored(provider.clone()) as Arc<dyn CredentialProviderStorage>),
                &secrets,
                "https://gw.example.com",
                via_fabric,
                ConsentCaller::TransitOrFabric,
                None,
                None,
            )
            .await;
            assert_eq!(resolved[0].action.outcome, DelegationActionOutcome::ConsentRequired, "via_fabric {via_fabric}");
            assert_eq!(start_stage(&resolved[0].result), None, "via_fabric {via_fabric}");
        }
    }

    /// An `iss` that differs from the strategy's only by a trailing slash is
    /// another issuer, so its caller gets a link that does not confirm them.
    #[tokio::test]
    async fn a_caller_whose_issuer_has_a_trailing_slash_is_not_confirmed() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let directory = tempfile::tempdir().unwrap();
        let (store, _strategy, provider, _alice) = confirming_fixture(directory.path(), None).await;
        let slashed = AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            principal_claim: "sub".to_string(),
            claims: serde_json::json!({"iss": "https://idp.example/", "sub": "alice"}),
            strategy_id: None,
            verification: Default::default(),
        };

        let minted = resolve_for_caller(&provider, &slashed, None, &store, VaultLookupResult::NotFound).await;

        assert_eq!(minted.action.outcome, DelegationActionOutcome::ConsentRequired);
        assert_eq!(start_stage(&minted.result), None);
    }

    /// A consent result carries the gateway's consent start page for the
    /// provider, with a sealed start state, never the vendor's URL.
    fn assert_start_url(result: &DelegationLookupResult) {
        let DelegationLookupResult::ConsentRequired { authorization_url, .. } = result else {
            panic!("expected a consent result, got {}", result_tag(result));
        };
        let url = url::Url::parse(authorization_url).unwrap();
        assert_eq!(
            url.origin()
                .ascii_serialization(),
            "https://gw.example.com",
            "{authorization_url}"
        );
        assert_eq!(url.path(), "/oauth/callback/test-cp-1/start", "{authorization_url}");
        let state = url
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        let state = crate::delegation_vault::oauth::decode_start_state(&state).unwrap();
        assert_eq!(
            (state.provider_id.as_str(), state.scopes.as_slice()),
            ("test-cp-1", ["repo".to_string()].as_slice())
        );
    }

    /// The consent start page an elicitation carries confirms its caller like
    /// any other consent link.
    #[tokio::test]
    async fn an_elicitation_carries_a_start_page_that_confirms_its_caller() {
        use crate::delegation_vault::ConsentStage;
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let directory = tempfile::tempdir().unwrap();
        let store = crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(
            directory
                .path()
                .join("strategies"),
        )
        .await
        .unwrap();
        let strategy = store
            .create(crate::jwt_bearer::models::JwtVerificationStrategy {
                id: String::new(),
                tenant_id: None,
                name: "Callers".to_string(),
                expected_issuer: "https://idp.example".to_string(),
                jwks_source: crate::jwt_bearer::models::JwksSource::Remote {
                    jwks_uri: "https://idp.example/jwks".to_string(),
                },
                principal_claim: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .await
            .unwrap();
        let mut provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2AuthorizationCode);
        provider.consent_confirmation = Some(
            serde_json::from_value(serde_json::json!({
                "client_id_secret_ref": "LOGIN_CLIENT_ID", "client_secret_secret_ref": "CLIENT_ID",
                "authorization_endpoint": "https://idp.example/authorize",
                "token_endpoint": "https://idp.example/token",
                "jwt_verification_strategy_id": strategy.id
            }))
            .unwrap(),
        );
        let alice = AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            principal_claim: "sub".to_string(),
            claims: serde_json::json!({"iss": "https://idp.example", "sub": "alice"}),
            strategy_id: Some(strategy.id.clone()),
            verification: Default::default(),
        };
        let (results, elicitation) = resolve_with_elicitation_reply_for(
            "session-confirming",
            crate::config::types::ElicitFallback::Fail,
            Some(crate::mcp::elicitation::ElicitationResult::Accept {
                content: serde_json::Value::Null,
            }),
            Some((&provider, &alice, &store)),
        )
        .await;

        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ElicitationAcceptedPending);
        let message = elicitation["params"]["message"]
            .as_str()
            .unwrap();
        let start_url = &message[message
            .find("https://gw.example.com/")
            .unwrap()..];
        let state = url::Url::parse(start_url)
            .unwrap()
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        let start = crate::delegation_vault::oauth::decode_start_state(&state).unwrap();
        assert!(
            matches!(&start.stage, Some(ConsentStage::ConfirmStart(binding)) if binding.strategy_id == strategy.id),
            "the start state confirms the caller"
        );
    }

    /// An accepted elicitation asks the person to open the gateway's consent
    /// start page, and the pending answer that follows carries the same page.
    #[tokio::test]
    async fn an_elicitation_and_its_pending_answer_carry_the_consent_start_page() {
        let (results, elicitation) = resolve_with_elicitation_reply(
            "session-accepted",
            crate::config::types::ElicitFallback::Fail,
            Some(crate::mcp::elicitation::ElicitationResult::Accept {
                content: serde_json::Value::Null,
            }),
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ElicitationAcceptedPending);
        assert_start_url(&results[0].result);
        let DelegationLookupResult::ConsentRequired { authorization_url, .. } = &results[0].result else {
            unreachable!()
        };
        let message = elicitation["params"]["message"]
            .as_str()
            .unwrap();
        assert!(message.ends_with(authorization_url.as_str()), "{message}");
    }

    /// Resolves an elicit binding for a client that advertises elicitation and
    /// holds an open SSE stream, answering the `elicitation/create` request with
    /// `reply`, or never answering when `reply` is `None`.
    async fn resolve_with_elicitation_reply(
        session_id: &str,
        fallback: crate::config::types::ElicitFallback,
        reply: Option<crate::mcp::elicitation::ElicitationResult>,
    ) -> (Vec<DelegationResolution>, serde_json::Value) {
        resolve_with_elicitation_reply_for(session_id, fallback, reply, None).await
    }

    /// [`resolve_with_elicitation_reply`] for `caller`, under a provider and
    /// strategies of its own when given, rather than `cp-1` and none.
    async fn resolve_with_elicitation_reply_for(
        session_id: &str,
        fallback: crate::config::types::ElicitFallback,
        reply: Option<crate::mcp::elicitation::ElicitationResult>,
        caller: Option<(&CredentialProvider, &AuthenticatedIdentity, &dyn JwtVerificationStrategyStorage)>,
    ) -> (Vec<DelegationResolution>, serde_json::Value) {
        use axum::response::IntoResponse;
        use http_body_util::BodyExt;

        crate::mcp::elicitation::global_capability_registry()
            .record(
                "ch-1",
                session_id,
                crate::mcp::elicitation::McpClientCapabilities {
                    elicitation: true,
                    sampling: false,
                    roots: false,
                },
            )
            .await;
        let stream = crate::mcp::streamable_sse::global_streamable_session_registry()
            .register("ch-1", session_id)
            .await
            .unwrap();
        let client_session = session_id.to_string();
        let (sent, elicitation) = tokio::sync::oneshot::channel();
        let client = tokio::spawn(async move {
            let mut body = axum::response::Sse::new(tokio_stream::wrappers::ReceiverStream::new(stream))
                .into_response()
                .into_body();
            let frame = body
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap();
            let event = String::from_utf8(frame.to_vec()).unwrap();
            let request: serde_json::Value = serde_json::from_str(
                event
                    .trim()
                    .strip_prefix("data: ")
                    .unwrap(),
            )
            .unwrap();
            sent.send(request.clone())
                .unwrap();
            match reply {
                Some(reply) => {
                    crate::mcp::elicitation::global_pending_elicitation_registry()
                        .resolve(
                            "ch-1",
                            &client_session,
                            request["id"]
                                .as_str()
                                .unwrap(),
                            reply,
                        )
                        .await;
                }
                None => std::future::pending::<()>().await,
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let secrets = crate::secrets::FilesystemSecretsStore::new_async(
            directory
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        secrets
            .create(
                serde_json::from_value(serde_json::json!({
                    "name": "Client id", "secret_id": "CLIENT_ID", "value": "client-id"
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let secrets: Arc<dyn SecretsStore> = Arc::new(secrets);
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = match caller {
            Some((provider, ..)) => MockProviderStore::with_stored(provider.clone()),
            None => MockProviderStore::with_oauth_provider("cp-1"),
        };
        let user_hash = caller
            .and_then(|(_, identity, _)| identity.principal_hash(None))
            .unwrap_or_else(|| "sha256:user1".to_string());
        let ctx = DelegationAuditContext {
            mcp_session_id: Some(session_id.to_string()),
            ..Default::default()
        };

        let results = resolve_delegation_credentials(
            &[elicit_binding("cp-1", fallback)],
            &user_hash,
            "did:web:agent.example",
            "ch-1",
            crate::tenancy::SurfaceTenancy::configured(None),
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            access_point(caller.map(|(_, identity, _)| identity), caller.map(|(.., strategies)| strategies)),
            Some(&ctx),
            None,
        )
        .await;
        client.abort();
        crate::mcp::streamable_sse::global_streamable_session_registry()
            .drop_session("ch-1", session_id)
            .await;
        (results, elicitation.await.unwrap())
    }

    #[tokio::test]
    async fn a_declined_or_cancelled_elicitation_refuses_the_request() {
        use crate::mcp::elicitation::ElicitationResult;

        for (session_id, reply, outcome) in [
            ("session-declined", ElicitationResult::Decline, DelegationActionOutcome::ElicitationDeclined),
            ("session-cancelled", ElicitationResult::Cancel, DelegationActionOutcome::ElicitationCancelled),
        ] {
            for fallback in [crate::config::types::ElicitFallback::Fail, crate::config::types::ElicitFallback::OnDemand]
            {
                let (results, _) =
                    resolve_with_elicitation_reply(session_id, fallback.clone(), Some(reply.clone())).await;

                assert_eq!(results.len(), 1);
                assert_eq!(result_tag(&results[0].result), "Unavailable", "{session_id} {fallback:?}");
                assert_eq!(results[0].action.outcome, outcome, "{session_id} {fallback:?}");
            }
        }
    }

    #[tokio::test]
    async fn an_unanswered_elicitation_refuses_the_request_when_it_times_out() {
        let (results, _) =
            resolve_with_elicitation_reply("session-timed-out", crate::config::types::ElicitFallback::Fail, None).await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "Unavailable");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ElicitationTimedOut);
    }

    // ── DelegationAction serialization ───────────────────────────────

    #[test]
    fn delegation_action_outcome_serializes_snake_case() {
        let outcomes_and_strs = [
            (DelegationActionOutcome::TokenInjected, "token_injected"),
            (DelegationActionOutcome::TokenRefreshed, "token_refreshed"),
            (DelegationActionOutcome::ConsentRequired, "consent_required"),
            (DelegationActionOutcome::ElicitationAcceptedPending, "elicitation_accepted_pending"),
            (DelegationActionOutcome::ElicitationDeclined, "elicitation_declined"),
            (DelegationActionOutcome::ElicitationCancelled, "elicitation_cancelled"),
            (DelegationActionOutcome::ElicitationTimedOut, "elicitation_timed_out"),
            (DelegationActionOutcome::ElicitationUnsupported, "elicitation_unsupported"),
            (DelegationActionOutcome::NotApplicable, "not_applicable"),
            (DelegationActionOutcome::ProviderUnavailable, "provider_unavailable"),
            (DelegationActionOutcome::RefreshFailed, "refresh_failed"),
            (DelegationActionOutcome::LookupError, "lookup_error"),
            (DelegationActionOutcome::ApiKeyResolutionFailed, "api_key_resolution_failed"),
            (DelegationActionOutcome::ClientCredentialsFailed, "client_credentials_failed"),
            (DelegationActionOutcome::JwtBearerFailed, "jwt_bearer_failed"),
            (DelegationActionOutcome::ClientCredentialsJwtAuthFailed, "client_credentials_jwt_auth_failed"),
        ];
        for (outcome, expected) in outcomes_and_strs {
            let v = serde_json::to_value(outcome).unwrap();
            assert_eq!(
                v,
                serde_json::Value::String(expected.to_string()),
                "{:?} should serialize to {}",
                outcome,
                expected
            );
        }
    }

    #[test]
    fn delegation_action_provider_name_omitted_when_none() {
        let binding = make_binding("cp-x");
        let r = DelegationResolution::new(
            &binding,
            None,
            DelegationActionOutcome::NotApplicable,
            Some("provider_not_found".to_string()),
            DelegationLookupResult::NotApplicable,
        );
        let v = serde_json::to_value(&r.action).unwrap();
        assert!(
            v.get("providerName")
                .is_none()
        );
    }

    // ── delegation_actions_value (workload-binding VP summary) ────────

    #[test]
    fn delegation_actions_value_returns_none_for_empty_input() {
        assert!(delegation_actions_value(&[]).is_none());
    }

    #[test]
    fn delegation_actions_value_serializes_each_binding_with_outcome() {
        let bindings = [make_binding("cp-1"), make_binding("cp-2")];
        let resolutions = vec![
            DelegationResolution::new(
                &bindings[0],
                Some("GitHub"),
                DelegationActionOutcome::TokenInjected,
                None,
                DelegationLookupResult::Inject(vec![ResolvedCredentialInjection::Header {
                    name: "Authorization".to_string(),
                    value: "Bearer x".to_string(),
                }]),
            ),
            DelegationResolution::new(
                &bindings[1],
                Some("Slack"),
                DelegationActionOutcome::ElicitationDeclined,
                Some("elicit_id=abc".to_string()),
                DelegationLookupResult::NotApplicable,
            ),
        ];

        let v = delegation_actions_value(&resolutions).expect("Some(value) for non-empty input");
        let arr = v.as_array().expect("array");
        assert_eq!(arr.len(), 2);

        // First entry: token_injected, no detail, GitHub provider
        assert_eq!(arr[0]["providerId"], "cp-1");
        assert_eq!(arr[0]["providerName"], "GitHub");
        assert_eq!(arr[0]["outcome"], "token_injected");
        assert!(arr[0].get("detail").is_none(), "detail must be omitted when None");

        // Second entry: elicitation_declined with detail, Slack provider
        assert_eq!(arr[1]["providerId"], "cp-2");
        assert_eq!(arr[1]["providerName"], "Slack");
        assert_eq!(arr[1]["outcome"], "elicitation_declined");
        assert_eq!(arr[1]["detail"], "elicit_id=abc");
    }
}
