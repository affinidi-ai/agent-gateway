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
use crate::delegation_vault::gateway_token::{GATEWAY_GRANT_BACKOFF, GrantEgress, ProviderSecrets, grant_label};
use crate::delegation_vault::{DelegationToken, VaultLookupResult, oauth, storage::DelegationVaultStorage};
use crate::secrets::SecretsStore;
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

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
    ConsentRequired {
        authorization_url: String,
        provider_name: String,
        scopes: Vec<String>,
    },
    /// Binding doesn't apply to this request (e.g. tool filter)
    NotApplicable,
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
    /// record cannot be read, it is outside the surface's tenant, it would send an
    /// `oauth2_jwt_bearer` token on a leg that may not carry it, or no authorization
    /// URL can be built from it. The request is refused rather than forwarded
    /// without the credential.
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

/// The prefix of the vault identity under which gateway tokens of legacy bindings are cached.
const GATEWAY_GRANT_USER_HASH: &str = "__client_credentials__";

/// The vault identity of a legacy gateway token for one scope set, so bindings of one
/// provider with different scopes never share a token. Scope order and repeats are ignored.
pub(crate) fn gateway_grant_user_hash(scopes: &[String]) -> String {
    use sha2::Digest;
    let mut scopes: Vec<&str> = scopes
        .iter()
        .map(String::as_str)
        .collect();
    scopes.sort_unstable();
    scopes.dedup();
    format!("{GATEWAY_GRANT_USER_HASH}:{}", hex::encode(sha2::Sha256::digest(scopes.join(" "))))
}

/// The binding a gateway token is injected for, with its audit context.
struct GatewayTokenTarget<'a> {
    binding: &'a OutboundCredentialBinding,
    provider: &'a CredentialProvider,
    agent_did: &'a str,
    channel_id: &'a str,
    via_fabric: bool,
    audit_ctx: Option<&'a DelegationAuditContext>,
    surface_variant: Option<&'a str>,
}

impl GatewayTokenTarget<'_> {
    fn scopes(&self) -> &[String] {
        if self.binding.scopes.is_empty() {
            &self.provider.default_scopes
        } else {
            &self.binding.scopes
        }
    }

    /// Injects the cached gateway token while it is outside its refresh margin, was
    /// requested after the provider's last change, and every secret its grant read is
    /// still at the version it read. Otherwise sends a new grant, falling back to a
    /// cached token that is still valid when the grant fails.
    async fn resolve(
        &self,
        vault_store: &Arc<dyn DelegationVaultStorage>,
        secrets_store: &Arc<dyn SecretsStore>,
        egress: &GrantEgress,
    ) -> DelegationResolution {
        let binding = self.binding;
        let provider = self.provider;
        let surface_variant = self.surface_variant;
        let grant_label = grant_label(&provider.provider_type);
        let effective_scopes = self.scopes();
        let user_hash = gateway_grant_user_hash(effective_scopes);
        let secrets = ProviderSecrets::new(secrets_store, provider);
        let cached = match vault_store
            .lookup(self.agent_did, &user_hash, &binding.credential_provider_id)
            .await
        {
            Ok(VaultLookupResult::Found(token))
                if token.consent_granted_at >= provider.updated_at
                    && secrets
                        .still_current(
                            token
                                .secret_versions
                                .as_deref(),
                        )
                        .await =>
            {
                Some(token)
            }
            Ok(
                VaultLookupResult::Found(token)
                | VaultLookupResult::ExpiredRefreshable(token)
                | VaultLookupResult::ExpiredNoRefresh(token),
            ) => {
                debug!(
                    target: "credential_delegation",
                    surface_variant,
                    token_id = %token.id,
                    "Gateway token is expired or predates a change to the provider or its secrets and will be replaced"
                );
                None
            }
            _ => None,
        };
        if let Some(token) = cached
            .as_ref()
            .filter(|token| !token.needs_refresh(Utc::now()))
        {
            if let Err(e) = vault_store
                .mark_used(&token.id)
                .await
            {
                warn!(
                    target: "credential_delegation",
                    surface_variant,
                    token_id = %token.id,
                    error = %e,
                    "Failed to mark gateway token as used"
                );
            }
            return self.inject(&user_hash, &token.id, &token.access_token, format!("{grant_label}_cached"));
        }

        let requested_at = Utc::now();
        let grant = GATEWAY_GRANT_BACKOFF
            .request(provider, effective_scopes, &secrets, egress)
            .await;
        match grant {
            Ok(token_response) => {
                info!(
                    target: "credential_delegation",
                    surface_variant,
                    surface_id = %self.channel_id,
                    provider_id = %binding.credential_provider_id,
                    grant = grant_label,
                    "Gateway token fetched — caching in vault"
                );
                let now = Utc::now();
                let delegation_token = DelegationToken {
                    id: Uuid::new_v4().to_string(),
                    agent_did: self.agent_did.to_string(),
                    user_identity_hash: user_hash.clone(),
                    credential_provider_id: binding
                        .credential_provider_id
                        .clone(),
                    provider_id: provider.provider_id.clone(),
                    access_token: token_response.access_token,
                    refresh_token: None,
                    token_type: token_response.token_type,
                    scopes: effective_scopes.to_vec(),
                    expires_at: token_response
                        .expires_in
                        .map(|secs| now + chrono::Duration::seconds(secs)),
                    delegation_vc: None,
                    consent_identity: None,
                    secret_versions: Some(secrets.versions_read()),
                    consent_granted_at: requested_at,
                    last_used_at: Some(now),
                    created_at: now,
                    updated_at: now,
                };
                match vault_store
                    .store(delegation_token)
                    .await
                {
                    Ok(stored) => {
                        self.inject(&user_hash, &stored.id, &stored.access_token, format!("{grant_label}_fresh"))
                    }
                    Err(error) => {
                        error!(
                            target: "credential_delegation",
                            surface_variant,
                            surface_id = %self.channel_id,
                            provider_id = %binding.credential_provider_id,
                            error = %error,
                            "Failed to store fresh gateway token in vault"
                        );
                        DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::ClientCredentialsFailed,
                            Some("vault_store_rejected".to_string()),
                            DelegationLookupResult::Unavailable,
                        )
                    }
                }
            }
            Err(error) => {
                warn!(
                    target: "credential_delegation",
                    surface_variant,
                    surface_id = %self.channel_id,
                    provider_id = %binding.credential_provider_id,
                    grant = grant_label,
                    category = error.category(),
                    "Gateway token fetch failed"
                );
                if let Some(token) = cached.filter(|token| token.is_provably_valid(Utc::now())) {
                    return self.inject(&user_hash, &token.id, &token.access_token, format!("{grant_label}_stale"));
                }
                let detail = format!("{grant_label}_{}", error.category());
                audit::emit("delegation_failed", || {
                    let mut evt = audit::audit_event(
                        DelegationAuditAction::DelegationFailed {
                            reason: error.delegation_failure_reason(),
                            provider_id: Some(
                                binding
                                    .credential_provider_id
                                    .clone(),
                            ),
                        },
                        Some(self.agent_did),
                        None,
                        Some(&binding.credential_provider_id),
                        Some(self.channel_id),
                    );
                    evt.via_fabric = self.via_fabric;
                    evt.detail = Some(detail.clone());
                    enrich_audit_event(&mut evt, self.audit_ctx, binding, Some(&provider.name));
                    evt.caller = Some(audit::gateway_caller_context());
                    evt
                });
                audit::emit("token_not_found", || {
                    let mut evt = audit::audit_event(
                        DelegationAuditAction::TokenNotFound,
                        Some(self.agent_did),
                        Some(&user_hash),
                        Some(&binding.credential_provider_id),
                        Some(self.channel_id),
                    );
                    evt.via_fabric = self.via_fabric;
                    evt.detail = Some(detail.clone());
                    enrich_audit_event(&mut evt, self.audit_ctx, binding, Some(&provider.name));
                    evt
                });
                DelegationResolution::new(
                    binding,
                    Some(&provider.name),
                    DelegationActionOutcome::ClientCredentialsFailed,
                    Some(detail),
                    DelegationLookupResult::Unavailable,
                )
            }
        }
    }

    fn inject(
        &self,
        user_hash: &str,
        token_id: &str,
        access_token: &str,
        detail: String,
    ) -> DelegationResolution {
        debug!(
            target: "credential_delegation",
            surface_variant = self.surface_variant,
            surface_id = %self.channel_id,
            provider_id = %self.binding.credential_provider_id,
            detail = %detail,
            "Injecting gateway token"
        );
        audit::emit("token_injected", || {
            let mut evt = audit::audit_event(
                DelegationAuditAction::TokenInjected,
                Some(self.agent_did),
                Some(user_hash),
                Some(
                    &self
                        .binding
                        .credential_provider_id,
                ),
                Some(self.channel_id),
            );
            evt.token_id = Some(token_id.to_string());
            evt.via_fabric = self.via_fabric;
            evt.detail = Some(detail.clone());
            enrich_audit_event(&mut evt, self.audit_ctx, self.binding, Some(&self.provider.name));
            evt
        });
        DelegationResolution::new(
            self.binding,
            Some(&self.provider.name),
            DelegationActionOutcome::TokenInjected,
            Some(detail),
            DelegationLookupResult::Inject(build_injection_headers(&self.binding.inject_as, access_token)),
        )
    }
}

/// Check all outbound credential bindings for a channel and return injection headers
/// or a consent_required signal.
///
/// # Arguments
/// * `bindings` — the channel's `outbound_credentials` configuration
/// * `user_identity_hash` — SHA-256 hash of the caller's identity claim
/// * `agent_did` — the DID of the agent this channel proxies to
/// * `channel_id` — for logging
/// * `mcp_tool_name` — if this is an MCP tool call, the tool name (for `Tools` requirement filter)
/// * `vault_store` — delegation vault storage
/// * `provider_store` — credential provider storage
/// * `secrets_store` — secrets storage (for refreshing tokens)
/// * `gateway_base_url` — for building OAuth authorization URLs
/// * `via_fabric` — true when this resolution is happening on the GW2 side of a fabric request
/// * `consent_principal` — the authenticated caller's consent principal, when this request
///   carries one. A vault record created by modern consent is released only to its own
///   principal; callers that cannot establish one (Transit, fabric) pass `None` and are
///   refused such records.
/// * `surface_tenant_id` — the surface's tenant. A binding whose provider is not usable by
///   that tenant ([`CredentialProvider::usable_by`]) is unavailable with detail
///   `provider_forbidden`.
/// * `jwt_bearer_leg_permitted` — whether this leg may carry the gateway's own token from an
///   `oauth2_jwt_bearer` provider
///   ([`permits_jwt_bearer_leg`](crate::proxy::target_credentials::permits_jwt_bearer_leg)).
///   When it may not, such a binding is unavailable with detail `jwt_bearer_leg_forbidden`.
/// * `client_credentials_leg_permitted` — whether this leg may carry the gateway's own token from
///   an `oauth2_client_credentials` provider
///   ([`permits_client_credentials_leg`](crate::proxy::target_credentials::permits_client_credentials_leg)).
///   When it may not, such a binding is unavailable with detail `client_credentials_leg_forbidden`.
pub async fn resolve_delegation_credentials(
    bindings: &[OutboundCredentialBinding],
    user_identity_hash: &str,
    agent_did: &str,
    channel_id: &str,
    mcp_tool_name: Option<&str>,
    vault_store: &Arc<dyn DelegationVaultStorage>,
    provider_store: &Arc<dyn CredentialProviderStorage>,
    secrets_store: &Arc<dyn SecretsStore>,
    gateway_base_url: &str,
    via_fabric: bool,
    audit_ctx: Option<&DelegationAuditContext>,
    consent_principal: Option<&str>,
    surface_tenant_id: Option<&str>,
    jwt_bearer_leg_permitted: bool,
    client_credentials_leg_permitted: bool,
) -> Vec<DelegationResolution> {
    let mut results: Vec<DelegationResolution> = Vec::new();
    let surface_variant = crate::observability::policy_audit::current_request_variant();
    let surface_variant = surface_variant.as_deref();

    for binding in bindings {
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

        if !provider.usable_by(surface_tenant_id) {
            warn!(
                target: "credential_delegation",
                surface_variant,
                surface_id = %channel_id,
                provider_id = %binding.credential_provider_id,
                "Credential provider is outside the surface's tenant - refusing the request"
            );
            results.push(DelegationResolution::new(
                binding,
                None,
                DelegationActionOutcome::ProviderUnavailable,
                Some("provider_forbidden".to_string()),
                DelegationLookupResult::Unavailable,
            ));
            continue;
        }

        if provider.provider_type == CredentialProviderType::OAuth2JwtBearer && !jwt_bearer_leg_permitted {
            warn!(
                target: "credential_delegation",
                surface_variant,
                surface_id = %channel_id,
                provider_id = %binding.credential_provider_id,
                "This leg may not carry an oauth2_jwt_bearer token - refusing the request"
            );
            results.push(DelegationResolution::new(
                binding,
                None,
                DelegationActionOutcome::ProviderUnavailable,
                Some("jwt_bearer_leg_forbidden".to_string()),
                DelegationLookupResult::Unavailable,
            ));
            continue;
        }

        if provider.provider_type == CredentialProviderType::OAuth2ClientCredentials
            && !client_credentials_leg_permitted
        {
            warn!(
                target: "credential_delegation",
                surface_variant,
                surface_id = %channel_id,
                provider_id = %binding.credential_provider_id,
                "This leg may not carry an oauth2_client_credentials token - refusing the request"
            );
            results.push(DelegationResolution::new(
                binding,
                None,
                DelegationActionOutcome::ProviderUnavailable,
                Some("client_credentials_leg_forbidden".to_string()),
                DelegationLookupResult::Unavailable,
            ));
            continue;
        }

        // Route by provider type
        match &provider.provider_type {
            CredentialProviderType::ApiKey => {
                // Direct secret resolution — no OAuth, no vault
                match oauth::resolve_api_key(&provider, secrets_store).await {
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
                            evt.detail = Some("api_key".to_string());
                            enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                            evt
                        });
                        let headers = build_injection_headers(&binding.inject_as, &api_key);
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::TokenInjected,
                            Some("api_key".to_string()),
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
            CredentialProviderType::OAuth2ClientCredentials | CredentialProviderType::OAuth2JwtBearer => {
                let target = GatewayTokenTarget {
                    binding,
                    provider: &provider,
                    agent_did,
                    channel_id,
                    via_fabric,
                    audit_ctx,
                    surface_variant,
                };
                results.push(
                    target
                        .resolve(vault_store, secrets_store, &GrantEgress::from_environment())
                        .await,
                );
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
                            Ok(refreshed) => {
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
                                    evt.detail = Some("after_refresh".to_string());
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
        &GrantEgress::from_environment(),
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

fn build_injection_headers(
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

/// Build a consent_required response for a binding that has no valid token
async fn build_consent_required(
    binding: &OutboundCredentialBinding,
    user_identity_hash: &str,
    agent_did: &str,
    channel_id: &str,
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

            match oauth::build_authorization_url(
                &provider,
                agent_did,
                user_identity_hash,
                channel_id,
                &scopes,
                gateway_base_url,
                secrets_store,
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
///   - `Some((ElicitationDeclined|Cancelled|TimedOut|Unsupported, _, NotApplicable))`
///     when the user rejected or the deadline expired.
///   - `None` if we should fall through to the legacy consent_required path
///     (no session id, client doesn't advertise elicitation cap and fallback
///     is `OnDemand`, provider not found, etc.).
#[allow(clippy::too_many_arguments)]
async fn try_elicit_flow(
    binding: &OutboundCredentialBinding,
    user_identity_hash: &str,
    agent_did: &str,
    channel_id: &str,
    provider: &CredentialProvider,
    vault_store: &Arc<dyn DelegationVaultStorage>,
    _provider_store: &Arc<dyn CredentialProviderStorage>,
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
                    DelegationLookupResult::NotApplicable,
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
    let authorization_url = match oauth::build_authorization_url(
        provider,
        agent_did,
        user_identity_hash,
        channel_id,
        &scopes,
        gateway_base_url,
        secrets_store,
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
                    DelegationLookupResult::NotApplicable,
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
                DelegationLookupResult::NotApplicable,
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
                DelegationLookupResult::NotApplicable,
            ))
        }
        Ok(Err(_canceled)) => {
            // Sender dropped without sending — treat as cancel.
            Some((
                DelegationActionOutcome::ElicitationCancelled,
                Some("waiter_dropped".to_string()),
                DelegationLookupResult::NotApplicable,
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
                DelegationLookupResult::NotApplicable,
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
    use crate::delegation_vault::gateway_token::SecretVersion;
    use crate::delegation_vault::gateway_token::test_endpoint::TokenEndpoint;
    use crate::delegation_vault::{DelegationToken, VaultLookupResult};
    use crate::secrets::{CreateSecretRequest, Secret, SecretListItem, UpdateSecretRequest};

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
        async fn lookup(
            &self,
            _agent_did: &str,
            _user_identity_hash: &str,
            _provider_id: &str,
        ) -> Result<VaultLookupResult> {
            let guard = self.result.lock().await;
            Ok(guard.clone())
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

        fn with_provider(provider: CredentialProvider) -> Arc<Self> {
            Arc::new(Self {
                providers: HashMap::from([(provider.id.clone(), provider)]),
            })
        }

        fn with_oauth_provider(id: &str) -> Arc<Self> {
            Self::with_provider(make_credential_provider(id, CredentialProviderType::OAuth2AuthorizationCode))
        }
    }

    #[async_trait]
    impl CredentialProviderStorage for MockProviderStore {
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
            _provider_id: &str,
        ) -> Result<Option<CredentialProvider>> {
            Ok(None)
        }
    }

    // ── Mock secrets store ────────────────────────────────────────────────

    struct MockSecretsStore;

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
        async fn list_all(&self) -> Result<Vec<SecretListItem>> {
            Ok(vec![])
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

    /// Answers every secret id with an unusable value at the version `gateway_token` records.
    struct UnchangedSecretsStore;

    #[async_trait]
    impl crate::secrets::store::SecretsStore for UnchangedSecretsStore {
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
            let earlier = chrono::DateTime::<Utc>::UNIX_EPOCH;
            Ok(Some(Secret {
                id: secret_id.into(),
                tenant_id: None,
                name: secret_id.into(),
                secret_id: secret_id.into(),
                description: None,
                value: "unusable".into(),
                secret_type: "General".into(),
                tags: vec![],
                created_at: earlier,
                updated_at: earlier,
            }))
        }
        async fn list_all(&self) -> Result<Vec<SecretListItem>> {
            Ok(vec![])
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
            jwt_bearer: None,
            description: None,
            created_at: now,
            updated_at: now,
            callback_url: None,
            resource: None,
            consent_identity_strategy_id: None,
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
            secret_versions: None,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let providers: Arc<dyn CredentialProviderStorage> = MockProviderStore::with_oauth_provider("cp-1");
        let store: Arc<dyn DelegationVaultStorage> = vault.clone();
        let results = resolve_delegation_credentials(
            &[make_binding("cp-1")],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &store,
            &providers,
            &secrets,
            "https://gw.example.com",
            false,
            None,
            Some("verified-user"),
            None,
            true,
            true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        resolve_delegation_credentials(
            &[make_binding("cp-1")],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            consent_principal,
            None,
            true,
            true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            None,
            true,
            true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            None,
            true,
            true,
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
    async fn api_key_and_client_credentials_failures_are_unavailable() {
        for (provider_type, outcome) in [
            (CredentialProviderType::ApiKey, DelegationActionOutcome::ApiKeyResolutionFailed),
            (CredentialProviderType::OAuth2ClientCredentials, DelegationActionOutcome::ClientCredentialsFailed),
        ] {
            let vault = MockVaultStore::new(VaultLookupResult::NotFound);
            let providers = MockProviderStore::with_provider(make_credential_provider("cp-1", provider_type.clone()));
            let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);

            let results = resolve_delegation_credentials(
                &[make_binding("cp-1")],
                "sha256:user1",
                "did:web:agent.example",
                "ch-1",
                None,
                &(vault as Arc<dyn DelegationVaultStorage>),
                &(providers as Arc<dyn CredentialProviderStorage>),
                &secrets,
                "https://gw.example.com",
                false,
                None,
                None,
                None,
                true,
                true,
            )
            .await;

            assert_eq!(results.len(), 1);
            assert_eq!(result_tag(&results[0].result), "Unavailable", "{provider_type:?}");
            assert_eq!(results[0].action.outcome, outcome, "{provider_type:?}");
        }
    }

    #[tokio::test]
    async fn a_delegation_line_names_the_request_variant() {
        use crate::observability::policy_audit::{RequestScope, in_request, set_request_variant};
        let logs = crate::component_tests::helpers::formatted_logs::FormattedLogs::capture();
        let vault: Arc<dyn DelegationVaultStorage> = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers: Arc<dyn CredentialProviderStorage> = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_binding("cp-1")];

        in_request(RequestScope::new("0123456789abcdef".to_string()), async {
            set_request_variant("beta");
            resolve_delegation_credentials(
                &bindings,
                "sha256:user1",
                "did:web:agent.example",
                "ch-1",
                None,
                &vault,
                &providers,
                &secrets,
                "https://gw.example.com",
                false,
                None,
                None,
                None,
                true,
                true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_tool_binding("cp-1", vec!["list_repos".to_string()])];

        // Call with a different tool name
        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            Some("create_issue"),
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            None,
            true,
            true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_tool_binding("cp-1", vec!["list_repos".to_string()])];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            Some("list_repos"),
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            None,
            true,
            true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_tool_binding("cp-1", vec!["list_repos".to_string()])];

        // No tool name (non-MCP request)
        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            None,
            true,
            true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);

        let results = resolve_delegation_credentials(
            &[],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            None,
            true,
            true,
        )
        .await;

        assert!(results.is_empty(), "Empty bindings should return empty results");
    }

    #[tokio::test]
    async fn test_custom_header_injection() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
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
        }];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            None,
            true,
            true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &vault,
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            None,
            true,
            true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            true, // via_fabric
            None,
            None,
            None,
            true,
            true,
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);

        let bindings = vec![make_binding("cp-1"), make_tool_binding("cp-2", vec!["special_tool".to_string()])];

        // No tool name → first binding matches (All), second is filtered (Tools with no tool)
        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            None,
            true,
            true,
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
        }
    }

    #[tokio::test]
    async fn test_elicit_without_session_id_falls_through_to_consent_required() {
        // ConsentMode::Elicit + NO audit_ctx.mcp_session_id → try_elicit_flow
        // returns None and the caller invokes build_consent_required.
        // MockSecretsStore cannot resolve the OAuth client_id secret, so no
        // authorization URL can be built and the binding is unavailable.
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![elicit_binding("cp-1", crate::config::types::ElicitFallback::OnDemand)];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None, // audit_ctx = None → no mcp_session_id
            None,
            None,
            true,
            true,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "Unavailable");
    }

    #[tokio::test]
    async fn test_elicit_no_capability_fail_fallback_returns_not_applicable() {
        // ConsentMode::Elicit + session_id present + client did NOT advertise
        // elicitation capability + fallback = Fail → NotApplicable + audit.
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
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
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            Some(&ctx),
            None,
            None,
            true,
            true,
        ))
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "NotApplicable");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ElicitationUnsupported);
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
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
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            Some(&ctx),
            None,
            None,
            true,
            true,
        )
        .await;

        assert_eq!(results.len(), 1);
        // As above: fallthrough → build_consent_required → secret resolution
        // fails on MockSecretsStore → no authorization URL → Unavailable.
        assert_eq!(result_tag(&results[0].result), "Unavailable");
    }

    #[tokio::test]
    async fn test_elicit_with_capability_no_sse_falls_back_per_policy() {
        // ConsentMode::Elicit + session_id + client DID advertise elicitation
        // capability, but NO SSE stream is registered for the session, so
        // send() returns false. With fallback = Fail → NotApplicable.
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
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
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            Some(&ctx),
            None,
            None,
            true,
            true,
        )
        .await;

        assert_eq!(results.len(), 1);
        // With MockSecretsStore the authorization-URL build fails before we
        // ever attempt SSE delivery, so try_elicit_flow returns None and the
        // caller falls through to build_consent_required, which also fails
        // on secrets → Unavailable. The no-SSE-stream branch itself is
        // covered by integration tests where the secret store is real.
        assert_eq!(result_tag(&results[0].result), "Unavailable");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ProviderUnavailable);
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

    fn jwt_bearer_provider(id: &str) -> CredentialProvider {
        let mut provider = make_credential_provider(id, CredentialProviderType::OAuth2JwtBearer);
        provider.authorization_endpoint = None;
        provider.client_id_secret_ref = None;
        provider.client_secret_secret_ref = None;
        provider.token_endpoint = Some("https://127.0.0.1/token".to_string());
        provider.jwt_bearer = Some(crate::credential_providers::JwtBearerSettings {
            assertion_issuer: "gateway@project.iam.gserviceaccount.com".into(),
            assertion_subject: None,
            signing_key_secret_ref: "SIGNING_KEY".into(),
            signing_algorithm: crate::credential_providers::jwt_assertion::JwtBearerAlgorithm::Es256,
            key_id: None,
            audience: None,
        });
        provider.created_at = Utc::now() - Duration::days(1);
        provider.updated_at = provider.created_at;
        provider
    }

    fn gateway_token(
        provider_id: &str,
        issued_secs_ago: i64,
        expires_in_secs: i64,
    ) -> DelegationToken {
        let mut token = make_token(false, false);
        token.credential_provider_id = provider_id.to_string();
        token.user_identity_hash = gateway_grant_user_hash(&["repo".to_string()]);
        token.access_token = "cached-gateway-token".to_string();
        token.secret_versions = Some(vec![SecretVersion {
            secret_id: "SIGNING_KEY".into(),
            updated_at: chrono::DateTime::<Utc>::UNIX_EPOCH,
        }]);
        token.consent_granted_at = Utc::now() - Duration::seconds(issued_secs_ago);
        token.created_at = token.consent_granted_at;
        token.expires_at = Some(Utc::now() + Duration::seconds(expires_in_secs));
        token
    }

    async fn resolve_gateway_binding(
        provider: CredentialProvider,
        lookup: VaultLookupResult,
        secrets: Arc<dyn SecretsStore>,
    ) -> DelegationResolution {
        resolve_binding_for_surface(provider, lookup, secrets, None, true).await
    }

    async fn resolve_binding_for_surface(
        provider: CredentialProvider,
        lookup: VaultLookupResult,
        secrets: Arc<dyn SecretsStore>,
        surface_tenant_id: Option<&str>,
        jwt_bearer_leg_permitted: bool,
    ) -> DelegationResolution {
        resolve_binding_on_legs(provider, lookup, secrets, surface_tenant_id, jwt_bearer_leg_permitted, true).await
    }

    async fn resolve_binding_on_legs(
        provider: CredentialProvider,
        lookup: VaultLookupResult,
        secrets: Arc<dyn SecretsStore>,
        surface_tenant_id: Option<&str>,
        jwt_bearer_leg_permitted: bool,
        client_credentials_leg_permitted: bool,
    ) -> DelegationResolution {
        let bindings = vec![make_binding(&provider.id)];
        let vault = MockVaultStore::new(lookup);
        let providers = MockProviderStore::with_provider(provider);
        let mut results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
            None,
            surface_tenant_id,
            jwt_bearer_leg_permitted,
            client_credentials_leg_permitted,
        )
        .await;
        assert_eq!(results.len(), 1);
        results.remove(0)
    }

    #[tokio::test]
    async fn test_bindings_send_the_gateways_own_credential_only_within_the_providers_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = signing_key_secrets(&directory).await;
        let cached = |provider: &CredentialProvider| VaultLookupResult::Found(gateway_token(&provider.id, 0, 3_600));
        let api_key = {
            let mut provider = make_credential_provider("cp-key", CredentialProviderType::ApiKey);
            provider.api_key_secret_ref = Some("SIGNING_KEY".into());
            provider
        };
        let consent = make_credential_provider("cp-consent", CredentialProviderType::OAuth2AuthorizationCode);
        let in_tenant = |mut provider: CredentialProvider, tenant: &str| {
            provider.tenant_id = Some(tenant.to_string());
            provider
        };

        for (provider, surface_tenant) in [
            (jwt_bearer_provider("cp-jwt"), Some("tenant-a")),
            (make_credential_provider("cp-cc", CredentialProviderType::OAuth2ClientCredentials), Some("tenant-a")),
            (api_key.clone(), Some("tenant-a")),
            (in_tenant(jwt_bearer_provider("cp-jwt"), "tenant-a"), None),
            (in_tenant(consent.clone(), "tenant-b"), Some("tenant-a")),
        ] {
            let lookup = cached(&provider);
            let resolution = resolve_binding_for_surface(provider, lookup, secrets.clone(), surface_tenant, true).await;
            assert!(matches!(resolution.result, DelegationLookupResult::Unavailable));
            assert_eq!(resolution.action.outcome, DelegationActionOutcome::ProviderUnavailable);
            assert_eq!(
                resolution
                    .action
                    .detail
                    .as_deref(),
                Some("provider_forbidden")
            );
        }

        let own = in_tenant(jwt_bearer_provider("cp-jwt"), "tenant-a");
        let tenant_directory = tempfile::tempdir().unwrap();
        let tenant_secrets = tenant_signing_key_secrets(&tenant_directory, Some("tenant-a")).await;
        let mut token = gateway_token(&own.id, 0, 3_600);
        token.secret_versions = Some(signing_key_version(&tenant_secrets, &own).await);
        let lookup = VaultLookupResult::Found(token);
        let resolution = resolve_binding_for_surface(own, lookup, tenant_secrets, Some("tenant-a"), true).await;
        assert_eq!(injected_bearer(&resolution).as_deref(), Some("Bearer cached-gateway-token"));
        let mut consented = make_token(false, false);
        consented.credential_provider_id = consent.id.clone();
        let resolution =
            resolve_binding_for_surface(consent, VaultLookupResult::Found(consented), secrets, Some("tenant-a"), true)
                .await;
        assert!(
            injected_bearer(&resolution).is_some(),
            "a user's consented token may come from an appliance-wide provider"
        );
    }

    #[tokio::test]
    async fn test_a_leg_refused_a_jwt_bearer_token_refuses_only_jwt_bearer_bindings() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = signing_key_secrets(&directory).await;
        let versions = signing_key_version(&secrets, &jwt_bearer_provider("cp-jwt-leg")).await;
        let cached = |provider: &CredentialProvider| {
            let mut token = gateway_token(&provider.id, 0, 3_600);
            token.secret_versions = Some(versions.clone());
            VaultLookupResult::Found(token)
        };

        let jwt = jwt_bearer_provider("cp-jwt-leg");
        let lookup = cached(&jwt);
        let refused = resolve_binding_for_surface(jwt.clone(), lookup, secrets.clone(), None, false).await;
        assert!(matches!(refused.result, DelegationLookupResult::Unavailable));
        assert_eq!(refused.action.outcome, DelegationActionOutcome::ProviderUnavailable);
        assert_eq!(
            refused
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_leg_forbidden")
        );

        let lookup = cached(&jwt);
        let permitted = resolve_binding_for_surface(jwt, lookup, secrets.clone(), None, true).await;
        assert_eq!(
            permitted
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(injected_bearer(&permitted).as_deref(), Some("Bearer cached-gateway-token"));

        let mut client_credentials =
            make_credential_provider("cp-cc-leg", CredentialProviderType::OAuth2ClientCredentials);
        client_credentials.updated_at = Utc::now() - Duration::days(1);
        let lookup = cached(&client_credentials);
        let resolution = resolve_binding_for_surface(client_credentials, lookup, secrets.clone(), None, false).await;
        assert_eq!(resolution.action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(injected_bearer(&resolution).as_deref(), Some("Bearer cached-gateway-token"));

        let mut api_key = make_credential_provider("cp-key-leg", CredentialProviderType::ApiKey);
        api_key.api_key_secret_ref = Some("SIGNING_KEY".into());
        let lookup = cached(&api_key);
        let resolution = resolve_binding_for_surface(api_key, lookup, secrets, None, false).await;
        assert_eq!(resolution.action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("api_key")
        );
    }

    #[tokio::test]
    async fn test_a_leg_refused_a_client_credentials_token_refuses_only_client_credentials_bindings() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = signing_key_secrets(&directory).await;
        let versions = signing_key_version(&secrets, &jwt_bearer_provider("cp-jwt-cc")).await;
        let cached = |provider: &CredentialProvider| {
            let mut token = gateway_token(&provider.id, 0, 3_600);
            token.secret_versions = Some(versions.clone());
            VaultLookupResult::Found(token)
        };
        let client_credentials = || {
            let mut provider = make_credential_provider("cp-cc-http", CredentialProviderType::OAuth2ClientCredentials);
            provider.updated_at = Utc::now() - Duration::days(1);
            provider
        };

        let provider = client_credentials();
        let lookup = cached(&provider);
        let refused = resolve_binding_on_legs(provider, lookup, secrets.clone(), None, true, false).await;
        assert!(matches!(refused.result, DelegationLookupResult::Unavailable));
        assert_eq!(refused.action.outcome, DelegationActionOutcome::ProviderUnavailable);
        assert_eq!(
            refused
                .action
                .detail
                .as_deref(),
            Some("client_credentials_leg_forbidden")
        );
        assert_eq!(injected_bearer(&refused), None);

        let provider = client_credentials();
        let lookup = cached(&provider);
        let permitted = resolve_binding_on_legs(provider, lookup, secrets.clone(), None, false, true).await;
        assert_eq!(permitted.action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(injected_bearer(&permitted).as_deref(), Some("Bearer cached-gateway-token"));

        let jwt = jwt_bearer_provider("cp-jwt-cc");
        let lookup = cached(&jwt);
        let resolution = resolve_binding_on_legs(jwt, lookup, secrets, None, true, false).await;
        assert_eq!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(injected_bearer(&resolution).as_deref(), Some("Bearer cached-gateway-token"));
    }

    fn injected_bearer(resolution: &DelegationResolution) -> Option<String> {
        match &resolution.result {
            DelegationLookupResult::Inject(injections) => injections
                .iter()
                .find_map(|injection| match injection {
                    ResolvedCredentialInjection::Header { name, value } if name == "Authorization" => {
                        Some(value.clone())
                    }
                    _ => None,
                }),
            _ => None,
        }
    }

    async fn signing_key_version(
        secrets: &Arc<dyn SecretsStore>,
        provider: &CredentialProvider,
    ) -> Vec<SecretVersion> {
        let read = ProviderSecrets::new(secrets, provider);
        read.resolve("SIGNING_KEY")
            .await
            .unwrap();
        read.versions_read()
    }

    async fn signing_key_secrets(directory: &tempfile::TempDir) -> Arc<dyn SecretsStore> {
        tenant_signing_key_secrets(directory, None).await
    }

    /// The signing key and the client id and secret of the test providers, in `tenant_id`.
    async fn tenant_signing_key_secrets(
        directory: &tempfile::TempDir,
        tenant_id: Option<&str>,
    ) -> Arc<dyn SecretsStore> {
        let secrets = crate::secrets::FilesystemSecretsStore::new_async(
            directory
                .path()
                .join("secrets")
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        for (secret_id, value) in [
            ("SIGNING_KEY", crate::credential_providers::jwt_assertion::test_keys::ec_pkcs8_pem()),
            ("CLIENT_ID", "client-id"),
            ("CLIENT_SECRET", "client-secret"),
        ] {
            secrets
                .create(CreateSecretRequest {
                    tenant_id: tenant_id.map(str::to_string),
                    name: secret_id.into(),
                    secret_id: secret_id.into(),
                    description: None,
                    value: value.to_string(),
                    secret_type: "General".into(),
                    tags: vec![],
                })
                .await
                .unwrap();
        }
        Arc::new(secrets)
    }

    struct GatewayGrantFixture {
        _directory: tempfile::TempDir,
        endpoint: TokenEndpoint,
        vault: Arc<dyn DelegationVaultStorage>,
        secrets: Arc<dyn SecretsStore>,
        provider: CredentialProvider,
        binding: OutboundCredentialBinding,
    }

    impl GatewayGrantFixture {
        async fn start(
            provider_id: &str,
            status: axum::http::StatusCode,
            body: serde_json::Value,
        ) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let endpoint = TokenEndpoint::start(status, body.to_string()).await;
            let vault: Arc<dyn DelegationVaultStorage> = Arc::new(
                crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().join("vault"))
                    .await
                    .unwrap(),
            );
            let secrets = signing_key_secrets(&directory).await;
            let mut provider = jwt_bearer_provider(provider_id);
            provider.token_endpoint = Some(endpoint.url.clone());
            let binding = make_binding(provider_id);
            Self {
                _directory: directory,
                endpoint,
                vault,
                secrets,
                provider,
                binding,
            }
        }

        async fn resolve(&self) -> DelegationResolution {
            GatewayTokenTarget {
                binding: &self.binding,
                provider: &self.provider,
                agent_did: "did:web:agent.example",
                channel_id: "ch-1",
                via_fabric: false,
                audit_ctx: None,
                surface_variant: None,
            }
            .resolve(&self.vault, &self.secrets, &self.endpoint.egress())
            .await
        }

        fn grants(&self) -> usize {
            self.endpoint
                .calls
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[test]
    fn test_gateway_grant_user_hash_ignores_scope_order_and_differs_by_scope_set() {
        let scopes = |names: &[&str]| -> Vec<String> {
            names
                .iter()
                .map(|name| name.to_string())
                .collect()
        };
        let read_write = gateway_grant_user_hash(&scopes(&["b", "a"]));
        assert_eq!(read_write, gateway_grant_user_hash(&scopes(&["a", "b", "a"])));
        assert_ne!(read_write, gateway_grant_user_hash(&scopes(&["a"])));
        assert_ne!(gateway_grant_user_hash(&[]), gateway_grant_user_hash(&scopes(&["a"])));
        for hash in [read_write, gateway_grant_user_hash(&[])] {
            let digest = hash
                .strip_prefix("__client_credentials__:")
                .expect("the hash keeps the gateway grant prefix");
            assert_eq!(digest.len(), 64, "{hash}");
        }
    }

    #[tokio::test]
    async fn test_routes_with_different_scopes_never_share_a_gateway_token() {
        let mut fixture = GatewayGrantFixture::start(
            "cp-jwt-scopes",
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "fresh-gateway-token", "token_type": "Bearer", "expires_in": 3600}),
        )
        .await;
        let narrow = vec!["orders.read".to_string()];
        let wide = vec!["orders.read".to_string(), "orders.write".to_string()];

        fixture.binding.scopes = narrow.clone();
        assert_eq!(
            fixture
                .resolve()
                .await
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_fresh")
        );
        fixture.binding.scopes = wide.clone();
        assert_eq!(
            fixture
                .resolve()
                .await
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_fresh")
        );
        assert_eq!(fixture.grants(), 2, "a wider scope set never reuses the narrower token");
        fixture.binding.scopes = narrow.clone();
        assert_eq!(
            fixture
                .resolve()
                .await
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(fixture.grants(), 2);

        let mut stored: Vec<(String, Vec<String>)> = fixture
            .vault
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .map(|token| (token.user_identity_hash, token.scopes))
            .collect();
        stored.sort();
        let mut expected = vec![(gateway_grant_user_hash(&narrow), narrow), (gateway_grant_user_hash(&wide), wide)];
        expected.sort();
        assert_eq!(stored, expected);
    }

    #[tokio::test]
    async fn test_gateway_binding_sends_one_grant_for_requests_inside_the_refresh_margin() {
        let fixture = GatewayGrantFixture::start(
            "cp-jwt-margin",
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "fresh-gateway-token", "token_type": "Bearer", "expires_in": 60}),
        )
        .await;
        let mut first_grant = gateway_token("cp-jwt-margin", 1_000, 10);
        first_grant.agent_did = "did:web:agent.example".into();
        first_grant.secret_versions = Some(signing_key_version(&fixture.secrets, &fixture.provider).await);
        fixture
            .vault
            .store(first_grant)
            .await
            .unwrap();

        let renewed = fixture.resolve().await;
        assert_eq!(
            renewed
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_fresh")
        );
        assert_eq!(injected_bearer(&renewed).as_deref(), Some("Bearer fresh-gateway-token"));

        let reused = fixture.resolve().await;
        assert_eq!(
            reused
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(injected_bearer(&reused).as_deref(), Some("Bearer fresh-gateway-token"));
        assert_eq!(fixture.grants(), 1);
    }

    #[tokio::test]
    async fn test_gateway_binding_sends_a_new_grant_after_the_provider_changes() {
        let mut fixture = GatewayGrantFixture::start(
            "cp-jwt-edited",
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "fresh-gateway-token", "token_type": "Bearer", "expires_in": 3600}),
        )
        .await;
        let first = fixture.resolve().await;
        assert_eq!(first.action.detail.as_deref(), Some("jwt_bearer_fresh"));
        let unchanged = fixture.resolve().await;
        assert_eq!(
            unchanged
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(fixture.grants(), 1);

        fixture.provider.updated_at = Utc::now();
        let edited = fixture.resolve().await;
        assert_eq!(
            edited
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_fresh")
        );
        assert_eq!(injected_bearer(&edited).as_deref(), Some("Bearer fresh-gateway-token"));
        assert_eq!(fixture.grants(), 2);

        let after_edit = fixture.resolve().await;
        assert_eq!(
            after_edit
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(fixture.grants(), 2);
    }

    #[tokio::test]
    async fn test_gateway_binding_never_serves_a_token_granted_before_a_secret_it_uses_changed() {
        use crate::delegation_vault::gateway_token::test_endpoint::replace_secret;
        let fixture = GatewayGrantFixture::start(
            "cp-jwt-secret-changed",
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "fresh-gateway-token", "token_type": "Bearer", "expires_in": 3600}),
        )
        .await;
        let resolve = async || {
            let resolution = fixture.resolve().await;
            (
                resolution
                    .action
                    .detail
                    .clone(),
                injected_bearer(&resolution),
                fixture.grants(),
            )
        };
        let injected = Some("Bearer fresh-gateway-token".to_string());
        assert_eq!(resolve().await, (Some("jwt_bearer_fresh".into()), injected.clone(), 1));

        replace_secret(&fixture.secrets, "CLIENT_ID", "not-used-by-this-provider").await;
        assert_eq!(resolve().await, (Some("jwt_bearer_cached".into()), injected.clone(), 1));

        let rotated_key = crate::component_tests::helpers::oidc_keys::SigningFixture::es256(1);
        replace_secret(&fixture.secrets, "SIGNING_KEY", rotated_key.private_pkcs8_pem()).await;
        assert_eq!(resolve().await, (Some("jwt_bearer_fresh".into()), injected.clone(), 2));
        assert_eq!(resolve().await, (Some("jwt_bearer_cached".into()), injected.clone(), 2));

        let signing_key = fixture
            .secrets
            .get_by_secret_id("SIGNING_KEY")
            .await
            .unwrap()
            .unwrap();
        fixture
            .secrets
            .set_tenant_id(&signing_key.id, Some("tenant-b".into()))
            .await
            .unwrap();
        assert_eq!(resolve().await, (Some("jwt_bearer_forbidden".into()), None, 2));

        fixture
            .secrets
            .delete(&signing_key.id)
            .await
            .unwrap();
        assert_eq!(resolve().await, (Some("jwt_bearer_secret_unavailable".into()), None, 2));
        assert_eq!(
            fixture
                .vault
                .list_all()
                .await
                .unwrap()
                .len(),
            1,
            "the still-valid token granted with the old key stays stored but is never served"
        );
    }

    #[tokio::test]
    async fn test_a_gateway_grant_sent_before_its_secret_changed_is_not_served_afterwards() {
        use crate::delegation_vault::gateway_token::test_endpoint::replace_secret;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post({
                let (release, calls) = (release.clone(), calls.clone());
                move || async move {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        release.notified().await;
                    }
                    axum::Json(serde_json::json!({"access_token": "slow-token", "token_type": "Bearer",
                        "expires_in": 3600}))
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let mut fixture = GatewayGrantFixture::start(
            "cp-jwt-secret-race",
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "unused", "token_type": "Bearer"}),
        )
        .await;
        fixture
            .provider
            .token_endpoint = Some(url.clone());
        let fixture = Arc::new(fixture);
        let egress = GrantEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: Some(url),
        };
        let resolve = |fixture: Arc<GatewayGrantFixture>, egress: GrantEgress| async move {
            GatewayTokenTarget {
                binding: &fixture.binding,
                provider: &fixture.provider,
                agent_did: "did:web:agent.example",
                channel_id: "ch-1",
                via_fabric: false,
                audit_ctx: None,
                surface_variant: None,
            }
            .resolve(&fixture.vault, &fixture.secrets, &egress)
            .await
            .action
            .detail
        };

        let in_flight = tokio::spawn(resolve(fixture.clone(), egress.clone()));
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        let rotated_key = crate::component_tests::helpers::oidc_keys::SigningFixture::es256(1);
        replace_secret(&fixture.secrets, "SIGNING_KEY", rotated_key.private_pkcs8_pem()).await;
        release.notify_one();
        assert_eq!(
            in_flight
                .await
                .unwrap()
                .as_deref(),
            Some("jwt_bearer_fresh")
        );

        assert_eq!(
            resolve(fixture.clone(), egress.clone())
                .await
                .as_deref(),
            Some("jwt_bearer_fresh")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the token granted with the old key is not reused");
        assert_eq!(
            resolve(fixture.clone(), egress)
                .await
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_a_gateway_grant_sent_before_its_provider_changed_is_not_served_afterwards() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post({
                let (release, calls) = (release.clone(), calls.clone());
                move || async move {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        release.notified().await;
                    }
                    axum::Json(serde_json::json!({"access_token": "slow-token", "token_type": "Bearer",
                        "expires_in": 3600}))
                }
            }),
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let mut fixture = GatewayGrantFixture::start(
            "cp-jwt-provider-race",
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "unused", "token_type": "Bearer"}),
        )
        .await;
        fixture
            .provider
            .token_endpoint = Some(url.clone());
        let fixture = Arc::new(fixture);
        let egress = GrantEgress {
            timeout: std::time::Duration::from_secs(5),
            exact_allowlist: Some(url),
        };
        let resolve = |fixture: Arc<GatewayGrantFixture>, provider: CredentialProvider, egress: GrantEgress| async move {
            GatewayTokenTarget {
                binding: &fixture.binding,
                provider: &provider,
                agent_did: "did:web:agent.example",
                channel_id: "ch-1",
                via_fabric: false,
                audit_ctx: None,
                surface_variant: None,
            }
            .resolve(&fixture.vault, &fixture.secrets, &egress)
            .await
            .action
            .detail
        };

        let in_flight = tokio::spawn(resolve(fixture.clone(), fixture.provider.clone(), egress.clone()));
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let mut edited = fixture.provider.clone();
        edited.updated_at = Utc::now();
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        release.notify_one();
        assert_eq!(
            in_flight
                .await
                .unwrap()
                .as_deref(),
            Some("jwt_bearer_fresh")
        );
        let stored = fixture
            .vault
            .list_all()
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].consent_granted_at < edited.updated_at, "consent is the time the grant was sent");
        assert!(stored[0].created_at > edited.updated_at);

        assert_eq!(
            resolve(fixture.clone(), edited.clone(), egress.clone())
                .await
                .as_deref(),
            Some("jwt_bearer_fresh")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the token granted before the provider changed is not reused");
        assert_eq!(
            resolve(fixture.clone(), edited, egress)
                .await
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_gateway_binding_refuses_a_grant_missing_a_requested_scope_and_stores_nothing() {
        let fixture = GatewayGrantFixture::start(
            "cp-jwt-narrowed",
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "narrow-token", "token_type": "Bearer", "expires_in": 3600,
                "scope": "other"}),
        )
        .await;
        let resolution = fixture.resolve().await;
        assert_eq!(resolution.action.outcome, DelegationActionOutcome::ClientCredentialsFailed);
        assert_eq!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_scope_mismatch")
        );
        assert!(matches!(resolution.result, DelegationLookupResult::Unavailable));
        assert!(
            fixture
                .vault
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(fixture.grants(), 1);
    }

    #[tokio::test]
    async fn test_gateway_binding_does_not_fall_back_to_a_token_granted_before_the_provider_changed() {
        let mut fixture = GatewayGrantFixture::start(
            "cp-jwt-edited-failing",
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "invalid_grant"}),
        )
        .await;
        let mut earlier = gateway_token("cp-jwt-edited-failing", 60, 3_540);
        earlier.agent_did = "did:web:agent.example".into();
        earlier.secret_versions = Some(signing_key_version(&fixture.secrets, &fixture.provider).await);
        fixture
            .vault
            .store(earlier)
            .await
            .unwrap();
        fixture.provider.updated_at = Utc::now();

        let resolution = fixture.resolve().await;
        assert_eq!(resolution.action.outcome, DelegationActionOutcome::ClientCredentialsFailed);
        assert!(
            resolution
                .action
                .detail
                .as_deref()
                .is_some_and(|detail| detail.starts_with("jwt_bearer_") && !detail.ends_with("_stale"))
        );
        assert!(injected_bearer(&resolution).is_none());
        assert_eq!(fixture.grants(), 1);
    }

    #[tokio::test]
    async fn test_jwt_bearer_binding_injects_a_cached_token_outside_the_refresh_margin() {
        let resolution = resolve_gateway_binding(
            jwt_bearer_provider("cp-jwt-cached"),
            VaultLookupResult::Found(gateway_token("cp-jwt-cached", 0, 3600)),
            Arc::new(UnchangedSecretsStore),
        )
        .await;
        assert_eq!(resolution.action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(injected_bearer(&resolution).as_deref(), Some("Bearer cached-gateway-token"));
    }

    #[tokio::test]
    async fn test_jwt_bearer_binding_keeps_a_valid_token_when_its_refresh_fails() {
        let resolution = resolve_gateway_binding(
            jwt_bearer_provider("cp-jwt-stale"),
            VaultLookupResult::Found(gateway_token("cp-jwt-stale", 3400, 200)),
            Arc::new(UnchangedSecretsStore),
        )
        .await;
        assert_eq!(resolution.action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_stale")
        );
        assert_eq!(injected_bearer(&resolution).as_deref(), Some("Bearer cached-gateway-token"));
    }

    #[tokio::test]
    async fn test_gateway_binding_does_not_inject_a_token_without_expiry_when_its_grant_fails() {
        let mut token = gateway_token("cp-jwt-no-expiry", 3600, 0);
        token.expires_at = None;
        let resolution = resolve_gateway_binding(
            jwt_bearer_provider("cp-jwt-no-expiry"),
            VaultLookupResult::Found(token),
            Arc::new(UnchangedSecretsStore),
        )
        .await;
        assert_eq!(resolution.action.outcome, DelegationActionOutcome::ClientCredentialsFailed);
        assert!(
            resolution
                .action
                .detail
                .as_deref()
                .is_some_and(|detail| detail.starts_with("jwt_bearer_") && !detail.ends_with("_stale"))
        );
        assert!(injected_bearer(&resolution).is_none());
        assert!(matches!(resolution.result, DelegationLookupResult::Unavailable));
    }

    fn gateway_token_without_secret_versions(
        provider_id: &str,
        issued_secs_ago: i64,
        expires_in_secs: i64,
    ) -> DelegationToken {
        let mut token = gateway_token(provider_id, issued_secs_ago, expires_in_secs);
        token.agent_did = "did:web:agent.example".into();
        token.secret_versions = None;
        token
    }

    #[tokio::test]
    async fn test_gateway_binding_replaces_a_stored_token_without_secret_versions_with_a_new_grant() {
        let fixture = GatewayGrantFixture::start(
            "cp-jwt-unversioned",
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "fresh-gateway-token", "token_type": "Bearer", "expires_in": 3600}),
        )
        .await;
        fixture
            .vault
            .store(gateway_token_without_secret_versions("cp-jwt-unversioned", 0, 3_600))
            .await
            .unwrap();

        let resolution = fixture.resolve().await;
        assert_eq!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_fresh")
        );
        assert_eq!(injected_bearer(&resolution).as_deref(), Some("Bearer fresh-gateway-token"));
        assert_eq!(fixture.grants(), 1);

        let stored = match fixture
            .vault
            .lookup("did:web:agent.example", &gateway_grant_user_hash(&fixture.binding.scopes), "cp-jwt-unversioned")
            .await
            .unwrap()
        {
            VaultLookupResult::Found(token) => token,
            _ => panic!("expected the new token to be stored"),
        };
        assert_eq!(stored.access_token, "fresh-gateway-token");
        assert_eq!(stored.secret_versions, Some(signing_key_version(&fixture.secrets, &fixture.provider).await));
    }

    #[tokio::test]
    async fn test_gateway_binding_does_not_fall_back_to_a_stored_token_without_secret_versions() {
        let fixture = GatewayGrantFixture::start(
            "cp-jwt-unversioned-failing",
            axum::http::StatusCode::BAD_REQUEST,
            serde_json::json!({"error": "invalid_grant"}),
        )
        .await;
        fixture
            .vault
            .store(gateway_token_without_secret_versions("cp-jwt-unversioned-failing", 3_400, 200))
            .await
            .unwrap();

        let resolution = fixture.resolve().await;
        assert_eq!(resolution.action.outcome, DelegationActionOutcome::ClientCredentialsFailed);
        assert!(
            resolution
                .action
                .detail
                .as_deref()
                .is_some_and(|detail| detail.starts_with("jwt_bearer_") && !detail.ends_with("_stale"))
        );
        assert!(injected_bearer(&resolution).is_none());
        assert_eq!(fixture.grants(), 1);
    }

    #[tokio::test]
    async fn test_gateway_grant_failure_records_a_delegation_failed_event_by_the_gateway() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = signing_key_secrets(&directory).await;

        let (resolution, events) = crate::audit::producer::capture(resolve_gateway_binding(
            jwt_bearer_provider("cp-jwt-audited"),
            VaultLookupResult::NotFound,
            secrets,
        ))
        .await;

        assert_eq!(resolution.action.outcome, DelegationActionOutcome::ClientCredentialsFailed);
        let failed: Vec<_> = events
            .iter()
            .filter(|event| matches!(event.event, DelegationAuditAction::DelegationFailed { .. }))
            .collect();
        assert_eq!(failed.len(), 1, "{events:?}");
        match &failed[0].event {
            DelegationAuditAction::DelegationFailed { reason, provider_id } => {
                assert_eq!(*reason, crate::audit::events::DelegationFailureReason::CredentialsUnavailable);
                assert_eq!(provider_id.as_deref(), Some("cp-jwt-audited"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(failed[0].detail.as_deref(), Some("jwt_bearer_forbidden"));
        assert_eq!(
            failed[0]
                .caller
                .as_ref()
                .map(|caller| caller.auth_method.as_str()),
            Some("gateway")
        );
    }

    #[tokio::test]
    async fn test_gateway_grant_failure_keeps_the_gateway_actor_when_an_audit_context_names_a_caller() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = signing_key_secrets(&directory).await;
        let provider = jwt_bearer_provider("cp-jwt-ctx");
        let bindings = vec![make_binding(&provider.id)];
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::with_provider(provider);
        let mut caller = crate::delegation_vault::audit::gateway_caller_context();
        caller.auth_method = "jwt".to_string();
        caller.sub = Some("user-1".to_string());
        let ctx = DelegationAuditContext {
            caller: Some(caller),
            channel_name: Some("Named surface".to_string()),
            ..Default::default()
        };

        let (_, events) = crate::audit::producer::capture(async {
            resolve_delegation_credentials(
                &bindings,
                "sha256:user1",
                "did:web:agent.example",
                "ch-1",
                None,
                &(vault as Arc<dyn DelegationVaultStorage>),
                &(providers as Arc<dyn CredentialProviderStorage>),
                &secrets,
                "https://gw.example.com",
                false,
                Some(&ctx),
                None,
                None,
                true,
                true,
            )
            .await
        })
        .await;

        let failed: Vec<_> = events
            .iter()
            .filter(|event| matches!(event.event, DelegationAuditAction::DelegationFailed { .. }))
            .collect();
        assert_eq!(failed.len(), 1, "{events:?}");
        let caller = failed[0]
            .caller
            .as_ref()
            .expect("caller");
        assert_eq!(caller.auth_method, "gateway");
        assert_eq!(caller.sub, None);
        assert_eq!(
            failed[0]
                .channel_name
                .as_deref(),
            Some("Named surface")
        );
    }

    #[tokio::test]
    async fn test_jwt_bearer_binding_failure_reports_a_category_each_time() {
        let directory = tempfile::tempdir().unwrap();
        let secrets = signing_key_secrets(&directory).await;

        let provider = jwt_bearer_provider("cp-jwt-fail");
        let first = resolve_gateway_binding(provider.clone(), VaultLookupResult::NotFound, secrets.clone()).await;
        assert_eq!(first.action.outcome, DelegationActionOutcome::ClientCredentialsFailed);
        assert_eq!(first.action.detail.as_deref(), Some("jwt_bearer_forbidden"));
        assert!(matches!(first.result, DelegationLookupResult::Unavailable));

        let second = resolve_gateway_binding(provider, VaultLookupResult::NotFound, secrets).await;
        assert_eq!(
            second
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_forbidden")
        );
    }

    #[tokio::test]
    async fn test_client_credentials_binding_failure_reports_only_a_category() {
        let resolution = resolve_gateway_binding(
            make_credential_provider("cp-cc-fail", CredentialProviderType::OAuth2ClientCredentials),
            VaultLookupResult::NotFound,
            Arc::new(MockSecretsStore),
        )
        .await;
        assert_eq!(resolution.action.outcome, DelegationActionOutcome::ClientCredentialsFailed);
        assert_eq!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("client_credentials_secret_unavailable")
        );
    }

    struct FaultyVault {
        inner: crate::delegation_vault::storage::FileSystemDelegationVaultStore,
        lookup: Option<VaultLookupResult>,
        fail_mark_used: bool,
        fail_store: bool,
    }

    #[async_trait]
    impl DelegationVaultStorage for FaultyVault {
        async fn store(
            &self,
            token: DelegationToken,
        ) -> Result<DelegationToken> {
            if self.fail_store {
                anyhow::bail!("vault rejected the write");
            }
            self.inner.store(token).await
        }
        async fn get(
            &self,
            id: &str,
        ) -> Result<Option<DelegationToken>> {
            self.inner.get(id).await
        }
        async fn lookup(
            &self,
            agent_did: &str,
            user_identity_hash: &str,
            provider_id: &str,
        ) -> Result<VaultLookupResult> {
            match &self.lookup {
                Some(result) => Ok(result.clone()),
                None => {
                    self.inner
                        .lookup(agent_did, user_identity_hash, provider_id)
                        .await
                }
            }
        }
        async fn list_all(&self) -> Result<Vec<DelegationToken>> {
            self.inner.list_all().await
        }
        async fn delete(
            &self,
            id: &str,
        ) -> Result<bool> {
            self.inner.delete(id).await
        }
        async fn delete_by_user(
            &self,
            user_identity_hash: &str,
        ) -> Result<usize> {
            self.inner
                .delete_by_user(user_identity_hash)
                .await
        }
        async fn update(
            &self,
            token: DelegationToken,
        ) -> Result<DelegationToken> {
            self.inner.update(token).await
        }
        async fn mark_used(
            &self,
            id: &str,
        ) -> Result<()> {
            if self.fail_mark_used {
                anyhow::bail!("vault could not record the use");
            }
            self.inner.mark_used(id).await
        }
    }

    async fn faulty_gateway_fixture(
        provider_id: &str,
        lookup: Option<VaultLookupResult>,
        fail_mark_used: bool,
        fail_store: bool,
    ) -> GatewayGrantFixture {
        let mut fixture = GatewayGrantFixture::start(
            provider_id,
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "fresh-gateway-token", "token_type": "Bearer", "expires_in": 3600}),
        )
        .await;
        let inner = crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(
            fixture
                ._directory
                .path()
                .join("faulty-vault"),
        )
        .await
        .unwrap();
        fixture.vault = Arc::new(FaultyVault {
            inner,
            lookup,
            fail_mark_used,
            fail_store,
        });
        fixture
    }

    #[tokio::test]
    async fn test_gateway_binding_replaces_an_expired_token_with_a_new_grant() {
        for (index, refreshable) in [true, false]
            .into_iter()
            .enumerate()
        {
            let provider_id = format!("cp-jwt-expired-{index}");
            let mut token = gateway_token(&provider_id, 7_200, -60);
            token.refresh_token = refreshable.then(|| "unused-refresh".to_string());
            let lookup = if refreshable {
                VaultLookupResult::ExpiredRefreshable(token)
            } else {
                VaultLookupResult::ExpiredNoRefresh(token)
            };
            let fixture = faulty_gateway_fixture(&provider_id, Some(lookup), false, false).await;

            let resolution = fixture.resolve().await;

            assert_eq!(resolution.action.outcome, DelegationActionOutcome::TokenInjected);
            assert_eq!(
                resolution
                    .action
                    .detail
                    .as_deref(),
                Some("jwt_bearer_fresh")
            );
            assert_eq!(injected_bearer(&resolution).as_deref(), Some("Bearer fresh-gateway-token"));
            assert_eq!(fixture.grants(), 1);
        }
    }

    #[tokio::test]
    async fn test_gateway_binding_injects_a_cached_token_when_the_vault_cannot_record_its_use() {
        let provider_id = "cp-jwt-mark-used";
        let cached = gateway_token(provider_id, 10, 3_600);
        let mut fixture =
            faulty_gateway_fixture(provider_id, Some(VaultLookupResult::Found(cached)), true, false).await;
        fixture.secrets = Arc::new(UnchangedSecretsStore);

        let resolution = fixture.resolve().await;

        assert_eq!(resolution.action.outcome, DelegationActionOutcome::TokenInjected);
        assert_eq!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("jwt_bearer_cached")
        );
        assert_eq!(injected_bearer(&resolution).as_deref(), Some("Bearer cached-gateway-token"));
        assert_eq!(fixture.grants(), 0);
    }

    #[tokio::test]
    async fn test_gateway_binding_withholds_a_fresh_token_the_vault_refuses_to_store() {
        let fixture = faulty_gateway_fixture("cp-jwt-store-refused", None, false, true).await;

        let resolution = fixture.resolve().await;

        assert_eq!(resolution.action.outcome, DelegationActionOutcome::ClientCredentialsFailed);
        assert_eq!(
            resolution
                .action
                .detail
                .as_deref(),
            Some("vault_store_rejected")
        );
        assert!(matches!(resolution.result, DelegationLookupResult::Unavailable));
        assert!(injected_bearer(&resolution).is_none());
        assert_eq!(fixture.grants(), 1);
        assert!(
            fixture
                .vault
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_gateway_binding_records_a_token_injected_event_for_the_gateway_grant() {
        let fixture = GatewayGrantFixture::start(
            "cp-jwt-injected-audit",
            axum::http::StatusCode::OK,
            serde_json::json!({"access_token": "fresh-gateway-token", "token_type": "Bearer", "expires_in": 3600}),
        )
        .await;

        let (resolution, events) = crate::audit::producer::capture(fixture.resolve()).await;

        assert_eq!(resolution.action.outcome, DelegationActionOutcome::TokenInjected);
        let injected: Vec<_> = events
            .iter()
            .filter(|event| matches!(event.event, DelegationAuditAction::TokenInjected))
            .collect();
        assert_eq!(injected.len(), 1, "{events:?}");
        let event = injected[0];
        assert_eq!(event.detail.as_deref(), Some("jwt_bearer_fresh"));
        assert_eq!(event.provider_id.as_deref(), Some("cp-jwt-injected-audit"));
        assert_eq!(
            event
                .user_identity_hash
                .as_deref(),
            Some(gateway_grant_user_hash(&fixture.binding.scopes).as_str())
        );
        assert_eq!(event.agent_did.as_deref(), Some("did:web:agent.example"));
        assert_eq!(event.surface_id.as_deref(), Some("ch-1"));
        let stored = fixture
            .vault
            .list_all()
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            event.token_id.as_deref(),
            stored
                .first()
                .map(|token| token.id.as_str())
        );
    }

    #[tokio::test]
    async fn legacy_resolution_reports_a_failed_coordinated_refresh_and_leaves_the_credential_unchanged() {
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
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let mut provider = make_credential_provider("cp-1", CredentialProviderType::OAuth2AuthorizationCode);
        provider.token_endpoint = Some("https://127.0.0.1/token".into());
        let providers: Arc<dyn CredentialProviderStorage> = MockProviderStore::with_provider(provider);
        let store: Arc<dyn DelegationVaultStorage> = vault.clone();

        let results = resolve_delegation_credentials(
            &[make_binding("cp-1")],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &store,
            &providers,
            &secrets,
            "https://gw.example.com",
            false,
            None,
            Some("verified-user"),
            None,
            true,
            true,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(matches!(
            vault
                .claim_refresh(&token, modern::now_secs().unwrap())
                .await,
            Err(crate::delegation_vault::storage::RefreshError::InProgress)
        ));
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::RefreshFailed);
        assert!(matches!(results[0].result, DelegationLookupResult::Unavailable));
        assert_eq!(
            results[0]
                .action
                .detail
                .as_deref(),
            Some("coordinated_refresh_unavailable")
        );
        let kept = vault
            .get(&token.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.access_token, token.access_token);
        assert_eq!(kept.refresh_token, token.refresh_token);
    }
}
