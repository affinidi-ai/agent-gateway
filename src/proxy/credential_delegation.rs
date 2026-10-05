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
    /// Binding skipped because it does not apply (tool filter, missing
    /// provider, …).
    NotApplicable,
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
) -> Vec<DelegationResolution> {
    let mut results: Vec<DelegationResolution> = Vec::new();

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
                    provider_id = %binding.credential_provider_id,
                    "Credential provider not found — skipping binding"
                );
                results.push(DelegationResolution::new(
                    binding,
                    None,
                    DelegationActionOutcome::NotApplicable,
                    Some("provider_not_found".to_string()),
                    DelegationLookupResult::NotApplicable,
                ));
                continue;
            }
            Err(e) => {
                warn!(
                    target: "credential_delegation",
                    provider_id = %binding.credential_provider_id,
                    error = %e,
                    "Failed to load credential provider"
                );
                results.push(DelegationResolution::new(
                    binding,
                    None,
                    DelegationActionOutcome::NotApplicable,
                    Some(format!("provider_load_error: {}", e)),
                    DelegationLookupResult::NotApplicable,
                ));
                continue;
            }
        };

        // Route by provider type
        match &provider.provider_type {
            CredentialProviderType::ApiKey => {
                // Direct secret resolution — no OAuth, no vault
                match oauth::resolve_api_key(&provider, secrets_store).await {
                    Ok(api_key) => {
                        debug!(
                            target: "credential_delegation",
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            "API key resolved — injecting into upstream request"
                        );
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
                        audit::audit(evt);
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
                            provider_id = %binding.credential_provider_id,
                            error = %e,
                            "Failed to resolve API key"
                        );
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::ApiKeyResolutionFailed,
                            Some(e.to_string()),
                            DelegationLookupResult::NotApplicable,
                        ));
                    }
                }
                continue;
            }
            CredentialProviderType::OAuth2ClientCredentials => {
                // M2M flow: check vault first (for caching), then fetch fresh if needed
                let m2m_user_hash = "__client_credentials__";
                let lookup_result = vault_store
                    .lookup(agent_did, m2m_user_hash, &binding.credential_provider_id)
                    .await;

                match lookup_result {
                    Ok(VaultLookupResult::Found(token)) => {
                        debug!(
                            target: "credential_delegation",
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            "Client credentials token found in vault — injecting"
                        );
                        if let Err(e) = vault_store
                            .mark_used(&token.id)
                            .await
                        {
                            warn!(
                                target: "credential_delegation",
                                token_id = %token.id,
                                error = %e,
                                "Failed to mark client_credentials token as used"
                            );
                        }
                        let mut evt = audit::audit_event(
                            DelegationAuditAction::TokenInjected,
                            Some(agent_did),
                            Some(m2m_user_hash),
                            Some(&binding.credential_provider_id),
                            Some(channel_id),
                        );
                        evt.token_id = Some(token.id.clone());
                        evt.via_fabric = via_fabric;
                        evt.detail = Some("client_credentials_cached".to_string());
                        enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                        audit::audit(evt);
                        let headers = build_injection_headers(&binding.inject_as, &token.access_token);
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::TokenInjected,
                            Some("client_credentials_cached".to_string()),
                            DelegationLookupResult::Inject(headers),
                        ));
                        continue;
                    }
                    Ok(VaultLookupResult::ExpiredRefreshable(token) | VaultLookupResult::ExpiredNoRefresh(token)) => {
                        debug!(
                            target: "credential_delegation",
                            token_id = %token.id,
                            "Expired client credentials will be replaced atomically"
                        );
                    }
                    _ => {
                        // Not found or error — proceed to fetch fresh token
                    }
                }

                let effective_scopes = if binding.scopes.is_empty() {
                    &provider.default_scopes
                } else {
                    &binding.scopes
                };

                match oauth::fetch_client_credentials_token(&provider, effective_scopes, secrets_store).await {
                    Ok(token_response) => {
                        info!(
                            target: "credential_delegation",
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            "Client credentials token fetched — caching in vault"
                        );
                        let expires_at = token_response
                            .expires_in
                            .map(|secs| Utc::now() + chrono::Duration::seconds(secs));
                        let now = Utc::now();
                        let delegation_token = DelegationToken {
                            id: Uuid::new_v4().to_string(),
                            agent_did: agent_did.to_string(),
                            user_identity_hash: m2m_user_hash.to_string(),
                            credential_provider_id: binding
                                .credential_provider_id
                                .clone(),
                            provider_id: provider.provider_id.clone(),
                            access_token: token_response
                                .access_token
                                .clone(),
                            refresh_token: token_response.refresh_token,
                            token_type: token_response.token_type,
                            scopes: effective_scopes.to_vec(),
                            expires_at,
                            delegation_vc: None,
                            consent_identity: None,
                            consent_granted_at: now,
                            last_used_at: Some(now),
                            created_at: now,
                            updated_at: now,
                        };
                        let stored = match vault_store
                            .store(delegation_token)
                            .await
                        {
                            Ok(stored) => stored,
                            Err(error) => {
                                error!(
                                    target: "credential_delegation",
                                    surface_id = %channel_id,
                                    provider_id = %binding.credential_provider_id,
                                    error = %error,
                                    "Failed to store fresh client_credentials token in vault"
                                );
                                results.push(DelegationResolution::new(
                                    binding,
                                    Some(&provider.name),
                                    DelegationActionOutcome::ClientCredentialsFailed,
                                    Some("vault_store_rejected".to_string()),
                                    DelegationLookupResult::Unavailable,
                                ));
                                continue;
                            }
                        };

                        let mut evt = audit::audit_event(
                            DelegationAuditAction::TokenInjected,
                            Some(agent_did),
                            Some(m2m_user_hash),
                            Some(&binding.credential_provider_id),
                            Some(channel_id),
                        );
                        evt.token_id = Some(stored.id);
                        evt.via_fabric = via_fabric;
                        evt.detail = Some("client_credentials_fresh".to_string());
                        enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                        audit::audit(evt);

                        let headers = build_injection_headers(&binding.inject_as, &stored.access_token);
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::TokenInjected,
                            Some("client_credentials_fresh".to_string()),
                            DelegationLookupResult::Inject(headers),
                        ));
                    }
                    Err(e) => {
                        warn!(
                            target: "credential_delegation",
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            error = %e,
                            "Client credentials token fetch failed"
                        );
                        let mut evt = audit::audit_event(
                            DelegationAuditAction::TokenNotFound,
                            Some(agent_did),
                            Some(m2m_user_hash),
                            Some(&binding.credential_provider_id),
                            Some(channel_id),
                        );
                        evt.via_fabric = via_fabric;
                        evt.detail = Some(e.to_string());
                        enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                        audit::audit(evt);
                        results.push(DelegationResolution::new(
                            binding,
                            Some(&provider.name),
                            DelegationActionOutcome::ClientCredentialsFailed,
                            Some(e.to_string()),
                            DelegationLookupResult::NotApplicable,
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
                        token_id = %token.id,
                        error = %e,
                        "Failed to mark delegation token as used"
                    );
                }

                // Audit: token injected
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
                audit::audit(evt);

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
                                audit::audit(event);
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
                                token = match persist_refreshed_token(vault_store.as_ref(), token, binding, &provider)
                                    .await
                                {
                                    Ok(stored) => stored,
                                    Err(resolution) => {
                                        results.push(resolution);
                                        continue;
                                    }
                                };
                                if let Err(e) = vault_store
                                    .mark_used(&token.id)
                                    .await
                                {
                                    warn!(
                                        target: "credential_delegation",
                                        token_id = %token.id,
                                        error = %e,
                                        "Failed to mark refreshed token as used"
                                    );
                                }

                                info!(
                                    target: "credential_delegation",
                                    surface_id = %channel_id,
                                    provider_id = %binding.credential_provider_id,
                                    "Token refreshed successfully"
                                );

                                // Audit: token refreshed
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
                                audit::audit(evt);

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
                                audit::audit(evt);

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
                                    surface_id = %channel_id,
                                    provider_id = %binding.credential_provider_id,
                                    error = %e,
                                    "Token refresh failed — requesting new consent"
                                );
                                // Audit: refresh failed
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
                                audit::audit(evt);
                                // Fall through to consent_required
                                let cr = build_consent_required(
                                    binding,
                                    user_identity_hash,
                                    agent_did,
                                    channel_id,
                                    provider_store,
                                    secrets_store,
                                    gateway_base_url,
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
                    )
                    .await;
                    let outcome = match cr {
                        DelegationLookupResult::ConsentRequired { .. } => DelegationActionOutcome::ConsentRequired,
                        _ => DelegationActionOutcome::NotApplicable,
                    };
                    results.push(DelegationResolution::new(binding, Some(&provider.name), outcome, None, cr));
                }
            }
            Err(e) => {
                warn!(
                    target: "credential_delegation",
                    surface_id = %channel_id,
                    provider_id = %binding.credential_provider_id,
                    error = %e,
                    "Vault lookup failed"
                );
                // Audit: token not found (vault error)
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
                audit::audit(evt);
                results.push(DelegationResolution::new(
                    binding,
                    Some(&provider.name),
                    DelegationActionOutcome::LookupError,
                    Some(e.to_string()),
                    DelegationLookupResult::NotApplicable,
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
    let client = crate::http_client::external().map_err(|_| ())?;
    let response = oauth::refresh_scoped_access_token(
        provider,
        claim
            .token()
            .refresh_token
            .as_deref()
            .ok_or(())?,
        &claim.token().scopes,
        secrets,
        &client,
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

async fn persist_refreshed_token(
    vault_store: &dyn DelegationVaultStorage,
    token: DelegationToken,
    binding: &OutboundCredentialBinding,
    provider: &CredentialProvider,
) -> Result<DelegationToken, DelegationResolution> {
    vault_store
        .update(token)
        .await
        .map_err(|error| {
            warn!(
                target: "credential_delegation",
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
        })
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
                        provider_id = %binding.credential_provider_id,
                        error = %e,
                        "Failed to build authorization URL"
                    );
                    DelegationLookupResult::NotApplicable
                }
            }
        }
        _ => {
            warn!(
                target: "credential_delegation",
                provider_id = %binding.credential_provider_id,
                "Credential provider not found for consent_required"
            );
            DelegationLookupResult::NotApplicable
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
) -> Option<(DelegationActionOutcome, Option<String>, DelegationLookupResult)> {
    let session_id = audit_ctx.and_then(|c| c.mcp_session_id.as_deref())?;

    // Check the client advertised the `elicitation` capability during
    // `initialize`. If it didn't, honour the binding's `elicit_fallback`.
    let cap_registry = crate::mcp::elicitation::global_capability_registry();
    let caps = cap_registry
        .get(session_id)
        .await;
    let supports_elicitation = caps
        .as_ref()
        .map(|c| c.elicitation)
        .unwrap_or(false);

    if !supports_elicitation {
        match binding.elicit_fallback {
            ElicitFallback::OnDemand => return None, // fall through to legacy consent_required
            ElicitFallback::Fail => {
                let mut evt = audit::audit_event(
                    DelegationAuditAction::ElicitationDeclined,
                    Some(agent_did),
                    Some(user_identity_hash),
                    Some(&binding.credential_provider_id),
                    Some(channel_id),
                );
                evt.via_fabric = via_fabric;
                evt.detail = Some("client does not advertise elicitation capability and fallback=fail".to_string());
                enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                audit::audit(evt);
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
        .register(session_id)
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
                error = %e,
                "Elicit: failed to serialize elicitation/create request"
            );
            return None;
        }
    };
    let sent = sse_registry
        .send(session_id, axum::response::sse::Event::default().data(serialized))
        .await;
    if !sent {
        // Client never opened the GET notification stream — we cannot
        // deliver. Fall back per binding policy.
        debug!(
            target: "credential_delegation",
            session_id = %session_id,
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
    audit::audit(sent_evt);

    // Park on the elicitation response with a timeout. We deliberately do
    // NOT race the vault notifier here: per spec we must wait for the
    // client's accept/decline/cancel reply before doing anything else.
    let timeout_duration = std::time::Duration::from_secs(binding.elicit_timeout_secs);
    let elicit_outcome = tokio::time::timeout(timeout_duration, waiter).await;

    let result = match elicit_outcome {
        Ok(Ok(crate::mcp::elicitation::ElicitationResult::Accept { .. })) => {
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
            audit::audit(evt);

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
                        audit::audit(inj);
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
            audit::audit(evt);
            Some((
                DelegationActionOutcome::ElicitationDeclined,
                Some(format!("elicit_id={}", elicit_id)),
                DelegationLookupResult::NotApplicable,
            ))
        }
        Ok(Ok(crate::mcp::elicitation::ElicitationResult::Cancel)) => {
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
            audit::audit(evt);
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
            audit::audit(evt);
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
        .remove(session_id, &elicit_id)
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

        fn with_oauth_provider(id: &str) -> Arc<Self> {
            let mut providers = HashMap::new();
            providers
                .insert(id.to_string(), make_credential_provider(id, CredentialProviderType::OAuth2AuthorizationCode));
            Arc::new(Self { providers })
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
        let Err(rejected) = persist_refreshed_token(&vault, refreshed, &binding, &provider).await else {
            panic!("a provider response must not revive revoked authorization");
        };
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
        let Ok(stored) = persist_refreshed_token(&vault, refreshed, &binding, &provider).await else {
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

    #[tokio::test]
    async fn test_not_found_returns_not_applicable_when_no_provider() {
        // When vault has no token AND provider store has no provider,
        // build_consent_required falls back to NotApplicable
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
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0].result, DelegationLookupResult::NotApplicable),
            "Expected NotApplicable when provider not found, got {:?}",
            result_tag(&results[0].result)
        );
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::NotApplicable);
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
    async fn test_vault_error_returns_not_applicable() {
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
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0].result, DelegationLookupResult::NotApplicable),
            "Vault error should degrade to NotApplicable"
        );
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::LookupError);
    }

    #[tokio::test]
    async fn test_expired_no_refresh_triggers_consent_required_path() {
        // Expired with no refresh token → should attempt consent_required
        // Since MockProviderStore is empty, falls back to NotApplicable
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
        )
        .await;

        assert_eq!(results.len(), 1);
        // Provider not in mock store — falls through to NotApplicable
        assert!(
            matches!(&results[0].result, DelegationLookupResult::NotApplicable),
            "ExpiredNoRefresh with no provider should degrade to NotApplicable"
        );
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
        // MockSecretsStore cannot resolve the OAuth client_id secret, so
        // build_consent_required itself degrades to NotApplicable. The fact
        // we did not get a panic or different variant proves the fallthrough.
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
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "NotApplicable");
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
        )
        .await;

        assert_eq!(results.len(), 1);
        assert_eq!(result_tag(&results[0].result), "NotApplicable");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::ElicitationUnsupported);
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
        )
        .await;

        assert_eq!(results.len(), 1);
        // Same degradation as above: fallthrough → build_consent_required →
        // secret resolution fails on MockSecretsStore → NotApplicable.
        assert_eq!(result_tag(&results[0].result), "NotApplicable");
    }

    #[tokio::test]
    async fn test_elicit_with_capability_no_sse_falls_back_per_policy() {
        // ConsentMode::Elicit + session_id + client DID advertise elicitation
        // capability, but NO SSE stream is registered for the session, so
        // send() returns false. With fallback = Fail → NotApplicable.
        let session_id = "session-elicit-no-sse";
        crate::mcp::elicitation::global_capability_registry()
            .record(
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
        )
        .await;

        assert_eq!(results.len(), 1);
        // With MockSecretsStore the authorization-URL build fails before we
        // ever attempt SSE delivery, so try_elicit_flow returns None and the
        // caller falls through to build_consent_required, which also fails
        // on secrets → NotApplicable. The no-SSE-stream branch itself is
        // covered by integration tests where the secret store is real.
        assert_eq!(result_tag(&results[0].result), "NotApplicable");
        assert_eq!(results[0].action.outcome, DelegationActionOutcome::NotApplicable);
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
}
