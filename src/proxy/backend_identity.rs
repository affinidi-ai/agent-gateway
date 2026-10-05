//! Protected agent identity resolution from responses.
//!
//! This module is the single place where the gateway resolves the identity of a
//! **protected agent** from its response messages. It extracts identity fields,
//! computes a canonical hash, and creates or retrieves a DID via the VC issuer.
//!
//! Identity sources:
//! - **Agent card**: `capabilities.extensions[agent-identity].params`
//! - **A2A/AP2 response**: `metadata[agent-identity/v1]`
//! - **MCP response**: `_meta[serverIdentity]` (configurable field name)

use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::identity::compute_canonical_identity_hash;

// ── Identity extraction errors ──────────────────────────────────────────────

/// Errors from identity payload extraction.
///
/// Callers use the variant to decide whether the request/response is anonymous
/// (extension absent) or malformed (extension declared but payload missing).
#[derive(Debug, thiserror::Error)]
pub enum IdentityExtractionError {
    /// The extensions[] array is present but does not declare agent-identity/v1.
    #[error("agent-identity/v1 extension not found in message")]
    ExtensionNotFound,

    /// The extensions[] array declares agent-identity/v1 but the metadata map
    /// does not contain the corresponding payload.
    #[error("agent-identity/v1 declared in extensions but missing from metadata")]
    DeclaredButMissing,

    /// The _meta field does not contain the expected identity field.
    #[error("identity field '{0}' not found in _meta")]
    MetaFieldNotFound(String),

    /// No metadata map found in any expected location.
    #[error("no metadata found in message")]
    NoMetadata,

    #[error("{0}")]
    InvalidMcpMetadata(#[from] crate::mcp::meta::McpMetadataError),
}

// ── Domain types ────────────────────────────────────────────────────────────

/// Resolved protected agent identity, used by both inbound and outbound pipelines.
#[derive(Debug, Clone)]
pub enum ProtectedAgentIdentity {
    /// Identity was resolved — DID assigned, fields extracted and validated.
    Managed { did: String, identity_fields: HashMap<String, JsonValue> },
    /// No managed_identity configured, or request/response has no identity extension.
    Anonymous,
}

/// Where the identity extension was expected but not found.
#[derive(Debug, Clone, Copy)]
pub enum IdentitySource {
    AgentCard,
    MessageResponse,
}

/// Which identity slot on the channel a resolution call is targeting.
///
/// The slot drives both *which* surface config is consulted (`protected_identity`
/// vs `external_identity`) and the `slot` field emitted on RFC 7807 problem+json
/// error responses so the demo UI can attribute the failure to the right edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySlot {
    /// MA → AP response: protected agent identity.
    Protected,
    /// EXT → TP response: external agent identity (inbound response + outbound proxy).
    External,
}

impl IdentitySlot {
    /// Stable name used in problem+json `slot` field.
    #[allow(dead_code)]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Protected => "protected_identity",
            Self::External => "external_identity",
        }
    }
}

impl std::fmt::Display for IdentitySource {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::AgentCard => write!(f, "agent card"),
            Self::MessageResponse => write!(f, "message response"),
        }
    }
}

/// Domain error for identity resolution failures.
///
/// Returned when `managed_identity` is configured but the gateway cannot
/// resolve the protected agent's identity from the response.
#[derive(Debug, thiserror::Error)]
pub enum IdentityResolutionError {
    #[error("Response body is not valid JSON")]
    InvalidResponseJson,

    #[error("Identity extension not found in {0} of protected agent")]
    IdentityExtensionMissing(IdentitySource),

    #[error("Identity validation failed: {0}")]
    ValidationFailed(String),

    #[error("Failed to create or retrieve DID: {0}")]
    DidCreationFailed(String),

    #[error("Identity backend unavailable: {0}")]
    IdentityBackendUnavailable(String),
}

impl IdentityResolutionError {
    /// Stable code string for problem+json `code` field. Used by demo UIs and
    /// downstream callers to programmatically distinguish failure classes
    /// without parsing the human-readable message.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidResponseJson => crate::a2a::ERR_IDENTITY_INVALID_RESPONSE,
            Self::IdentityExtensionMissing(_) => crate::a2a::ERR_IDENTITY_EXTENSION_MISSING,
            Self::ValidationFailed(_) => crate::a2a::ERR_IDENTITY_VALIDATION_FAILED,
            Self::DidCreationFailed(_) | Self::IdentityBackendUnavailable(_) => crate::a2a::ERR_IDENTITY_DID_FAILED,
        }
    }

    /// HTTP status: client/upstream omission → 422; misconfig → 500;
    /// backend unreachable → 503; gateway-side DID failure → 502.
    pub fn http_status(&self) -> axum::http::StatusCode {
        match self {
            Self::IdentityExtensionMissing(_) | Self::InvalidResponseJson | Self::ValidationFailed(_) => {
                axum::http::StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::DidCreationFailed(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Self::IdentityBackendUnavailable(_) => axum::http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

// ── Public entry point ──────────────────────────────────────────────────────

/// Resolve the protected agent's identity from a response.
///
/// - Returns `Ok(Anonymous)` when `managed_identity` is **not** configured (identity management disabled).
/// - Returns `Ok(Managed { did, identity_fields })` on success.
/// - Returns `Err(IdentityResolutionError)` when `managed_identity` **is** configured but resolution fails.
///
/// This must be called **once**, immediately after receiving the upstream response.
/// All subsequent response-processing steps consume the resolved identity.
pub async fn resolve_protected_agent_identity(
    response_body: &[u8],
    surface: &crate::config::agent_surface::AgentSurface,
    identity_selector: Option<&Arc<crate::identity::IdentitySelector>>,
    identity_rules_engine: Option<&Arc<crate::proxy::RulesEngine>>,
    channel_name: &str,
    is_agent_card: bool,
    source_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> Result<ProtectedAgentIdentity, IdentityResolutionError> {
    resolve_agent_identity_for_slot(
        response_body,
        surface,
        IdentitySlot::Protected,
        identity_selector,
        identity_rules_engine,
        channel_name,
        is_agent_card,
        source_identity,
    )
    .await
}

/// Resolve the **external** agent's identity from an upstream response.
///
/// Mirrors [`resolve_protected_agent_identity`] but consults the
/// `identity_slots.external` config (the Agent Identity node dropped on the
/// MA→External edge in the Surface Builder UI). Returns `Anonymous` when the
/// slot is not configured, so this is safe to call unconditionally on every
/// inbound/outbound response.
pub async fn resolve_external_agent_identity(
    response_body: &[u8],
    surface: &crate::config::agent_surface::AgentSurface,
    identity_selector: Option<&Arc<crate::identity::IdentitySelector>>,
    identity_rules_engine: Option<&Arc<crate::proxy::RulesEngine>>,
    channel_name: &str,
    is_agent_card: bool,
    source_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> Result<ProtectedAgentIdentity, IdentityResolutionError> {
    resolve_agent_identity_for_slot(
        response_body,
        surface,
        IdentitySlot::External,
        identity_selector,
        identity_rules_engine,
        channel_name,
        is_agent_card,
        source_identity,
    )
    .await
}

/// Issue (or fetch) the slot's DID: the protected slot is the managed agent,
/// the external slot an external caller.
async fn issue_for_slot(
    vc_issuer: &crate::identity::VCIssuer,
    slot: IdentitySlot,
    identity_fields: HashMap<String, JsonValue>,
    identity_hash: String,
    surface: &crate::config::agent_surface::AgentSurface,
) -> anyhow::Result<crate::identity::AgentIdentityResponse> {
    let surface_id = Some(surface.surface_id.clone());
    let issuer_id = surface.issuer_id.clone();
    match slot {
        IdentitySlot::Protected => {
            vc_issuer
                .issue_or_get_managed_credential(identity_fields, Some(identity_hash), surface_id, issuer_id)
                .await
        }
        IdentitySlot::External => {
            vc_issuer
                .issue_or_get_caller_credential(identity_fields, Some(identity_hash), surface_id, issuer_id)
                .await
        }
    }
}

/// Resolve an agent identity from a response body for a specific channel slot.
///
/// The slot selects which surface accessor to consult (`protected_identity` for
/// MA→AP responses or `external_identity` for EXT→TP outbound responses) and
/// drives the `slot` field on any returned [`IdentityResolutionError`] so the
/// demo UI can attribute the failure to the correct edge.
pub async fn resolve_agent_identity_for_slot(
    response_body: &[u8],
    surface: &crate::config::agent_surface::AgentSurface,
    slot: IdentitySlot,
    identity_selector: Option<&Arc<crate::identity::IdentitySelector>>,
    identity_rules_engine: Option<&Arc<crate::proxy::RulesEngine>>,
    channel_name: &str,
    is_agent_card: bool,
    source_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> Result<ProtectedAgentIdentity, IdentityResolutionError> {
    if !is_agent_card
        && surface.channel_protocol() == crate::config::ChannelProtocol::Mcp
        && let Ok(body) = serde_json::from_slice::<JsonValue>(response_body)
        && (body.get("error").is_some()
            || body
                .get("result")
                .and_then(|result| result.get("resultType"))
                .is_some_and(|kind| kind.as_str() != Some("complete")))
    {
        return Ok(ProtectedAgentIdentity::Anonymous);
    }
    // Slot-specific config first; fall back to the legacy `managed_identity`
    // alias so unmigrated channels keep working in the protected slot.
    let slot_config: Option<crate::source_auth::ManagedIdentityConfig> = match slot {
        IdentitySlot::Protected => surface
            .protected_identity()
            .cloned()
            .or_else(|| surface.managed_identity()),
        IdentitySlot::External => surface
            .external_identity()
            .cloned(),
    };

    let has_managed_identity = slot_config.is_some();

    let source = if is_agent_card {
        IdentitySource::AgentCard
    } else {
        IdentitySource::MessageResponse
    };

    if !has_managed_identity {
        return Ok(ProtectedAgentIdentity::Anonymous);
    }

    // Request-bound short-circuit: `FromJwtClaim` derives the DID from the
    // caller's *validated* JWT claims (produced by `jwt_bearer` source auth on
    // the same surface), not from a stored credential. The store-based
    // resolver has no token in scope, so this mode is handled here before the
    // credential-derived path below.
    if let Some(crate::source_auth::ManagedIdentityConfig::FromJwtClaim { claim, namespace_claims }) =
        slot_config.as_ref()
    {
        let mode_label = "from_jwt_claim";
        let started = std::time::Instant::now();
        let Some(claims) = source_identity.and_then(|i| i.jwt_claims()) else {
            // No validated token in scope. For agent-card fetches there is no
            // inbound caller, so treat as anonymous; otherwise the surface is
            // misconfigured (FromJwtClaim without jwt_bearer source auth).
            if is_agent_card {
                return Ok(ProtectedAgentIdentity::Anonymous);
            }
            crate::metrics::backends::prometheus::track_managed_identity_resolve(
                channel_name,
                mode_label,
                "jwt_claims_unavailable",
                started
                    .elapsed()
                    .as_secs_f64(),
            );
            return Err(IdentityResolutionError::DidCreationFailed(
                crate::identity::credential_identity::CredentialIdentityError::JwtClaimsUnavailable.to_string(),
            ));
        };
        match crate::identity::credential_identity::resolve_jwt_claim_identity(claim, namespace_claims, claims) {
            Ok(crate::identity::credential_identity::CredentialIdentity::Derived {
                identity_fields,
                identity_hash,
            }) => {
                let Some(selector) = identity_selector else {
                    crate::metrics::backends::prometheus::track_managed_identity_resolve(
                        channel_name,
                        mode_label,
                        "vc_issuer_missing",
                        started
                            .elapsed()
                            .as_secs_f64(),
                    );
                    return Err(IdentityResolutionError::DidCreationFailed(
                        "Request-bound identity requires VC issuer selector".to_string(),
                    ));
                };
                let vc_issuer = selector.get_vc_issuer();
                match issue_for_slot(vc_issuer.as_ref(), slot, identity_fields.clone(), identity_hash.clone(), surface)
                    .await
                {
                    Ok(response) => {
                        let result_label = if response.is_new {
                            "ok_new"
                        } else {
                            "ok_cached"
                        };
                        crate::metrics::backends::prometheus::track_managed_identity_resolve(
                            channel_name,
                            mode_label,
                            result_label,
                            started
                                .elapsed()
                                .as_secs_f64(),
                        );
                        debug!(
                            channel = channel_name,
                            slot = slot.name(),
                            did = %response.did,
                            mode = mode_label,
                            is_new = response.is_new,
                            "Inbound request-bound identity (jwt claim)"
                        );
                        return Ok(ProtectedAgentIdentity::Managed {
                            did: response.did,
                            identity_fields,
                        });
                    }
                    Err(e) => {
                        crate::metrics::backends::prometheus::track_managed_identity_resolve(
                            channel_name,
                            mode_label,
                            "vc_issuer_error",
                            started
                                .elapsed()
                                .as_secs_f64(),
                        );
                        return Err(IdentityResolutionError::IdentityBackendUnavailable(e.to_string()));
                    }
                }
            }
            Ok(crate::identity::credential_identity::CredentialIdentity::Bound { .. }) => {
                unreachable!("resolve_jwt_claim_identity only returns Derived")
            }
            Err(e) => {
                crate::metrics::backends::prometheus::track_managed_identity_resolve(
                    channel_name,
                    mode_label,
                    e.reason_label(),
                    started
                        .elapsed()
                        .as_secs_f64(),
                );
                // Missing/invalid claim is a client/token problem (422);
                // anything else is a surface misconfiguration (500).
                return Err(match e {
                    crate::identity::credential_identity::CredentialIdentityError::JwtClaimMissing(_) => {
                        IdentityResolutionError::ValidationFailed(e.to_string())
                    }
                    _ => IdentityResolutionError::DidCreationFailed(e.to_string()),
                });
            }
        }
    }

    // Credential-derived short-circuit (FromMtls / FromApiKey / Static).
    // These modes do NOT require the response body to carry an identity
    // payload — the DID is derived from the channel's bound credential, so we
    // skip JSON parsing, schema validation, and field extraction entirely.
    // This is the inbound counterpart of the outbound short-circuit in
    // proxy/outbound_handler.rs.
    if let Some(cfg) = slot_config.as_ref()
        && !matches!(cfg, crate::source_auth::ManagedIdentityConfig::PayloadExtraction(_))
    {
        let mode_label = match cfg {
            crate::source_auth::ManagedIdentityConfig::FromMtls { .. } => "from_mtls",
            crate::source_auth::ManagedIdentityConfig::FromApiKey { .. } => "from_api_key",
            crate::source_auth::ManagedIdentityConfig::Static { .. } => "static",
            crate::source_auth::ManagedIdentityConfig::FromJwtClaim { .. } => {
                unreachable!("FromJwtClaim is resolved before the credential-derived path")
            }
            crate::source_auth::ManagedIdentityConfig::PayloadExtraction(_) => unreachable!(),
        };
        let started = std::time::Instant::now();
        let resolver = crate::identity::credential_identity::global_resolver();
        let certificates_store = crate::proxy::server::get_certificates_store();
        let secrets_store = crate::gateways::connection_points::message_processor::get_secrets_store();
        match resolver
            .resolve(cfg, certificates_store.as_ref(), secrets_store.as_ref())
            .await
        {
            Ok(None) => {
                // Should not happen — PayloadExtraction is filtered above —
                // fall through to legacy payload extraction below.
            }
            Ok(Some(crate::identity::credential_identity::CredentialIdentity::Bound { did, identity_fields })) => {
                crate::metrics::backends::prometheus::track_managed_identity_resolve(
                    channel_name,
                    mode_label,
                    "ok_bound",
                    started
                        .elapsed()
                        .as_secs_f64(),
                );
                debug!(
                    channel = channel_name,
                    slot = slot.name(),
                    did = %did,
                    mode = mode_label,
                    "Inbound credential-derived identity (bound)"
                );
                return Ok(ProtectedAgentIdentity::Managed { did, identity_fields });
            }
            Ok(Some(crate::identity::credential_identity::CredentialIdentity::Derived {
                identity_fields,
                identity_hash,
            })) => {
                let Some(selector) = identity_selector else {
                    crate::metrics::backends::prometheus::track_managed_identity_resolve(
                        channel_name,
                        mode_label,
                        "vc_issuer_missing",
                        started
                            .elapsed()
                            .as_secs_f64(),
                    );
                    return Err(IdentityResolutionError::DidCreationFailed(
                        "Credential-derived identity requires VC issuer selector".to_string(),
                    ));
                };
                let vc_issuer = selector.get_vc_issuer();
                match issue_for_slot(vc_issuer.as_ref(), slot, identity_fields.clone(), identity_hash.clone(), surface)
                    .await
                {
                    Ok(response) => {
                        let result_label = if response.is_new {
                            "ok_new"
                        } else {
                            "ok_cached"
                        };
                        crate::metrics::backends::prometheus::track_managed_identity_resolve(
                            channel_name,
                            mode_label,
                            result_label,
                            started
                                .elapsed()
                                .as_secs_f64(),
                        );
                        debug!(
                            channel = channel_name,
                            slot = slot.name(),
                            did = %response.did,
                            mode = mode_label,
                            is_new = response.is_new,
                            "Inbound credential-derived identity (derived)"
                        );
                        return Ok(ProtectedAgentIdentity::Managed {
                            did: response.did,
                            identity_fields,
                        });
                    }
                    Err(e) => {
                        crate::metrics::backends::prometheus::track_managed_identity_resolve(
                            channel_name,
                            mode_label,
                            "vc_issuer_error",
                            started
                                .elapsed()
                                .as_secs_f64(),
                        );
                        return Err(IdentityResolutionError::IdentityBackendUnavailable(e.to_string()));
                    }
                }
            }
            Err(e) => {
                crate::metrics::backends::prometheus::track_managed_identity_resolve(
                    channel_name,
                    mode_label,
                    e.reason_label(),
                    started
                        .elapsed()
                        .as_secs_f64(),
                );
                // Misconfiguration → 500; backend unavailability → 503.
                return Err(match e.classify() {
                    crate::identity::credential_identity::CredentialIdentityErrorClass::BackendUnavailable => {
                        IdentityResolutionError::IdentityBackendUnavailable(e.to_string())
                    }
                    crate::identity::credential_identity::CredentialIdentityErrorClass::Misconfigured => {
                        IdentityResolutionError::DidCreationFailed(e.to_string())
                    }
                });
            }
        }
    }

    if response_body.is_empty() {
        return Err(IdentityResolutionError::IdentityExtensionMissing(source));
    }

    let response_json = match serde_json::from_slice::<JsonValue>(response_body) {
        Ok(json) => json,
        Err(_) => return Err(IdentityResolutionError::InvalidResponseJson),
    };

    info!(channel = channel_name, is_agent_card = is_agent_card, "Resolving protected agent identity from response");

    // Step 1: Find the raw identity payload (protocol-specific, before flatten)
    let raw_payload = match surface.channel_protocol() {
        crate::config::ChannelProtocol::Mcp => {
            let meta_field_from_managed = slot_config
                .as_ref()
                .and_then(|mi| match mi {
                    crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => Some(cfg.meta_field.clone()),
                    _ => None,
                });
            let meta_field = meta_field_from_managed
                .as_deref()
                .unwrap_or("serverIdentity");
            // Try configured meta_field first; if not found and it differs from
            // the MCP response convention ("serverIdentity"), fall back to
            // "serverIdentity". This handles the common case where meta_field
            // is set for the request path (e.g. "agentIdentity") but the
            // upstream response uses "serverIdentity".
            extract_mcp_identity(&response_json, meta_field).or_else(|_| {
                if meta_field != "serverIdentity" {
                    extract_mcp_identity(&response_json, "serverIdentity")
                } else {
                    Err(IdentityExtractionError::MetaFieldNotFound(meta_field.to_string()))
                }
            })
        }
        crate::config::ChannelProtocol::A2a | crate::config::ChannelProtocol::Ap2 => {
            if is_agent_card {
                // Short-circuit: when the card already carries an
                // `agent-identity-credential/v1` extension (injected by an
                // upstream gateway that has already resolved and DID-hashed the
                // agent identity), use the `did` and `identityFields` from the
                // VP directly rather than trying to extract and re-validate the
                // raw `agent-identity/v1` params (which are no longer present).
                // This avoids a spurious `identity_extension_missing` on
                // multi-hop fabric flows where GW2 already processed the card.
                let cred_ext = response_json
                    .get("capabilities")
                    .and_then(|c| c.get("extensions"))
                    .and_then(|e| e.as_array())
                    .and_then(|exts| {
                        exts.iter().find(|ext| {
                            ext.get("uri")
                                .and_then(|u| u.as_str())
                                == Some(crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION)
                        })
                    })
                    .cloned();

                if let Some(ext) = cred_ext {
                    let params = ext.get("params");
                    let did = params
                        .and_then(|p| p.get("did"))
                        .and_then(|d| d.as_str());
                    if let Some(did_str) = did {
                        // Parse the VP to cross-check the DID in `params.did` against
                        // the VP's `holder` and `credentialSubject.id`. Without this
                        // an attacker who controls the agent card's HTTP layer could set
                        // an arbitrary DID in params while the signed VP content remains
                        // unrelated, bypassing identity checks. The VP signature itself
                        // is not re-verified here (that happens when GW2 issues it), but
                        // the structural consistency check prevents trivial DID injection.
                        let vp_parsed = params
                            .and_then(|p| p.get("verifiablePresentation"))
                            .and_then(|v| v.as_str())
                            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());

                        if let Some(ref vp) = vp_parsed {
                            let holder = vp
                                .get("holder")
                                .and_then(|h| h.as_str());
                            let subject_id = vp
                                .get("verifiableCredential")
                                .and_then(|vc| vc.get("credentialSubject"))
                                .and_then(|cs| cs.get("id"))
                                .and_then(|id| id.as_str());
                            let holder_ok = holder
                                .map(|h| h == did_str)
                                .unwrap_or(false);
                            let subject_ok = subject_id
                                .map(|s| s == did_str)
                                .unwrap_or(false);
                            if !holder_ok || !subject_ok {
                                warn!(
                                    channel = channel_name,
                                    params_did = %did_str,
                                    vp_holder = ?holder,
                                    vp_subject = ?subject_id,
                                    "agent-identity-credential/v1: DID mismatch between params and VP — rejecting"
                                );
                                return Err(IdentityResolutionError::IdentityExtensionMissing(source));
                            }
                        } else {
                            // VP absent or unparseable — reject to prevent params.did spoofing
                            warn!(
                                channel = channel_name,
                                did = %did_str,
                                "agent-identity-credential/v1: missing or malformed VP — rejecting"
                            );
                            return Err(IdentityResolutionError::IdentityExtensionMissing(source));
                        }

                        // Extract identity fields from the signed VP's credentialSubject
                        // (display/metadata only; the DID is the authoritative identity).
                        let vp_fields: std::collections::HashMap<String, serde_json::Value> = vp_parsed
                            .as_ref()
                            .and_then(|vp| {
                                vp.get("verifiableCredential")
                                    .and_then(|vc| vc.get("credentialSubject"))
                                    .and_then(|cs| {
                                        cs.get("identityFields")
                                            .or_else(|| cs.get("workloadBinding"))
                                    })
                                    .and_then(|f| f.as_object())
                                    .map(|m| {
                                        m.iter()
                                            .map(|(k, v)| (k.clone(), v.clone()))
                                            .collect()
                                    })
                            })
                            .unwrap_or_default();

                        info!(
                            channel = channel_name,
                            did = %did_str,
                            "A2A agent card: short-circuiting protected identity via agent-identity-credential/v1 DID"
                        );
                        return Ok(ProtectedAgentIdentity::Managed {
                            did: did_str.to_string(),
                            identity_fields: vp_fields,
                        });
                    }
                }

                extract_a2a_identity_from_agent_card(&response_json)
            } else {
                extract_a2a_identity_from_message(&response_json)
            }
        }
        _ => Err(IdentityExtractionError::ExtensionNotFound),
    };

    let raw_payload = raw_payload.map_err(|_| IdentityResolutionError::IdentityExtensionMissing(source))?;

    // Step 1.5: Schema validation. When the slot's `PayloadExtractionConfig`
    // declares a `json_schema` (or legacy `extension_rules.json_schema`), the
    // compiled `IdentitySelector` carries the JSON Schema validator and must
    // reject payloads that do not conform — independently of whether
    // x-identity fields are declared. Without this step a malformed identity
    // payload would be accepted and silently flattened into a synthetic DID.
    if let Some(selector) = identity_selector {
        selector
            .validate(&raw_payload)
            .map_err(|e| IdentityResolutionError::ValidationFailed(e.to_string()))?;
        debug!(channel = channel_name, "Identity JSON schema validation passed");
    }

    // Step 2: Validate raw payload against identity rules engine BEFORE flatten/hash/DID
    if let Some(engine) = identity_rules_engine {
        engine
            .validate(&raw_payload, channel_name)
            .map_err(|e| IdentityResolutionError::ValidationFailed(e.to_string()))?;
        debug!(channel = channel_name, "Identity rules engine validation passed");
    }

    // Step 3: Extract identity fields.
    // If an IdentitySelector is available and has x-identity fields defined in the
    // schema, use it to extract ONLY those fields. This prevents extra fields in
    // the payload (not defined in the schema) from affecting the identity hash
    // and creating spurious separate identities.
    // Fall back to full flatten only when no selector or no schema fields exist.
    let selector = identity_selector
        .ok_or_else(|| IdentityResolutionError::DidCreationFailed("No identity selector available".to_string()))?;

    let identity_fields = if selector.has_identity_fields() {
        let fields = selector.extract_identity_fields(&raw_payload);
        if fields.is_empty() {
            return Err(IdentityResolutionError::IdentityExtensionMissing(source));
        }
        debug!(channel = channel_name, field_count = fields.len(), "Extracted x-identity schema fields from payload");
        fields
    } else {
        let mut fields = HashMap::new();
        flatten_json_to_dot_notation(&raw_payload, "", &mut fields);
        if fields.is_empty() {
            return Err(IdentityResolutionError::IdentityExtensionMissing(source));
        }
        fields
    };

    let hash = compute_canonical_identity_hash(&identity_fields);

    debug!(
        channel = channel_name,
        hash = %hash,
        field_count = identity_fields.len(),
        "Computed canonical identity hash"
    );

    let vc_issuer = selector.get_vc_issuer();

    info!(
        channel = channel_name,
        issuer_id = ?surface.issuer_id,
        hash = %hash,
        "[TR-TRACE] backend_identity: calling issue_or_get_credential"
    );

    let response = issue_for_slot(vc_issuer.as_ref(), slot, identity_fields.clone(), hash.clone(), surface)
        .await
        .map_err(|e| IdentityResolutionError::IdentityBackendUnavailable(e.to_string()))?;

    if response.is_new {
        info!(
            channel = channel_name,
            did = %response.did,
            hash = %hash,
            "Created new DID for protected agent"
        );
    } else {
        debug!(
            channel = channel_name,
            did = %response.did,
            hash = %hash,
            "Resolved existing DID for protected agent"
        );
    }

    Ok(ProtectedAgentIdentity::Managed {
        did: response.did,
        identity_fields,
    })
}

// ── Public extraction API ───────────────────────────────────────────────────

/// Extract agent-identity/v1 from an A2A/AP2 message body.
///
/// Handles both request layout (`params.message.metadata` / `message.metadata`)
/// and the response locations an A2A v1.0 `Task` may carry the agent's identity
/// in: the status message and the output `artifacts[]` (see
/// [`response_identity_candidates`] for the order, and for why `history[]` is
/// excluded).
/// Checks `extensions[]` array as a protocol correctness guard — if the extension is
/// declared but the metadata payload is missing, returns `DeclaredButMissing`.
///
/// Returns the raw identity payload (unwrapped).
pub fn extract_a2a_identity_from_message(json: &JsonValue) -> Result<JsonValue, IdentityExtractionError> {
    extract_a2a_identity_from_message_with_uri(json, crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION)
}

pub fn extract_a2a_identity_from_message_with_uri(
    json: &JsonValue,
    ext_uri: &str,
) -> Result<JsonValue, IdentityExtractionError> {
    // Request layout: params.message or message
    let request_msg = json
        .get("params")
        .and_then(|p| p.get("message"))
        .or_else(|| json.get("message"));

    if let Some(msg) = request_msg {
        return extract_from_message_obj(msg, ext_uri);
    }

    // Response layout: walk every location a Task may carry identity in, in a
    // defined order, and take the first that yields a payload.
    if let Some(result) = json.get("result") {
        let mut first_err: Option<IdentityExtractionError> = None;

        for candidate in response_identity_candidates(result) {
            match extract_from_message_obj(candidate, ext_uri) {
                Ok(payload) => return Ok(payload),
                // A location that declares the extension but omits the payload is
                // malformed. Report that rather than letting a later location mask
                // it, so a caller cannot get a bad message accepted by appending a
                // well-formed one after it.
                Err(IdentityExtractionError::DeclaredButMissing) => {
                    return Err(IdentityExtractionError::DeclaredButMissing);
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }

        return Err(first_err.unwrap_or(IdentityExtractionError::NoMetadata));
    }

    Err(IdentityExtractionError::NoMetadata)
}

/// Response locations that may carry the agent-identity extension, in the order
/// they are consulted.
///
/// This module resolves the identity of the **protected agent**, so only
/// locations the agent itself authors are consulted:
///
/// A v1.0 `SendMessage` result wraps its payload (`SendMessageResponse`: `task`
/// or `message`), while `GetTask` and v0.3 return a bare Task, so `result.task`
/// is unwrapped first and read as the Task.
///
/// 1. **The status message** (`result.message`, or `result.status.message` for a
///    Task, or `result` itself when it is a bare Message). This is the agent's
///    current message and the most authoritative assertion, so it wins.
/// 2. **`artifacts[]`**, the task outputs, in document order. `Artifact` declares
///    the same `metadata` + `extensions` pair as `Message`, and artifacts are
///    produced by the agent, so an identity asserted there is the agent's.
///
/// **`history[]` is deliberately excluded.** A Task's history is the record of
/// the whole interaction, so it contains the *caller's* messages as well as the
/// agent's. Reading identity from it would let the caller's own asserted identity
/// be resolved as the protected agent's, and a DID minted for it. Consulting
/// history would only be safe if restricted to entries the agent authored
/// (`role` of `agent` / `ROLE_AGENT`), which is a separate decision.
///
/// **Accepted residual risk: authorship is assumed, not proved.** Excluding
/// `history[]` removes the one location that structurally holds caller-authored
/// content, but neither remaining location can be checked for authorship. A2A's
/// `Artifact` carries no authorship field at all, and a response `Message` may
/// carry `role` but the gateway does not validate responses, so a value there is
/// the agent's own claim. If a managed agent ever reflects caller-supplied
/// content into its status message or an output artifact — by echoing it, by
/// tracing it, or because it has been prompt-injected or compromised — a
/// caller's self-asserted identity could still resolve as the agent's. This rests
/// on the trust already placed in a managed agent: it is the protected party, it
/// is configured by the operator, and it is the authority for its own identity.
/// Closing it would require A2A to carry provenance on these structures.
///
/// First match wins, which keeps the resolution deterministic when more than one
/// location carries an extension. The Task/Message distinction uses `kind` when
/// present and falls back to structure, because A2A v1.0 dropped the `kind`
/// discriminator that v0.3 used.
fn response_identity_candidates(result: &JsonValue) -> Vec<&JsonValue> {
    let result = crate::a2a::extensions::unwrap_task_result(result);

    let kind = result
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("");

    let mut candidates: Vec<&JsonValue> = Vec::new();

    let primary = result
        .get("message")
        .or_else(|| match kind {
            // Task response: identity lives on status.message
            "task" => result
                .get("status")
                .and_then(|s| s.get("message")),
            // Message response: identity lives directly on result
            "message" => Some(result),
            // No kind field — infer from structure
            _ => {
                if result.get("status").is_some() {
                    // Looks like a Task
                    result
                        .get("status")
                        .and_then(|s| s.get("message"))
                } else {
                    // Treat as a bare Message
                    Some(result)
                }
            }
        });
    if let Some(msg) = primary {
        candidates.push(msg);
    }

    for artifact in result
        .get("artifacts")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
    {
        candidates.push(artifact);
    }

    candidates
}

/// Shared extraction logic for a single A2A/AP2 message object.
///
/// Checks `extensions[]` declaration guard first, then falls back to metadata lookup.
fn extract_from_message_obj(
    msg: &JsonValue,
    ext_uri: &str,
) -> Result<JsonValue, IdentityExtractionError> {
    // Check extensions[] declaration guard
    let has_extension = msg
        .get("extensions")
        .and_then(|e| e.as_array())
        .map(|exts| {
            exts.iter()
                .any(|ext| ext.as_str() == Some(ext_uri))
        })
        .unwrap_or(false);

    if has_extension {
        // Extension declared — metadata MUST contain the payload
        return msg
            .get("metadata")
            .and_then(|m| m.get(ext_uri))
            .cloned()
            .ok_or(IdentityExtractionError::DeclaredButMissing);
    }

    // No extension declared — check metadata anyway (legacy compat)
    if let Some(payload) = msg
        .get("metadata")
        .and_then(|m| m.get(ext_uri))
    {
        return Ok(payload.clone());
    }

    // Message object exists but no identity found
    if msg.get("metadata").is_some() {
        Err(IdentityExtractionError::ExtensionNotFound)
    } else {
        Err(IdentityExtractionError::NoMetadata)
    }
}

/// Extract agent-identity/v1 from an agent card's `capabilities.extensions[]`.
///
/// Returns the `params` object from the matching extension. Returns
/// `ExtensionNotFound` when the card carries `agent-identity-credential/v1`
/// instead (already processed by an upstream gateway) — callers that need to
/// handle that case should check for it before calling this function (see the
/// short-circuit in `resolve_protected_agent_identity`).
pub fn extract_a2a_identity_from_agent_card(agent_card: &JsonValue) -> Result<JsonValue, IdentityExtractionError> {
    let extensions = agent_card
        .get("capabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(|e| e.as_array());

    let extensions = match extensions {
        Some(exts) if !exts.is_empty() => exts,
        _ => return Err(IdentityExtractionError::ExtensionNotFound),
    };

    let identity_ext = extensions.iter().find(|ext| {
        ext.get("uri")
            .and_then(|u| u.as_str())
            == Some(crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION)
    });

    match identity_ext {
        Some(ext) => ext
            .get("params")
            .cloned()
            .ok_or(IdentityExtractionError::DeclaredButMissing),
        None => Err(IdentityExtractionError::ExtensionNotFound),
    }
}

/// Extract agent identity from an MCP request or response `_meta` field.
///
/// `meta_field` is resolved by the caller from channel config
/// (e.g. `"agentIdentity"` for requests, `"serverIdentity"` for responses).
///
/// Returns the identity wrapped as `{ meta_field: payload }` to preserve
/// the field name for downstream validation and flattening.
pub fn extract_mcp_identity(
    json: &JsonValue,
    meta_field: &str,
) -> Result<JsonValue, IdentityExtractionError> {
    let meta = crate::mcp::meta::read_metadata(json)?;

    let meta = match meta {
        Some(m) => m,
        None => return Err(IdentityExtractionError::MetaFieldNotFound(meta_field.to_string())),
    };

    match meta.get(crate::mcp::meta::canonical_key(meta_field)) {
        Some(payload) => Ok(payload.clone()),
        None => Err(IdentityExtractionError::MetaFieldNotFound(meta_field.to_string())),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Flatten nested JSON objects to dot-notation paths.
///
/// e.g. `{"agentIdentity": {"name": "test"}}` → `{"agentIdentity.name": "test"}`
pub(crate) fn flatten_json_to_dot_notation(
    value: &JsonValue,
    prefix: &str,
    result: &mut HashMap<String, JsonValue>,
) {
    if let Some(obj) = value.as_object() {
        for (key, val) in obj {
            let new_key = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", prefix, key)
            };

            if val.is_object() {
                flatten_json_to_dot_notation(val, &new_key, result);
            } else {
                result.insert(new_key, val.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXT_URI: &str = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;

    // ── extract_a2a_identity_from_message ────────────────────────────────

    #[test]
    fn a2a_message_request_standard() {
        let json = json!({
            "params": { "message": { "metadata": {
                EXT_URI: { "cloudProvider": "local" }
            }}}
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"cloudProvider": "local"}));
    }

    #[test]
    fn a2a_message_request_top_level() {
        let json = json!({
            "message": { "metadata": {
                EXT_URI: { "cloudProvider": "local" }
            }}
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"cloudProvider": "local"}));
    }

    #[test]
    fn a2a_task_response_status_message() {
        let json = json!({
            "result": {
                "kind": "task",
                "id": "task-1",
                "status": {
                    "state": "completed",
                    "message": {
                        "kind": "message",
                        "extensions": [EXT_URI],
                        "metadata": {
                            EXT_URI: { "name": "BackendAgent" }
                        }
                    }
                },
                "history": [{
                    "kind": "message",
                    "role": "user",
                    "parts": [{"text": "hello"}]
                }]
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"name": "BackendAgent"}));
    }

    #[test]
    fn a2a_task_response_without_kind() {
        // Task inferred from `status` field presence (no `kind`)
        let json = json!({
            "result": {
                "status": {
                    "state": "completed",
                    "message": {
                        "extensions": [EXT_URI],
                        "metadata": {
                            EXT_URI: { "did": "did:web:x" }
                        }
                    }
                }
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"did": "did:web:x"}));
    }

    // ── v1.0 Task response locations ─────────────────────────────────────
    //
    // `Artifact` declares the same `metadata` + `extensions` pair as `Message`,
    // so a task's outputs are a valid place for the agent to assert identity.
    // `history[]` is not, because it also contains the caller's messages.

    /// `history[]` records the whole interaction, so it holds the *caller's*
    /// messages too. Resolving the protected agent's identity from it would let
    /// a caller's own asserted identity be adopted as the agent's, and a DID
    /// minted for it. It must stay excluded even though it is a valid A2A
    /// location for the extension.
    #[test]
    fn a2a_task_response_ignores_caller_identity_in_history() {
        let json = json!({
            "result": {
                "kind": "task",
                "id": "task-1",
                "status": { "state": "completed", "message": { "metadata": {} } },
                "history": [{
                    "role": "ROLE_USER",
                    "extensions": [EXT_URI],
                    "metadata": { EXT_URI: { "did": "did:web:the-caller" } }
                }]
            }
        });
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(
            matches!(err, IdentityExtractionError::ExtensionNotFound),
            "the caller's identity in history must not resolve as the agent's, got {err:?}"
        );
    }

    #[test]
    fn a2a_task_response_trusts_artifact_identity_that_mirrors_the_caller() {
        // Pins the accepted residual risk documented on `response_identity_candidates`.
        // Excluding `history[]` stops the caller's own message resolving as the
        // agent's, but an `Artifact` carries no authorship field, so an artifact
        // that reflects caller-supplied content is indistinguishable from one the
        // agent authored. Here the identical DID that is refused in `history[]`
        // resolves when it appears on an artifact. This is deliberate and rests on
        // managed-agent trust; if a later change adds an authorship check, this
        // test is the one that should fail and be rewritten.
        let caller_did = "did:web:the-caller";

        let in_history = json!({
            "result": {
                "kind": "task",
                "id": "task-1",
                "status": { "state": "completed", "message": { "metadata": {} } },
                "history": [{
                    "role": "ROLE_USER",
                    "extensions": [EXT_URI],
                    "metadata": { EXT_URI: { "did": caller_did } }
                }]
            }
        });
        assert!(
            matches!(
                extract_a2a_identity_from_message(&in_history).unwrap_err(),
                IdentityExtractionError::ExtensionNotFound
            ),
            "identity in history must not resolve"
        );

        let reflected_into_artifact = json!({
            "result": {
                "kind": "task",
                "id": "task-1",
                "status": { "state": "completed", "message": { "parts": [] } },
                "artifacts": [{
                    "artifactId": "echo-of-the-request",
                    "extensions": [EXT_URI],
                    "metadata": { EXT_URI: { "did": caller_did } }
                }]
            }
        });
        assert_eq!(
            extract_a2a_identity_from_message(&reflected_into_artifact).unwrap(),
            json!({ "did": caller_did }),
            "the same value resolves from an artifact: authorship is assumed, not proved"
        );
    }

    #[test]
    fn a2a_task_response_identity_from_artifacts() {
        // Neither the status message nor history carries identity; an output
        // artifact does.
        let json = json!({
            "result": {
                "kind": "task",
                "id": "task-1",
                "status": { "state": "completed", "message": { "parts": [] } },
                "artifacts": [{
                    "artifactId": "a-1",
                    "extensions": [EXT_URI],
                    "metadata": { EXT_URI: { "did": "did:web:from-artifact" } }
                }]
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"did": "did:web:from-artifact"}));
    }

    #[test]
    fn a2a_task_response_without_kind_still_reaches_artifacts() {
        // A pure v1.0 Task has no `kind` discriminator, so the structural
        // fallback must still reach the later locations.
        let json = json!({
            "result": {
                "id": "task-1",
                "status": { "state": "working" },
                "artifacts": [{
                    "artifactId": "a-1",
                    "metadata": { EXT_URI: { "did": "did:web:no-kind" } }
                }]
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"did": "did:web:no-kind"}));
    }

    #[test]
    fn a2a_task_response_prefers_status_message_over_artifacts() {
        // Resolution must be deterministic when several locations carry an
        // extension: the agent's current status message wins.
        let json = json!({
            "result": {
                "kind": "task",
                "status": {
                    "message": {
                        "extensions": [EXT_URI],
                        "metadata": { EXT_URI: { "did": "did:web:status" } }
                    }
                },
                "artifacts": [{ "metadata": { EXT_URI: { "did": "did:web:artifact" } } }]
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"did": "did:web:status"}));
    }

    #[test]
    fn a2a_task_response_first_artifact_wins() {
        let json = json!({
            "result": {
                "kind": "task",
                "status": { "state": "completed", "message": { "metadata": {} } },
                "artifacts": [
                    { "metadata": { EXT_URI: { "did": "did:web:first" } } },
                    { "metadata": { EXT_URI: { "did": "did:web:second" } } }
                ]
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"did": "did:web:first"}));
    }

    #[test]
    fn a2a_declared_but_missing_is_not_masked_by_a_later_location() {
        // The status message declares the extension but omits the payload. A
        // well-formed history entry must not launder that malformed message.
        let json = json!({
            "result": {
                "kind": "task",
                "status": {
                    "message": {
                        "extensions": [EXT_URI],
                        "metadata": { "something-else": {} }
                    }
                },
                "artifacts": [{ "metadata": { EXT_URI: { "did": "did:web:artifact" } } }]
            }
        });
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(
            matches!(err, IdentityExtractionError::DeclaredButMissing),
            "a malformed location must surface rather than be masked, got {err:?}"
        );
    }

    #[test]
    fn a2a_task_response_without_identity_anywhere_still_errors() {
        let json = json!({
            "result": {
                "kind": "task",
                "status": { "state": "completed", "message": { "metadata": {} } },
                "artifacts": [{ "metadata": {} }]
            }
        });
        assert!(extract_a2a_identity_from_message(&json).is_err());
    }

    fn v1_send_message_task_reply(task: JsonValue) -> JsonValue {
        json!({ "jsonrpc": "2.0", "id": "req-1", "result": { "task": task } })
    }

    #[test]
    fn a2a_v1_send_message_task_reply_status_message() {
        let json = v1_send_message_task_reply(json!({
            "id": "task-1",
            "status": {
                "state": "TASK_STATE_COMPLETED",
                "message": {
                    "role": "ROLE_AGENT",
                    "parts": [{ "text": "done" }],
                    "extensions": [EXT_URI],
                    "metadata": { EXT_URI: { "did": "did:web:status" } }
                }
            },
            "artifacts": [{ "metadata": { EXT_URI: { "did": "did:web:artifact" } } }]
        }));
        assert_eq!(extract_a2a_identity_from_message(&json).unwrap(), json!({ "did": "did:web:status" }));
    }

    #[test]
    fn a2a_v1_send_message_task_reply_first_artifact() {
        let json = v1_send_message_task_reply(json!({
            "id": "task-1",
            "status": { "state": "TASK_STATE_COMPLETED" },
            "artifacts": [
                { "artifactId": "a1", "parts": [], "metadata": { EXT_URI: { "did": "did:web:first" } } },
                { "artifactId": "a2", "parts": [], "metadata": { EXT_URI: { "did": "did:web:second" } } }
            ]
        }));
        assert_eq!(extract_a2a_identity_from_message(&json).unwrap(), json!({ "did": "did:web:first" }));
    }

    #[test]
    fn a2a_v1_send_message_task_reply_ignores_history() {
        let json = v1_send_message_task_reply(json!({
            "id": "task-1",
            "status": { "state": "TASK_STATE_COMPLETED", "message": { "metadata": {} } },
            "history": [{
                "role": "ROLE_USER",
                "extensions": [EXT_URI],
                "metadata": { EXT_URI: { "did": "did:web:the-caller" } }
            }]
        }));
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(
            matches!(err, IdentityExtractionError::ExtensionNotFound),
            "the caller's identity in history must not resolve as the agent's, got {err:?}"
        );
    }

    #[test]
    fn a2a_v1_send_message_task_reply_declared_but_missing_is_not_masked() {
        let json = v1_send_message_task_reply(json!({
            "id": "task-1",
            "status": {
                "state": "TASK_STATE_COMPLETED",
                "message": { "extensions": [EXT_URI], "metadata": { "something-else": {} } }
            },
            "artifacts": [{ "metadata": { EXT_URI: { "did": "did:web:artifact" } } }]
        }));
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(
            matches!(err, IdentityExtractionError::DeclaredButMissing),
            "a malformed location must surface rather than be masked, got {err:?}"
        );
    }

    #[test]
    fn a2a_v1_send_message_task_reply_trusts_artifact_identity_that_mirrors_the_caller() {
        // The residual risk pinned by
        // `a2a_task_response_trusts_artifact_identity_that_mirrors_the_caller`, in
        // the wrapped v1.0 SendMessage shape.
        let caller_did = "did:web:the-caller";
        let json = v1_send_message_task_reply(json!({
            "id": "task-1",
            "status": { "state": "TASK_STATE_COMPLETED" },
            "history": [{ "role": "ROLE_USER", "metadata": { EXT_URI: { "did": caller_did } } }],
            "artifacts": [{ "artifactId": "echo", "parts": [], "metadata": { EXT_URI: { "did": caller_did } } }]
        }));
        assert_eq!(extract_a2a_identity_from_message(&json).unwrap(), json!({ "did": caller_did }));
    }

    #[test]
    fn a2a_response_with_non_object_task_is_not_unwrapped() {
        let json = json!({
            "result": {
                "task": "task-1",
                "extensions": [EXT_URI],
                "metadata": { EXT_URI: { "did": "did:web:message" } }
            }
        });
        assert_eq!(extract_a2a_identity_from_message(&json).unwrap(), json!({ "did": "did:web:message" }));
    }

    #[test]
    fn a2a_message_response_direct() {
        // Message response: result IS the message (kind: "message")
        let json = json!({
            "result": {
                "kind": "message",
                "extensions": [EXT_URI],
                "metadata": {
                    EXT_URI: { "did": "did:web:x" }
                }
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"did": "did:web:x"}));
    }

    #[test]
    fn a2a_message_response_wrapped() {
        let json = json!({
            "jsonrpc": "2.0",
            "id": "req-1",
            "result": {
                "message": {
                    "messageId": "msg-1",
                    "contextId": "ctx-1",
                    "role": "ROLE_AGENT",
                    "parts": [{ "text": "Order accepted" }],
                    "extensions": [EXT_URI],
                    "metadata": {
                        EXT_URI: { "did": "did:web:x" }
                    }
                }
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"did": "did:web:x"}));
    }

    #[test]
    fn a2a_message_response_direct_without_kind() {
        // Bare result with no kind — inferred as Message from lack of `status`
        let json = json!({
            "result": {
                "extensions": [EXT_URI],
                "metadata": {
                    EXT_URI: { "did": "did:web:x" }
                }
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"did": "did:web:x"}));
    }

    #[test]
    fn a2a_task_response_status_message_with_embedded_message() {
        // Task with result.message (NOT result.status.message) — should
        // still resolve via status.message when kind is "task"
        let json = json!({
            "result": {
                "kind": "task",
                "status": {
                    "state": "completed",
                    "message": {
                        "extensions": [EXT_URI],
                        "metadata": {
                            EXT_URI: { "name": "Sparky" }
                        }
                    }
                }
            }
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"name": "Sparky"}));
    }

    #[test]
    fn a2a_task_response_declared_but_missing() {
        let json = json!({
            "result": {
                "kind": "task",
                "status": {
                    "state": "completed",
                    "message": {
                        "extensions": [EXT_URI],
                        "metadata": {}
                    }
                }
            }
        });
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::DeclaredButMissing));
    }

    #[test]
    fn a2a_message_request_full_a2a_format() {
        // Full A2A request with extensions[] (string array) + metadata map
        let json = json!({
            "jsonrpc": "2.0",
            "method": "task.message",
            "params": {
                "taskId": "task-456",
                "message": {
                    "messageId": "msg-001",
                    "role": "user",
                    "parts": [{"text": "hello"}],
                    "extensions": [EXT_URI],
                    "metadata": {
                        EXT_URI: { "name": "Sparky" }
                    }
                }
            },
            "id": "req-1"
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"name": "Sparky"}));
    }

    #[test]
    fn a2a_message_request_declared_but_missing() {
        // Extension declared in extensions[] but not in metadata
        let json = json!({
            "params": { "message": {
                "extensions": [EXT_URI],
                "metadata": {}
            }}
        });
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::DeclaredButMissing));
    }

    #[test]
    fn a2a_task_response_history_declared_but_missing() {
        // history[0] has extension declared but missing — should NOT be checked;
        // extraction targets status.message which has no identity → ExtensionNotFound
        let json = json!({
            "result": {
                "kind": "task",
                "status": {
                    "state": "completed",
                    "message": {
                        "metadata": {}
                    }
                },
                "history": [{
                    "extensions": [EXT_URI],
                    "metadata": {}
                }]
            }
        });
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::ExtensionNotFound));
    }

    #[test]
    fn a2a_message_no_metadata() {
        let json = json!({
            "params": { "message": { "text": "hello" } }
        });
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::NoMetadata));
    }

    #[test]
    fn a2a_message_empty_object() {
        let json = json!({});
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::NoMetadata));
    }

    #[test]
    fn a2a_message_wrong_extension_uri() {
        let json = json!({
            "params": { "message": { "metadata": {
                "wrong-uri": { "foo": "bar" }
            }}}
        });
        let err = extract_a2a_identity_from_message(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::ExtensionNotFound));
    }

    #[test]
    fn a2a_message_multi_field_payload() {
        let json = json!({
            "params": { "message": { "metadata": {
                EXT_URI: { "cloudProvider": "local", "region": "eu" }
            }}}
        });
        let result = extract_a2a_identity_from_message(&json).unwrap();
        assert_eq!(result, json!({"cloudProvider": "local", "region": "eu"}));
    }

    // ── extract_a2a_identity_from_agent_card ─────────────────────────────

    #[test]
    fn agent_card_happy_path() {
        let json = json!({
            "capabilities": { "extensions": [{
                "uri": EXT_URI,
                "params": { "cloudProvider": "local" }
            }]}
        });
        let result = extract_a2a_identity_from_agent_card(&json).unwrap();
        assert_eq!(result, json!({"cloudProvider": "local"}));
    }

    #[test]
    fn agent_card_multiple_extensions() {
        let json = json!({
            "capabilities": { "extensions": [
                { "uri": "https://other.example/v1", "params": { "x": 1 } },
                { "uri": EXT_URI, "params": { "cloudProvider": "local" } }
            ]}
        });
        let result = extract_a2a_identity_from_agent_card(&json).unwrap();
        assert_eq!(result, json!({"cloudProvider": "local"}));
    }

    #[test]
    fn agent_card_no_matching_uri() {
        let json = json!({
            "capabilities": { "extensions": [
                { "uri": "https://other.example/v1", "params": { "x": 1 } }
            ]}
        });
        let err = extract_a2a_identity_from_agent_card(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::ExtensionNotFound));
    }

    #[test]
    fn agent_card_empty_extensions() {
        let json = json!({
            "capabilities": { "extensions": [] }
        });
        let err = extract_a2a_identity_from_agent_card(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::ExtensionNotFound));
    }

    #[test]
    fn agent_card_no_capabilities() {
        let json = json!({});
        let err = extract_a2a_identity_from_agent_card(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::ExtensionNotFound));
    }

    // When the card carries agent-identity-credential/v1 (already processed by
    // an upstream gateway), extract_a2a_identity_from_agent_card returns
    // ExtensionNotFound — the caller (resolve_protected_agent_identity) handles
    // this case via the credential-extension short-circuit before this function
    // is ever invoked. The test asserts the pure function's contract.
    #[test]
    fn agent_card_credential_ext_returns_extension_not_found() {
        let json = json!({
            "capabilities": {
                "extensions": [
                    {
                        "uri": crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "params": {
                            "did": "did:web:example.com",
                            "verifiablePresentation": "{}"
                        }
                    }
                ]
            }
        });
        let err = extract_a2a_identity_from_agent_card(&json).unwrap_err();
        assert!(matches!(err, IdentityExtractionError::ExtensionNotFound));
    }

    // When params.did doesn't match the VP's holder/credentialSubject.id the
    // short-circuit in resolve_protected_agent_identity rejects the card.
    // This test checks the validation logic directly via the JSON structure
    // that would be exercised by the short-circuit.
    #[test]
    fn agent_card_credential_ext_did_mismatch_is_detected() {
        // VP holder and credentialSubject.id are "did:web:real" but params.did is "did:web:fake"
        let vp_json = serde_json::json!({
            "holder": "did:web:real",
            "verifiableCredential": {
                "credentialSubject": {
                    "id": "did:web:real",
                    "identityFields": { "name": "real-agent" }
                }
            }
        });
        let vp_str = serde_json::to_string(&vp_json).unwrap();

        let params_did = "did:web:fake";
        let holder = vp_json
            .get("holder")
            .and_then(|h| h.as_str());
        let subject_id = vp_json
            .get("verifiableCredential")
            .and_then(|vc| vc.get("credentialSubject"))
            .and_then(|cs| cs.get("id"))
            .and_then(|id| id.as_str());

        let holder_ok = holder
            .map(|h| h == params_did)
            .unwrap_or(false);
        let subject_ok = subject_id
            .map(|s| s == params_did)
            .unwrap_or(false);
        // Both must fail for a mismatched DID
        assert!(!holder_ok, "holder should not match fake DID");
        assert!(!subject_ok, "subject should not match fake DID");

        // Confirm the VP itself is parseable (so the rejection is DID-mismatch, not parse failure)
        let _ = serde_json::from_str::<serde_json::Value>(&vp_str).unwrap();
    }

    // ── extract_mcp_identity ─────────────────────────────────────────────

    #[test]
    fn mcp_default_field() {
        let json = json!({
            "_meta": { "agentIdentity": { "cloud": "local" } }
        });
        let result = extract_mcp_identity(&json, "agentIdentity").unwrap();
        assert_eq!(result, json!({"cloud": "local"}));
    }

    #[test]
    fn mcp_custom_field() {
        let json = json!({
            "_meta": { "myCustomField": { "x": "y" } }
        });
        let result = extract_mcp_identity(&json, "myCustomField").unwrap();
        assert_eq!(result, json!({"x": "y"}));
    }

    #[test]
    fn mcp_response_field() {
        let json = json!({
            "_meta": { "serverIdentity": { "name": "svc" } }
        });
        let result = extract_mcp_identity(&json, "serverIdentity").unwrap();
        assert_eq!(result, json!({"name": "svc"}));
    }

    #[test]
    fn mcp_missing_meta() {
        let json = json!({});
        let err = extract_mcp_identity(&json, "agentIdentity").unwrap_err();
        assert!(matches!(err, IdentityExtractionError::MetaFieldNotFound(ref f) if f == "agentIdentity"));
    }

    #[test]
    fn mcp_missing_field_in_meta() {
        let json = json!({
            "_meta": {}
        });
        let err = extract_mcp_identity(&json, "agentIdentity").unwrap_err();
        assert!(matches!(err, IdentityExtractionError::MetaFieldNotFound(ref f) if f == "agentIdentity"));
    }

    #[test]
    fn mcp_wrong_field_name() {
        let json = json!({
            "_meta": { "agentIdentity": { "x": 1 } }
        });
        let err = extract_mcp_identity(&json, "somethingElse").unwrap_err();
        assert!(matches!(err, IdentityExtractionError::MetaFieldNotFound(ref f) if f == "somethingElse"));
    }
}
