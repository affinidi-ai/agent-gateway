//! The managed agent identity a Transit Point takes from its own caller's
//! credential, and the agent identity a request body asserts.

use std::time::Instant;
use tracing::{debug, warn};

use super::{IdentityResolutionFailure, OutboundPipelineContext, OutboundPipelineError};
use crate::config::ChannelProtocol;
use crate::proxy::backend_identity::ProtectedAgentIdentity;
use crate::state::OutboundProxyState;

/// The managed agent's identity on a Transit Point that takes it from its
/// caller's credential: a `from_api_key` naming no stored key reads the API key,
/// `from_jwt_claim` the claims of the JWT, and a `from_mtls` naming no stored
/// certificate the client certificate, that the Transit Point's own
/// `source_auth` verified on this request. The DID is the one the Access Point
/// gives the same key or claim value, recorded as this Transit Point's managed
/// agent unless the identity already has an origin. Once derived, every identity
/// the request body asserts is removed, so only the gateway's own credential is
/// forwarded. Without a DID an API key or certificate caller goes on to policy
/// with no identity, while a JWT caller is refused as on the Access Point: `500`
/// with no VC issuer, `502` when issuance fails. A derivation the gateway cannot
/// complete refuses the request before anything is forwarded, with a fixed body:
/// `422` for a token without the claim, as on the Access Point, `500` when
/// misconfigured and `503` when a store is unavailable; why is logged.
pub(super) async fn resolve_caller_bound_agent_identity(
    state: &OutboundProxyState,
    ctx: &mut OutboundPipelineContext,
    identity: &crate::source_auth::ManagedIdentityConfig,
    credential: crate::source_auth::CallerCredential,
) -> Result<(), OutboundPipelineError> {
    use crate::identity::credential_identity::{CredentialIdentityError, CredentialIdentityErrorClass};
    use crate::proxy::handler::CALLER_IDENTITY_UNRESOLVED;
    use crate::source_auth::CallerCredential;

    let started = Instant::now();
    let channel = ctx.surface.name.clone();
    let mode = credential.identity_mode();
    let track = |outcome: &str| {
        crate::metrics::backends::prometheus::track_managed_identity_resolve(
            &channel,
            mode,
            outcome,
            started
                .elapsed()
                .as_secs_f64(),
        );
    };
    let derived = match ctx
        .authenticated_identity
        .as_ref()
        .filter(|_| ctx.authenticated_by == Some(crate::surface_context::TransitClientVerification::SourceAuth))
    {
        Some(caller) => {
            crate::identity::credential_identity::global_resolver()
                .resolve_verified_caller(
                    identity,
                    caller,
                    ctx.virtual_channel
                        .source_auth
                        .as_ref(),
                    state.secrets_store.as_ref(),
                )
                .await
        }
        None => Err(match credential {
            CallerCredential::ApiKey => CredentialIdentityError::ApiKeyCallerMissing,
            CallerCredential::JwtBearer => CredentialIdentityError::JwtClaimsUnavailable,
            CallerCredential::Mtls => CredentialIdentityError::MtlsCallerMissing,
        }),
    };
    let derived = match derived {
        Ok(derived) => derived,
        Err(error) => {
            warn!(
                request_id = %ctx.request_id,
                transit_point = %ctx.virtual_channel.alias,
                mode,
                error = %error,
                "Failed to derive the managed agent identity from the credential the Transit Point's caller presented"
            );
            track(error.reason_label());
            let message = CALLER_IDENTITY_UNRESOLVED.to_string();
            return Err(OutboundPipelineError::IdentityResolutionFailed(match error {
                CredentialIdentityError::JwtClaimMissing(_) => IdentityResolutionFailure::ExtensionMissing(message),
                error => match error.classify() {
                    CredentialIdentityErrorClass::Misconfigured => IdentityResolutionFailure::Misconfigured(message),
                    CredentialIdentityErrorClass::BackendUnavailable => {
                        IdentityResolutionFailure::BackendUnavailable(message)
                    }
                },
            }));
        }
    };
    remove_asserted_identity(ctx)?;
    let refuses_without_did = credential == CallerCredential::JwtBearer;
    let Some(vc_issuer) = state.vc_issuer.as_ref() else {
        warn!(
            request_id = %ctx.request_id,
            transit_point = %ctx.virtual_channel.alias,
            mode,
            "No VC issuer for the credential the Transit Point's caller presented — no managed agent identity"
        );
        track("vc_issuer_missing");
        if refuses_without_did {
            return Err(OutboundPipelineError::IdentityResolutionFailed(IdentityResolutionFailure::Misconfigured(
                "from_jwt_claim requires a configured VC issuer".to_string(),
            )));
        }
        return Ok(());
    };
    let response = match vc_issuer
        .issue_or_get_managed_credential(
            derived
                .identity_fields
                .clone(),
            Some(derived.identity_hash.clone()),
            ctx.surface
                .config_id()
                .map(String::from),
            ctx.surface.issuer_id.clone(),
            crate::identity::filesystem::ManagedIdentitySource::caller_bound_transit_point(
                ctx.virtual_channel
                    .alias
                    .clone(),
            ),
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            warn!(
                request_id = %ctx.request_id,
                transit_point = %ctx.virtual_channel.alias,
                error = %error,
                mode,
                "Failed to issue the DID of the credential the Transit Point's caller presented — no managed agent identity"
            );
            track("vc_issuer_error");
            if refuses_without_did {
                return Err(OutboundPipelineError::IdentityResolutionFailed(
                    IdentityResolutionFailure::ServiceUnavailable(
                        "VCIssuer failure during from_jwt_claim resolution".to_string(),
                    ),
                ));
            }
            return Ok(());
        }
    };
    track(if response.is_new {
        "ok_new"
    } else {
        "ok_cached"
    });
    debug!(
        request_id = %ctx.request_id,
        transit_point = %ctx.virtual_channel.alias,
        did = %response.did,
        mode,
        "Managed agent identity taken from the credential the Transit Point's caller presented"
    );
    ctx.resolved_identity = ProtectedAgentIdentity::Managed {
        did: response.did,
        identity_fields: derived.identity_fields,
    };
    ctx.resolved_identity_hash = Some(derived.identity_hash);
    ctx.resolved_identity_verification = derived.verification;
    Ok(())
}

/// The protocol the request is read in, when it carries an agent identity
/// (A2A, AP2 or MCP); any other protocol is refused, since an identity can be
/// neither injected into nor removed from it.
pub(super) fn identity_carrier(ctx: &OutboundPipelineContext) -> Result<ChannelProtocol, OutboundPipelineError> {
    let protocol = ctx
        .protocol
        .clone()
        .unwrap_or_else(|| ctx.surface.channel_protocol());
    match protocol {
        ChannelProtocol::A2a | ChannelProtocol::Ap2 | ChannelProtocol::Mcp => Ok(protocol),
        _ => Err(OutboundPipelineError::IdentityInjectionFailed(format!(
            "Identity injection not supported for protocol {:?}",
            protocol
        ))),
    }
}

/// Removes the agent identity the request body asserts on a caller-bound
/// Transit Point, so the destination never receives a copied one, and from the
/// `2026-07-28` MCP request captured at admission, which policy reads. A
/// protocol with no identity carrier is refused, as identity injection refuses
/// it, and so is an A2A body that is not exactly one JSON object, so neither is
/// forwarded unchecked.
fn remove_asserted_identity(ctx: &mut OutboundPipelineContext) -> Result<(), OutboundPipelineError> {
    let protocol = identity_carrier(ctx)?;
    let Some(body) = ctx.body_bytes.as_ref() else {
        return Ok(());
    };
    let removed = if protocol == ChannelProtocol::Mcp {
        if let Some(crate::mcp::request_validation::McpRequestClassification::Modern(request)) = ctx
            .mcp_classification
            .as_mut()
            && let Some(params) = request.params.as_mut()
        {
            crate::mcp::meta::remove_asserted_identity_from_params(params);
        }
        crate::mcp::meta::remove_asserted_identity(body)
    } else {
        crate::a2a::extensions::remove_asserted_identity(body)
            .ok_or(OutboundPipelineError::AssertedIdentityUnremovable)?
    };
    ctx.body_bytes = Some(removed);
    Ok(())
}

/// `input.extension_identity` for a Transit Point call: its caller, the
/// managed agent, as the Access Point reports its own caller. Absent while
/// the managed agent has no identity.
pub(super) fn outbound_extension_identity(
    ctx: &OutboundPipelineContext
) -> Option<crate::surface_context::ExtensionIdentityContext> {
    match &ctx.resolved_identity {
        ProtectedAgentIdentity::Managed { did, .. } => Some(crate::surface_context::ExtensionIdentityContext {
            did: Some(did.clone()),
            identity_hash: ctx
                .resolved_identity_hash
                .as_deref()
                .and_then(crate::surface_context::ExtensionIdentityContext::hash_field),
            verification: ctx.resolved_identity_verification,
        }),
        ProtectedAgentIdentity::Anonymous => None,
    }
}
