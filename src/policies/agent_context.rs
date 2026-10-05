//! Build `AgentContext` for OPA evaluation from agent card and trust registry data.
//!
//! This module is responsible for resolving all external data (DID documents, trust registry
//! results) into an `AgentContext` value ready for injection into `PolicyInput.agent`.
//! It belongs in the `policies` module because its sole purpose is building OPA input.
//!
//! `build_agent_context` is intentionally **best-effort**: every step that fails leaves the
//! corresponding field as `None` rather than propagating an error. The Rego policy receives
//! whatever was resolved and decides whether absent fields imply deny.

use tracing::{debug, info, warn};

use crate::config::{AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION, ChannelProtocol, TRUST_REGISTRY_EXTENSION};
use crate::trust_registries::communication::TrustRegistryListenerManager;
use crate::trust_registries::types::TrqpQueryRequest;

use crate::surface_context::AgentContext;

/// Protocol-specific location of the URI-keyed extension metadata object used
/// for source-mode agent-context extraction.
///
/// The trust-registry and identity-credential extensions carry the same shape
/// regardless of protocol; only *where* they live in the request/response body
/// differs. A2A stores them under the A2A message's `metadata`; MCP stores them
/// under `_meta` (top-level or `params._meta`). Implementations return that
/// object so the shared extraction + cross-validation logic runs unchanged.
pub trait ExtensionMetadataSource: Send + Sync {
    /// Locate the extension metadata object in a source-mode request/response body.
    fn message_metadata<'a>(
        &self,
        body: &'a serde_json::Value,
    ) -> Option<std::borrow::Cow<'a, serde_json::Map<String, serde_json::Value>>>;
}

/// A2A / AP2 extractor: extensions live under the normalized message's `metadata`.
pub struct A2aExtensionSource;

impl ExtensionMetadataSource for A2aExtensionSource {
    fn message_metadata<'a>(
        &self,
        body: &'a serde_json::Value,
    ) -> Option<std::borrow::Cow<'a, serde_json::Map<String, serde_json::Value>>> {
        normalize_message_body(body)
            .and_then(|msg| msg.get("metadata"))
            .and_then(|md| md.as_object())
            .map(std::borrow::Cow::Borrowed)
    }
}

pub struct McpExtensionSource;

impl ExtensionMetadataSource for McpExtensionSource {
    fn message_metadata<'a>(
        &self,
        body: &'a serde_json::Value,
    ) -> Option<std::borrow::Cow<'a, serde_json::Map<String, serde_json::Value>>> {
        let metadata = crate::mcp::meta::read_metadata(body).ok()??;
        let view = metadata
            .into_iter()
            .map(|(key, value)| {
                let shared_key = crate::config::MCP_METADATA_ALIASES
                    .iter()
                    .find(|(_, canonical)| *canonical == key)
                    .map_or(key.clone(), |(historical, _)| historical.to_string());
                (shared_key, value)
            })
            .collect();
        Some(std::borrow::Cow::Owned(view))
    }
}

/// Select the extension-metadata source for a channel protocol.
fn extension_metadata_source(protocol: ChannelProtocol) -> &'static dyn ExtensionMetadataSource {
    match protocol {
        ChannelProtocol::Mcp => &McpExtensionSource,
        _ => &A2aExtensionSource,
    }
}

/// Build an `AgentContext` from available agent data and optional trust registry lookups.
///
/// A2A-shaped entry point (source-mode extensions read from message `metadata`).
/// For protocol-aware extraction use [`build_agent_context_for_protocol`].
///
/// # Arguments
/// * `body_json` — Full message body (source mode) or agent card JSON (target mode).
/// * `agent_card` — Parsed agent card JSON, present only in target mode.
/// * `tr_manager` — Optional reference to the trust registry listener manager used for TR
///   recognition queries.  When `None` the queries are skipped and `trust_verification` stays `None`.
/// * `enforce_identity_match` — When `true`, cross-check that the identity-credential
///   extension DID matches the TR extension's `agent_did`; on mismatch, discard the TR
///   extension data, clear `ctx.did`, and set `ctx.tr_identity_mismatch = true`. When
///   `false` (caller-leg calls today), the cross-check is skipped and TR extension data
///   is passed through as-is even without a matching identity credential.
///
/// Returns an `AgentContext` with `trust_verification` set.  Never errors.
pub async fn build_agent_context(
    body_json: Option<&serde_json::Value>,
    agent_card: Option<&serde_json::Value>,
    tr_manager: Option<&TrustRegistryListenerManager>,
    enforce_identity_match: bool,
) -> AgentContext {
    build_agent_context_with(&A2aExtensionSource, body_json, agent_card, tr_manager, enforce_identity_match).await
}

/// Protocol-aware variant of [`build_agent_context`]. Selects where source-mode
/// extensions are read from (A2A message `metadata` vs MCP `_meta`) based on
/// `protocol`; all downstream extraction, cross-validation, and recognition
/// queries are identical across protocols.
pub async fn build_agent_context_for_protocol(
    protocol: ChannelProtocol,
    body_json: Option<&serde_json::Value>,
    agent_card: Option<&serde_json::Value>,
    tr_manager: Option<&TrustRegistryListenerManager>,
    enforce_identity_match: bool,
) -> AgentContext {
    build_agent_context_with(
        extension_metadata_source(protocol),
        body_json,
        agent_card,
        tr_manager,
        enforce_identity_match,
    )
    .await
}

async fn build_agent_context_with(
    extractor: &dyn ExtensionMetadataSource,
    body_json: Option<&serde_json::Value>,
    agent_card: Option<&serde_json::Value>,
    tr_manager: Option<&TrustRegistryListenerManager>,
    enforce_identity_match: bool,
) -> AgentContext {
    let mut ctx = AgentContext {
        trust_verification: None,
        source_trust_verification: None,
        target_trust_verification: None,
        did: None,
        did_verified: false,
        did_verification: None,
        agent_dna: None,
        trust_registry_did: None,
        provider_did: None,
        authority_did: None,
        identity_issuer_did: None,
        tr_identity_mismatch: false,
    };

    info!(
        "build_agent_context: body_json={} agent_card={} tr_manager={}",
        body_json.is_some(),
        agent_card.is_some(),
        tr_manager.is_some()
    );

    // Locate the source-mode extension metadata object for this protocol
    // (A2A message `metadata` or MCP `_meta`).
    let metadata_view = body_json.and_then(|body| extractor.message_metadata(body));
    let msg_metadata = metadata_view.as_deref();

    // --- DID extraction (needed for Q1: issuer owns agent) ---
    let mut agent_did: Option<String> = None;
    let mut context_did: Option<String> = None;
    if let Some(card) = agent_card {
        agent_did = extract_did_from_agent_card(card);
        context_did = extract_context_did_from_agent_card(card);

        ctx.agent_dna = card
            .get("agentDNA")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok());
    }

    if context_did.is_none()
        && let Some(md) = msg_metadata
    {
        context_did = extract_did_from_extension_metadata(md);
    }

    ctx.did = context_did;

    if agent_did.is_none()
        && let Some(md) = msg_metadata
    {
        agent_did = extract_did_from_extension_metadata(md);
    }
    debug!("build_agent_context: agent_did={:?} ctx.did={:?}", agent_did, ctx.did);

    // --- TR extension extraction (registry_did, provider_did/issuer_did, authority_did, agent_did) ---
    let tr_data = extract_trust_registry_extension(msg_metadata, agent_card);
    debug!("build_agent_context: TR extension found: {:#?} {:#?}", tr_data, msg_metadata);

    // Cross-validate: the identity-credential extension DID must equal the TR
    // extension's `agent_did`. Both values are read from the SAME source (card in
    // target mode, body in source mode) using no-fallback getters, so a mismatch
    // means the TR extension is spoofed. On mismatch we discard the TR data (so the
    // recognition queries below never fire), clear `ctx.did`, and flag it for OPA /
    // Trust Check via `trust_verification = Some(false)` and `tr_identity_mismatch`.
    let identity_did = if let Some(card) = agent_card {
        extract_identity_ext_did_from_card(card)
    } else {
        msg_metadata.and_then(extract_identity_ext_did_from_metadata)
    };
    let tr_agent_did = tr_data
        .as_ref()
        .and_then(|d| d.3.clone());

    let tr_data = if enforce_identity_match {
        match (&identity_did, &tr_agent_did) {
            // No TR extension agent_did present → nothing to cross-check.
            (_, None) => tr_data,
            // TR present and identity credential DID matches → trusted.
            (Some(id_did), Some(tr_did)) if id_did == tr_did => tr_data,
            // TR present but the identity credential DID is missing or differs →
            // suspicious. The TR extension must never appear without a matching
            // identity credential. Discard TR data (queries below never fire),
            // clear `ctx.did`, and flag for OPA / Trust Check.
            (identity, Some(tr_did)) => {
                warn!(
                    "build_agent_context: TR extension agent_did '{}' has no matching identity \
                     credential DID (identity_did={:?}) — discarding TR extension data",
                    tr_did, identity
                );
                ctx.did = None;
                ctx.trust_verification = Some(false);
                ctx.tr_identity_mismatch = true;
                None
            }
        }
    } else {
        tr_data
    };

    if let Some((registry_did, provider_did, authority_did, _)) = &tr_data {
        ctx.trust_registry_did = Some(registry_did.clone());
        ctx.provider_did = Some(provider_did.clone());
        ctx.authority_did = authority_did.clone();
    }

    // --- Three recognition queries ---
    match (&tr_data, &agent_did, tr_manager) {
        (Some((registry_did, issuer_did, authority_did, _)), Some(agent_did), Some(manager)) => {
            debug!(
                "build_agent_context: performing TR recognition queries: agent_did={} registry={} issuer={} authority={:?}",
                agent_did, registry_did, issuer_did, authority_did
            );
            ctx.trust_verification = Some(
                perform_trust_verification(agent_did, registry_did, issuer_did, authority_did.as_deref(), manager)
                    .await,
            );
        }
        (None, _, _) => debug!("build_agent_context: TRUST_REGISTRY_EXTENSION not present, skipping TR queries"),
        (_, None, _) => debug!("build_agent_context: no agent DID resolved, skipping TR queries"),
        (_, _, None) => debug!("build_agent_context: tr_manager is None, skipping TR queries"),
    }

    info!("build_agent_context: FINAL ctx={:?}", ctx);
    ctx
}

/// Perform all three trust registry recognition queries.
///
/// Returns `true` only when all three queries return `recognized == true`.
/// Returns `false` if any query fails or returns `recognized == false`.
async fn perform_trust_verification(
    agent_did: &str,
    registry_did: &str,
    issuer_did: &str,
    authority_did: Option<&str>,
    manager: &TrustRegistryListenerManager,
) -> bool {
    // Q1: Issuer recognizes agent (is/ownedAgent)
    let q1 = TrqpQueryRequest {
        authority_id: issuer_did.to_string(),
        entity_id: agent_did.to_string(),
        action: "is".to_string(),
        resource: "ownedAgent".to_string(),
    };
    debug!(
        "[AgentPolicy Q1] Querying: authority_id={} entity_id={} action=is resource=ownedAgent registry={}",
        issuer_did, agent_did, registry_did
    );
    match manager
        .query_recognition(registry_did, &q1)
        .await
    {
        Ok(Some(resp)) if resp.recognized => {
            info!("[AgentPolicy Q1] issuer owns agent: PASSED");
        }
        Ok(_) => {
            info!("[AgentPolicy Q1] issuer owns agent: DENIED");
            return false;
        }
        Err(e) => {
            warn!("[AgentPolicy Q1] query failed: {}", e);
            return false;
        }
    }

    // Q2 & Q3 require authority_did
    let Some(authority_did) = authority_did else {
        warn!("build_agent_context: authority_did not available, skipping Q2/Q3");
        return false;
    };

    // Q2: Issuer is allowed to register agents (register/agents)
    let q2 = TrqpQueryRequest {
        authority_id: authority_did.to_string(),
        entity_id: issuer_did.to_string(),
        action: "register".to_string(),
        resource: "agents".to_string(),
    };
    debug!(
        "[AgentPolicy Q2] Querying: authority_id={} entity_id={} action=register resource=agents registry={}",
        authority_did, issuer_did, registry_did
    );
    match manager
        .query_recognition(registry_did, &q2)
        .await
    {
        Ok(Some(resp)) if resp.recognized => {
            info!("[AgentPolicy Q2] issuer can register agents: PASSED");
        }
        Ok(_) => {
            info!("[AgentPolicy Q2] issuer can register agents: DENIED");
            return false;
        }
        Err(e) => {
            warn!("[AgentPolicy Q2] query failed: {}", e);
            return false;
        }
    }

    // Q3: Authority recognizes issuer (is/{configured resource name}). The wire
    // resource string is controlled by `TrustRegistryRuntimeConfig::q3_resource_name`
    // (default `"registeredDepartment"` for wire compat) so gateways whose Trust
    // Registry has migrated to `"registeredIssuer"` can flip the toggle without
    // this hard-coded default forcing a wire deviation.
    let q3_resource = crate::trust_registries::q3_resource_config::q3_resource_name();
    let q3 = TrqpQueryRequest {
        authority_id: authority_did.to_string(),
        entity_id: issuer_did.to_string(),
        action: "is".to_string(),
        resource: q3_resource.to_string(),
    };
    debug!(
        "[AgentPolicy Q3] Querying: authority_id={} entity_id={} action=is resource={} registry={}",
        authority_did, issuer_did, q3_resource, registry_did
    );
    match manager
        .query_recognition(registry_did, &q3)
        .await
    {
        Ok(Some(resp)) if resp.recognized => {
            info!("[AgentPolicy Q3] authority recognizes issuer: PASSED");
        }
        Ok(_) => {
            info!("[AgentPolicy Q3] authority recognizes issuer: DENIED");
            return false;
        }
        Err(e) => {
            warn!("[AgentPolicy Q3] query failed: {}", e);
            return false;
        }
    }

    info!("build_agent_context: all three recognition queries passed");
    true
}

/// Resolve the A2A message object from an arbitrary JSON body.
///
/// Tries, in order:
/// 1. `params.message`
/// 2. `result.status.message`
/// 3. `result.message`
/// 4. `result` directly (when it looks like a message)
/// 5. `message`
/// 6. The body itself (when it looks like a message)
///
/// Returns `None` when no recognisable message structure is found.
fn normalize_message_body(body: &serde_json::Value) -> Option<&serde_json::Value> {
    // 1. JSON-RPC request envelope: params.message
    if let Some(msg) = body
        .get("params")
        .and_then(|p| p.get("message"))
    {
        debug!("build_agent_context: Using params.message");
        return Some(msg);
    }

    // 2-4. JSON-RPC response envelope: result.*
    if let Some(result) = body.get("result") {
        if let Some(msg) = result
            .get("status")
            .and_then(|s| s.get("message"))
        {
            debug!("build_agent_context: Using result.status.message");
            return Some(msg);
        }
        if let Some(msg) = result.get("message") {
            debug!("build_agent_context: Using result.message");
            return Some(msg);
        }
        if looks_like_message(result) {
            debug!("build_agent_context: Using result directly as message");
            return Some(result);
        }
        debug!("build_agent_context: unrecognized result structure");
        return None;
    }

    // 5. Wrapped in a top-level "message" key
    if let Some(msg) = body.get("message") {
        return Some(msg);
    }

    // 6. Body is the message itself
    if looks_like_message(body) {
        debug!("build_agent_context: Using body as message directly");
        return Some(body);
    }

    let keys: Vec<&String> = body
        .as_object()
        .map(|o| o.keys().collect())
        .unwrap_or_default();
    debug!(keys = ?keys, "build_agent_context: unrecognized message structure");
    None
}

/// Returns `true` when a JSON value has at least one field that indicates it
/// is an A2A message (`metadata`, `extensions`, `kind`, or `parts`).
#[inline]
fn looks_like_message(value: &serde_json::Value) -> bool {
    value
        .get("metadata")
        .is_some()
        || value
            .get("extensions")
            .is_some()
        || value.get("kind").is_some()
        || value.get("parts").is_some()
}

fn extract_context_did_from_agent_card(card: &serde_json::Value) -> Option<String> {
    let extensions = card
        .get("capabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(|e| e.as_array())
        .or_else(|| {
            warn!("Agent card missing capabilities.extensions array");
            None
        })?;

    for ext in extensions {
        if ext
            .get("uri")
            .and_then(|u| u.as_str())
            == Some(AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION)
            && let Some(did) = ext
                .get("did")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    ext.get("params")
                        .and_then(|p| p.get("did"))
                        .and_then(|v| v.as_str())
                })
        {
            return Some(did.to_string());
        }
    }

    extract_did_from_agent_card(card)
}

/// Extract the stringified `agent-identity-credential/v1` Verifiable
/// Presentation from a fetched agent card, if present.
pub fn extract_credential_vp_from_card(card: &serde_json::Value) -> Option<&str> {
    let extensions = card
        .get("capabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(|e| e.as_array())?;

    for ext in extensions {
        if ext
            .get("uri")
            .and_then(|u| u.as_str())
            != Some(AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION)
        {
            continue;
        }
        if let Some(vp) = ext
            .get("params")
            .and_then(|p| p.get("verifiablePresentation"))
            .and_then(|v| v.as_str())
        {
            return Some(vp);
        }
        if let Some(vp) = ext
            .get("verifiablePresentation")
            .and_then(|v| v.as_str())
        {
            return Some(vp);
        }
    }

    None
}

fn extract_did_from_agent_card(card: &serde_json::Value) -> Option<String> {
    let extensions = card
        .get("capabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(|e| e.as_array())
        .or_else(|| {
            warn!("Agent card missing capabilities.extensions array");
            None
        })?;

    // Extract agent_did from TRUST_REGISTRY_EXTENSION → .params.agent_did
    for ext in extensions {
        if ext
            .get("uri")
            .and_then(|u| u.as_str())
            == Some(TRUST_REGISTRY_EXTENSION)
        {
            if let Some(did) = ext
                .get("params")
                .and_then(|p| p.get("agent_did"))
                .and_then(|v| v.as_str())
            {
                return Some(did.to_string());
            } else {
                warn!("Trust registry extension missing agent_did in params");
            }
        }
    }

    None
}

fn extract_did_from_extension_metadata(metadata: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    // Step 1: prefer AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION → .did
    if let Some(did) = metadata
        .get(AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION)
        .and_then(|ext| ext.get("did"))
        .and_then(|v| v.as_str())
    {
        return Some(did.to_string());
    }

    // Step 2: fallback to TRUST_REGISTRY_EXTENSION → .agent_did
    if let Some(ext) = metadata.get(TRUST_REGISTRY_EXTENSION) {
        if let Some(did) = ext
            .get("agent_did")
            .and_then(|v| v.as_str())
        {
            return Some(did.to_string());
        } else {
            warn!("Trust registry extension missing agent_did in params");
        }
    }

    None
}
/// Extract `(registry_did, provider_did, authority_did, agent_did)` from the TRUST_REGISTRY_EXTENSION, if present.
/// Checks the agent card first (target mode), then the source-mode extension metadata.
fn extract_trust_registry_extension(
    metadata: Option<&serde_json::Map<String, serde_json::Value>>,
    agent_card: Option<&serde_json::Value>,
) -> Option<(String, String, Option<String>, Option<String>)> {
    // Target mode: search capabilities.extensions array in agent card
    if let Some(card) = agent_card
        && let Some(result) = extract_tr_extension_from_card(card)
    {
        return Some(result);
    }

    // Source mode: check extension metadata keyed by extension URI
    if let Some(md) = metadata
        && let Some(result) = extract_tr_extension_from_metadata(md)
    {
        return Some(result);
    }

    None
}

fn extract_tr_extension_from_card(
    card: &serde_json::Value
) -> Option<(String, String, Option<String>, Option<String>)> {
    let extensions = card
        .get("capabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(|e| e.as_array())?;

    let ext = extensions.iter().find(|e| {
        e.get("uri")
            .and_then(|u| u.as_str())
            == Some(TRUST_REGISTRY_EXTENSION)
    })?;

    let params = ext.get("params")?;
    let registry_did = params
        .get("trust_registry_did")
        .and_then(|v| v.as_str())?
        .to_string();
    let provider_did = params
        .get("provider_did")
        .and_then(|v| v.as_str())?
        .to_string();
    let authority_did = params
        .get("authority_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let agent_did = params
        .get("agent_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some((registry_did, provider_did, authority_did, agent_did))
}

fn extract_tr_extension_from_metadata(
    metadata: &serde_json::Map<String, serde_json::Value>
) -> Option<(String, String, Option<String>, Option<String>)> {
    let ext = metadata.get(TRUST_REGISTRY_EXTENSION)?;

    let registry_did = ext
        .get("trust_registry_did")
        .and_then(|v| v.as_str())?
        .to_string();
    let provider_did = ext
        .get("provider_did")
        .and_then(|v| v.as_str())?
        .to_string();
    let authority_did = ext
        .get("authority_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let agent_did = ext
        .get("agent_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some((registry_did, provider_did, authority_did, agent_did))
}

/// Extract the identity-credential extension DID from the agent card **without**
/// falling back to the TR extension's `agent_did`. Used for cross-validation only.
fn extract_identity_ext_did_from_card(card: &serde_json::Value) -> Option<String> {
    let extensions = card
        .get("capabilities")
        .and_then(|c| c.get("extensions"))
        .and_then(|e| e.as_array())?;

    let _uris: Vec<&str> = extensions
        .iter()
        .filter_map(|e| {
            e.get("uri")
                .and_then(|u| u.as_str())
        })
        .collect();

    for ext in extensions {
        let uri = ext
            .get("uri")
            .and_then(|u| u.as_str());
        if uri == Some(AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION) {
            let did = ext
                .get("did")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    ext.get("params")
                        .and_then(|p| p.get("did"))
                        .and_then(|v| v.as_str())
                })
                .map(|s| s.to_string());
            return did;
        }
    }

    None
}

/// Extract the identity-credential extension DID from the source-mode extension
/// metadata **without** falling back to the TR extension's `agent_did`.
fn extract_identity_ext_did_from_metadata(metadata: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    metadata
        .get(AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION)
        .and_then(|ext| ext.get("did"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn mcp_canonical_aliases_are_read_without_claiming_verification() {
        use crate::config::{ChannelProtocol, MCP_AGENT_IDENTITY_CREDENTIAL_KEY, MCP_TRUST_REGISTRY_KEY};
        use serde_json::json;
        for container in ["params", "result"] {
            let body = json!({container: {"_meta": {
                MCP_AGENT_IDENTITY_CREDENTIAL_KEY: {"did": "did:example:declared"},
                MCP_TRUST_REGISTRY_KEY: {"agent_did": "did:example:declared", "trust_registry_did": "did:example:registry", "provider_did": "did:example:provider"}
            }}});
            let context =
                super::build_agent_context_for_protocol(ChannelProtocol::Mcp, Some(&body), None, None, true).await;
            assert_eq!(context.did.as_deref(), Some("did:example:declared"));
            assert_eq!(
                context
                    .provider_did
                    .as_deref(),
                Some("did:example:provider")
            );
            assert_eq!(context.trust_verification, None);
        }
        let body = json!({"params": {"_meta": null}, "_meta": {MCP_AGENT_IDENTITY_CREDENTIAL_KEY: {"did": "did:example:spoofed"}}});
        assert!(
            super::build_agent_context_for_protocol(ChannelProtocol::Mcp, Some(&body), None, None, false)
                .await
                .did
                .is_none()
        );
    }

    use super::*;
    use serde_json::json;

    // ---------------------------------------------------------------
    // extract_credential_vp_from_card
    // ---------------------------------------------------------------

    #[test]
    fn extract_vp_reads_params_shape() {
        let card = json!({
            "capabilities": {
                "extensions": [
                    { "uri": TRUST_REGISTRY_EXTENSION, "params": { "agent_did": "did:web:tr" } },
                    {
                        "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "params": { "verifiablePresentation": "{\"vp\":true}", "did": "did:web:x" }
                    }
                ]
            }
        });
        assert_eq!(extract_credential_vp_from_card(&card), Some("{\"vp\":true}"));
    }

    #[test]
    fn extract_vp_reads_top_level_shape() {
        let card = json!({
            "capabilities": {
                "extensions": [
                    {
                        "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "verifiablePresentation": "{\"vp\":1}"
                    }
                ]
            }
        });
        assert_eq!(extract_credential_vp_from_card(&card), Some("{\"vp\":1}"));
    }

    #[test]
    fn extract_vp_absent_returns_none() {
        // Credential extension present but carries only an unsigned `did`,
        // no VP — must not be treated as a VP.
        let card = json!({
            "capabilities": {
                "extensions": [
                    { "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION, "params": { "did": "did:web:x" } }
                ]
            }
        });
        assert_eq!(extract_credential_vp_from_card(&card), None);
    }

    #[test]
    fn extract_vp_no_extensions_returns_none() {
        let card = json!({ "name": "no-caps" });
        assert_eq!(extract_credential_vp_from_card(&card), None);
    }

    #[test]
    fn test_normalize_message_body_params_message() {
        let body = json!({ "jsonrpc": "2.0", "params": { "message": { "kind": "message" } } });
        let msg = normalize_message_body(&body).expect("should find params.message");
        assert_eq!(
            msg.get("kind")
                .and_then(|v| v.as_str()),
            Some("message")
        );
    }

    #[test]
    fn test_normalize_message_body_result_status_message() {
        let body = json!({ "result": { "status": { "message": { "parts": [] } } } });
        let msg = normalize_message_body(&body).expect("should find result.status.message");
        assert!(msg.get("parts").is_some());
    }

    #[test]
    fn test_normalize_message_body_result_message() {
        let body = json!({ "result": { "message": { "metadata": {} } } });
        let msg = normalize_message_body(&body).expect("should find result.message");
        assert!(msg.get("metadata").is_some());
    }

    #[test]
    fn test_normalize_message_body_result_is_message() {
        // result itself looks like a message (has `kind`)
        let body = json!({ "result": { "kind": "message", "parts": [] } });
        let msg = normalize_message_body(&body).expect("should use result directly");
        assert_eq!(
            msg.get("kind")
                .and_then(|v| v.as_str()),
            Some("message")
        );
    }

    #[test]
    fn test_normalize_message_body_result_unrecognized_returns_none() {
        // result exists but has no message-like fields → None (don't fall through to outer body)
        let body = json!({ "result": { "id": "xyz" } });
        assert!(normalize_message_body(&body).is_none());
    }

    #[test]
    fn test_normalize_message_body_top_level_message_key() {
        let body = json!({ "message": { "metadata": { "ext": "value" } } });
        let msg = normalize_message_body(&body).expect("should find top-level message key");
        assert!(msg.get("metadata").is_some());
    }

    #[test]
    fn test_normalize_message_body_body_is_message() {
        let body = json!({ "kind": "message", "parts": [] });
        let msg = normalize_message_body(&body).expect("should use body directly");
        assert_eq!(
            msg.get("kind")
                .and_then(|v| v.as_str()),
            Some("message")
        );
    }

    #[test]
    fn test_normalize_message_body_unrecognized_returns_none() {
        let body = json!({ "foo": "bar", "baz": 42 });
        assert!(normalize_message_body(&body).is_none());
    }

    // params.message takes priority over a top-level kind field
    #[test]
    fn test_normalize_message_body_params_wins_over_direct() {
        let body = json!({
            "kind": "outer",
            "params": { "message": { "kind": "inner" } }
        });
        let msg = normalize_message_body(&body).unwrap();
        assert_eq!(
            msg.get("kind")
                .and_then(|v| v.as_str()),
            Some("inner")
        );
    }

    // ---------------------------------------------------------------
    // extract_did_from_agent_card
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_did_from_agent_card_via_credential_extension() {
        // Credential extension alone is no longer used — only trust registry extension.
        let card = json!({
            "capabilities": {
                "extensions": [{
                    "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                    "verifiable_presentation": {},
                    "did": "did:web:agent.example.com"
                }]
            }
        });
        assert_eq!(extract_did_from_agent_card(&card), None);
    }

    #[test]
    fn test_extract_did_from_agent_card_via_tr_extension_fallback() {
        let card = json!({
            "capabilities": {
                "extensions": [{
                    "uri": TRUST_REGISTRY_EXTENSION,
                    "params": { "agent_did": "did:web:tr-agent.example.com" }
                }]
            }
        });
        assert_eq!(extract_did_from_agent_card(&card), Some("did:web:tr-agent.example.com".to_string()));
    }

    #[test]
    fn test_extract_did_from_agent_card_tr_used_when_both_present() {
        // Only trust registry extension is used for DID extraction.
        let card = json!({
            "capabilities": {
                "extensions": [
                    {
                        "uri": TRUST_REGISTRY_EXTENSION,
                        "params": { "agent_did": "did:web:tr-agent" }
                    },
                    {
                        "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "did": "did:web:credential-agent"
                    }
                ]
            }
        });
        assert_eq!(extract_did_from_agent_card(&card), Some("did:web:tr-agent".to_string()));
    }

    #[test]
    fn test_extract_did_from_agent_card_empty_extensions_returns_none() {
        let card = json!({ "capabilities": { "extensions": [] } });
        assert!(extract_did_from_agent_card(&card).is_none());
    }

    #[test]
    fn test_extract_did_from_agent_card_missing_capabilities_returns_none() {
        let card = json!({ "name": "Agent" });
        assert!(extract_did_from_agent_card(&card).is_none());
    }

    #[test]
    fn test_extract_context_did_from_agent_card_prefers_credential_extension() {
        let card = json!({
            "capabilities": {
                "extensions": [
                    {
                        "uri": TRUST_REGISTRY_EXTENSION,
                        "params": { "agent_did": "did:web:tr-agent" }
                    },
                    {
                        "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "did": "did:web:credential-agent"
                    }
                ]
            }
        });

        assert_eq!(extract_context_did_from_agent_card(&card), Some("did:web:credential-agent".to_string()));
    }

    // ---------------------------------------------------------------
    // extract_did_from_extension_metadata
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_did_from_extension_metadata_via_credential() {
        let mut metadata = serde_json::Map::new();
        metadata.insert(
            AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION.to_string(),
            json!({ "did": "did:web:sender.example.com" }),
        );
        assert_eq!(extract_did_from_extension_metadata(&metadata), Some("did:web:sender.example.com".to_string()));
    }

    #[test]
    fn test_extract_did_from_extension_metadata_via_tr_fallback() {
        let mut metadata = serde_json::Map::new();
        metadata.insert(TRUST_REGISTRY_EXTENSION.to_string(), json!({  "agent_did": "did:web:tr-sender" } ));
        assert_eq!(extract_did_from_extension_metadata(&metadata), Some("did:web:tr-sender".to_string()));
    }

    #[test]
    fn test_extract_did_from_extension_metadata_empty_returns_none() {
        let metadata = serde_json::Map::new();
        assert!(extract_did_from_extension_metadata(&metadata).is_none());
    }

    // ---------------------------------------------------------------
    // extract_tr_extension_from_card / message
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_tr_extension_from_card() {
        let card = json!({
            "capabilities": {
                "extensions": [{
                    "uri": TRUST_REGISTRY_EXTENSION,
                    "params": {
                        "trust_registry_did": "did:web:registry.example.com",
                        "provider_did": "did:web:provider.example.com",
                        "authority_did": "did:web:authority.example.com"
                    }
                }]
            }
        });
        let result = extract_tr_extension_from_card(&card);
        assert_eq!(
            result,
            Some((
                "did:web:registry.example.com".to_string(),
                "did:web:provider.example.com".to_string(),
                Some("did:web:authority.example.com".to_string()),
                None,
            ))
        );
    }

    #[test]
    fn test_extract_tr_extension_from_card_missing_returns_none() {
        let card = json!({ "capabilities": { "extensions": [] } });
        assert!(extract_tr_extension_from_card(&card).is_none());
    }

    #[test]
    fn test_extract_tr_extension_from_metadata() {
        let metadata = json!({
            TRUST_REGISTRY_EXTENSION: {
                "trust_registry_did": "did:web:registry",
                "provider_did": "did:web:provider",
                "authority_did": "did:web:authority"
            }
        });
        let metadata = metadata.as_object().unwrap();
        assert_eq!(
            extract_tr_extension_from_metadata(metadata),
            Some((
                "did:web:registry".to_string(),
                "did:web:provider".to_string(),
                Some("did:web:authority".to_string()),
                None,
            ))
        );
    }

    // ---------------------------------------------------------------
    // build_agent_context — integration tests
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_build_agent_context_no_data() {
        let ctx = build_agent_context(None, None, None, true).await;
        assert!(
            ctx.trust_verification
                .is_none()
        );
        assert!(
            ctx.trust_registry_did
                .is_none()
        );
        assert!(ctx.provider_did.is_none());
        assert!(ctx.authority_did.is_none());
    }

    #[tokio::test]
    async fn test_build_agent_context_mirrors_trust_registry_extension_fields() {
        // Source-mode payload mirroring the actual production shape:
        // metadata.<TRUST_REGISTRY_EXTENSION>.{trust_registry_did, provider_did, authority_did}.
        // The Trust Check element references {{ input.agent.provider_did }}
        // as its `query.authority_id` template, so this field MUST land on
        // AgentContext for the template resolver to find it.
        let msg = json!({
            "metadata": {
                TRUST_REGISTRY_EXTENSION: {
                    "trust_registry_did": "did:web:registry.example",
                    "provider_did": "did:web:provider.example",
                    "authority_did": "did:webvh:abc123:authority.example"
                }
            }
        });
        let ctx = build_agent_context(Some(&msg), None, None, false).await;
        assert_eq!(ctx.trust_registry_did, Some("did:web:registry.example".to_string()));
        assert_eq!(ctx.provider_did, Some("did:web:provider.example".to_string()));
        assert_eq!(ctx.authority_did, Some("did:webvh:abc123:authority.example".to_string()));
    }

    #[tokio::test]
    async fn test_build_agent_context_authority_did_absent_when_extension_omits_it() {
        // A registry extension MAY omit authority_did; the others stay set,
        // but authority_did must remain None (the trust-check template will
        // then fail to resolve, which the executor maps to TEMPLATE_RESOLUTION_FAILED).
        let msg = json!({
            "metadata": {
                TRUST_REGISTRY_EXTENSION: {
                    "trust_registry_did": "did:web:registry.example",
                    "provider_did": "did:web:provider.example"
                }
            }
        });
        let ctx = build_agent_context(Some(&msg), None, None, false).await;
        assert_eq!(ctx.trust_registry_did, Some("did:web:registry.example".to_string()));
        assert!(ctx.authority_did.is_none());
    }

    // ---------------------------------------------------------------
    // build_agent_context_for_protocol — MCP (_meta) extraction
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_build_agent_context_mcp_reads_tr_extension_from_meta() {
        // MCP carries the trust-registry extension under `_meta`, keyed by the
        // same URI A2A uses under `metadata`. The protocol-dispatched extractor
        // must surface provider_did/authority_did so the caller-leg Trust Check
        // template `{{ input.agent.provider_did }}` resolves for MCP surfaces.
        let body = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": "search", "arguments": {} },
            "_meta": {
                TRUST_REGISTRY_EXTENSION: {
                    "trust_registry_did": "did:web:registry.mcp",
                    "provider_did": "did:web:provider.mcp",
                    "authority_did": "did:web:authority.mcp"
                }
            }
        });
        let ctx = build_agent_context_for_protocol(ChannelProtocol::Mcp, Some(&body), None, None, false).await;
        assert_eq!(ctx.trust_registry_did, Some("did:web:registry.mcp".to_string()));
        assert_eq!(ctx.provider_did, Some("did:web:provider.mcp".to_string()));
        assert_eq!(ctx.authority_did, Some("did:web:authority.mcp".to_string()));
    }

    #[tokio::test]
    async fn test_build_agent_context_mcp_reads_tr_extension_from_params_meta() {
        // Spec-compliant MCP places `_meta` under `params`.
        let body = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "search",
                "_meta": {
                    TRUST_REGISTRY_EXTENSION: {
                        "trust_registry_did": "did:web:registry.mcp",
                        "provider_did": "did:web:provider.mcp"
                    }
                }
            }
        });
        let ctx = build_agent_context_for_protocol(ChannelProtocol::Mcp, Some(&body), None, None, false).await;
        assert_eq!(ctx.provider_did, Some("did:web:provider.mcp".to_string()));
    }

    #[tokio::test]
    async fn test_build_agent_context_mcp_tolerant_without_extension() {
        // No `_meta` extension present — same best-effort rule as A2A: empty
        // agent context, never an error.
        let body = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": "search", "arguments": {} }
        });
        let ctx = build_agent_context_for_protocol(ChannelProtocol::Mcp, Some(&body), None, None, false).await;
        assert!(ctx.provider_did.is_none());
        assert!(
            ctx.trust_registry_did
                .is_none()
        );
        assert!(
            ctx.trust_verification
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_build_agent_context_mcp_did_from_identity_credential_meta() {
        // Identity-credential extension DID under `_meta` populates ctx.did.
        let body = json!({
            "method": "tools/call",
            "_meta": {
                AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: { "did": "did:web:mcp-agent.example" }
            }
        });
        let ctx = build_agent_context_for_protocol(ChannelProtocol::Mcp, Some(&body), None, None, false).await;
        assert_eq!(ctx.did, Some("did:web:mcp-agent.example".to_string()));
    }

    #[tokio::test]
    async fn body_asserted_did_is_never_reported_verified() {
        let body = json!({
            "jsonrpc": "2.0",
            "params": {
                "message": {
                    "kind": "message",
                    "metadata": { AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: { "did": "did:web:claimed" } }
                }
            }
        });
        let ctx = build_agent_context(Some(&body), None, None, false).await;
        assert_eq!(ctx.did.as_deref(), Some("did:web:claimed"));
        assert!(!ctx.did_verified, "a DID read from body metadata is caller-asserted");

        let card = json!({
            "capabilities": {
                "extensions": [
                    { "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION, "params": { "did": "did:web:card" } }
                ]
            }
        });
        let ctx = build_agent_context(None, Some(&card), None, false).await;
        assert_eq!(ctx.did.as_deref(), Some("did:web:card"));
        assert!(!ctx.did_verified, "a DID read from an agent card is target-asserted");
    }

    #[tokio::test]
    async fn test_build_agent_context_target_mode_no_tr_manager() {
        let card = json!({
            "name": "Payment Agent",
            "url": "https://payments.example.com",
            "capabilities": {
                "extensions": [{
                    "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                    "did": "did:web:payments.example.com"
                }]
            }
        });
        let ctx = build_agent_context(None, Some(&card), None, true).await;
        assert_eq!(ctx.did, Some("did:web:payments.example.com".to_string()));
        assert!(
            ctx.trust_verification
                .is_none(),
            "no tr_manager → trust_verification must stay None"
        );
    }

    #[tokio::test]
    async fn test_didwebvh_fix_build_agent_context_target_mode_from_card() {
        let card = json!({
            "name": "Payment Agent",
            "url": "https://payments.example.com",
            "agentDNA": {
                "uai": "uai:1:scid:gen.beh.op.att",
                "birthEvent": {
                    "scid": "scid",
                    "timestamp": "2026-04-08T00:00:00Z",
                    "initialGenesis": {
                        "codeHash": "code",
                        "modelSpec": { "provider": "OpenAI", "model": "gpt-4.1" },
                        "configHash": "cfg",
                        "genesisHash": "gen",
                        "computedAt": "2026-04-08T00:00:00Z"
                    },
                    "birthEntryHash": "birth"
                },
                "genesis": {
                    "codeHash": "code",
                    "modelSpec": { "provider": "OpenAI", "model": "gpt-4.1" },
                    "configHash": "cfg",
                    "genesisHash": "gen",
                    "computedAt": "2026-04-08T00:00:00Z"
                },
                "behavioral": {
                    "behavioralHash": "beh",
                    "measuredAt": "2026-04-08T00:00:00Z"
                },
                "operational": {
                    "capabilitiesHash": "caps",
                    "operationalHash": "op",
                    "attestedAt": "2026-04-08T00:00:00Z"
                },
                "attestations": {
                    "merkleRoot": "root",
                    "count": 1
                }
            },
            "capabilities": {
                "extensions": [{
                    "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                    "did": "did:web:payments.example.com"
                }]
            }
        });
        let ctx = build_agent_context(None, Some(&card), None, true).await;
        assert_eq!(ctx.did, Some("did:web:payments.example.com".to_string()));
        assert_eq!(
            ctx.agent_dna
                .as_ref()
                .map(|dna| dna.uai.as_str()),
            Some("uai:1:scid:gen.beh.op.att")
        );
    }

    #[tokio::test]
    async fn test_build_agent_context_source_mode_no_tr_manager() {
        let mut inner_metadata = serde_json::Map::new();
        inner_metadata.insert(
            AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION.to_string(),
            json!({ "did": "did:web:source-agent.example.com" }),
        );
        let body = json!({
            "jsonrpc": "2.0",
            "params": {
                "message": {
                    "kind": "message",
                    "metadata": inner_metadata
                }
            }
        });
        let ctx = build_agent_context(Some(&body), None, None, false).await;
        assert_eq!(ctx.did, Some("did:web:source-agent.example.com".to_string()));
        assert!(
            ctx.trust_verification
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_build_agent_context_skips_tr_when_no_manager() {
        let card = json!({
            "name": "Agent",
            "capabilities": {
                "extensions": [
                    {
                        "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "did": "did:web:agent"
                    },
                    {
                        "uri": TRUST_REGISTRY_EXTENSION,
                        "params": {
                            "trust_registry_did": "did:web:registry",
                            "provider_did": "did:web:provider",
                            "authority_did": "did:web:authority",
                            "agent_did": "did:web:agent"
                        }
                    }
                ]
            }
        });
        let ctx = build_agent_context(None, Some(&card), None, true).await;
        assert!(
            ctx.trust_verification
                .is_none()
        );
    }

    /// Regression pin for the legacy `build_agent_context` verifier.
    ///
    /// The Trust Check element ([`crate::trust_registry_verification`]) is the forward
    /// path for trust-registry probing; this verifier remains as a fallback while the
    /// retirement slice is staged. Each assertion below pins one strand of the
    /// best-effort contract — "silent no-op when X is missing, never an error" — so
    /// the retirement slice flips these deliberately rather than silently.
    mod legacy_verifier_regression_pin {
        use super::*;

        /// Best-effort contract: the function is `async fn -> AgentContext`, not
        /// `Result`, so it must never propagate an error. Pin the type-level shape.
        #[tokio::test]
        async fn build_agent_context_is_infallible_on_garbage_inputs() {
            let body = json!("not-an-object");
            let card = json!(42);
            let ctx = build_agent_context(Some(&body), Some(&card), None, true).await;
            assert!(ctx.did.is_none());
            assert!(
                ctx.trust_verification
                    .is_none()
            );
            assert!(
                ctx.source_trust_verification
                    .is_none()
            );
            assert!(
                ctx.target_trust_verification
                    .is_none()
            );
            assert!(ctx.agent_dna.is_none());
        }

        /// Source mode: a body that carries only the credential extension and no
        /// `TRUST_REGISTRY_EXTENSION` skips the 3-query path silently.
        #[tokio::test]
        async fn body_without_trust_registry_extension_silently_skips_verification() {
            let mut metadata = serde_json::Map::new();
            metadata
                .insert(AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION.to_string(), json!({ "did": "did:web:sender" }));
            let body = json!({
                "jsonrpc": "2.0",
                "params": {
                    "message": { "kind": "message", "metadata": metadata }
                }
            });
            let ctx = build_agent_context(Some(&body), None, None, false).await;
            assert_eq!(ctx.did, Some("did:web:sender".to_string()));
            assert!(
                ctx.trust_verification
                    .is_none(),
                "no TRUST_REGISTRY_EXTENSION ⇒ trust_verification stays None"
            );
        }

        /// Target mode: a card with the trust registry extension but no
        /// `agent_did` skips the 3-query path silently — the function logs and
        /// returns rather than failing.
        #[tokio::test]
        async fn card_with_tr_extension_missing_agent_did_silently_skips_verification() {
            let card = json!({
                "name": "Agent",
                "capabilities": {
                    "extensions": [{
                        "uri": TRUST_REGISTRY_EXTENSION,
                        "params": {
                            "trust_registry_did": "did:web:registry",
                            "provider_did": "did:web:provider",
                            "authority_did": "did:web:authority"
                        }
                    }]
                }
            });
            let ctx = build_agent_context(None, Some(&card), None, true).await;
            assert!(
                ctx.trust_verification
                    .is_none()
            );
        }

        /// `tr_manager = None` is the production fallback when no registry is
        /// configured. The verifier must short-circuit before any I/O.
        #[tokio::test]
        async fn missing_manager_short_circuits_even_when_card_is_complete() {
            let card = json!({
                "name": "Agent",
                "capabilities": {
                    "extensions": [
                        {
                            "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                            "params": {
                                "did": "did:web:agent",
                                "verifiablePresentation": "{}"
                            }
                        },
                        {
                            "uri": TRUST_REGISTRY_EXTENSION,
                            "params": {
                                "trust_registry_did": "did:web:registry",
                                "provider_did": "did:web:provider",
                                "authority_did": "did:web:authority",
                                "agent_did": "did:web:agent"
                            }
                        }
                    ]
                }
            });
            let ctx = build_agent_context(None, Some(&card), None, true).await;
            assert!(
                ctx.trust_verification
                    .is_none()
            );
        }

        /// The recognition-query sequence is hard-coded as Q1/Q2/Q3 against
        /// `(issuer→agent, authority→issuer:register, authority→issuer:is)`.
        /// We can't exercise the manager without a trait stub, but we can pin
        /// that the helper accepts the documented arguments in the documented
        /// order — a signature drift here would force the retirement slice to
        /// re-derive call sites.
        #[allow(dead_code)]
        async fn _perform_trust_verification_signature_is_pinned(
            agent_did: &str,
            registry_did: &str,
            issuer_did: &str,
            authority_did: Option<&str>,
            manager: &TrustRegistryListenerManager,
        ) -> bool {
            perform_trust_verification(agent_did, registry_did, issuer_did, authority_did, manager).await
        }
    }

    #[tokio::test]
    async fn tr_extension_discarded_when_agent_did_mismatches_identity_ext_did() {
        let msg = json!({
            "metadata": {
                AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: { "did": "did:web:real" },
                TRUST_REGISTRY_EXTENSION: {
                    "agent_did": "did:web:other",
                    "trust_registry_did": "did:web:registry",
                    "provider_did": "did:web:provider",
                    "authority_did": "did:web:authority"
                }
            }
        });
        // `enforce_identity_match = true` pins the guard's mechanism: when the
        // caller flag opts in, a mismatch still discards TR data. Production
        // caller-leg call sites pass `false` today and get the exemption
        // asserted by the companion test below.
        let ctx = build_agent_context(Some(&msg), None, None, true).await;
        assert_eq!(ctx.did, None, "ctx.did must be cleared on mismatch");
        assert_eq!(ctx.trust_verification, Some(false), "trust_verification must be false on mismatch");
        assert!(ctx.tr_identity_mismatch, "tr_identity_mismatch must be set");
        assert!(
            ctx.trust_registry_did
                .is_none(),
            "trust_registry_did must be discarded on mismatch"
        );
        assert!(ctx.provider_did.is_none(), "provider_did must be discarded on mismatch");
        assert!(ctx.authority_did.is_none(), "authority_did must be discarded on mismatch");
    }

    /// Caller-leg exemption: when `enforce_identity_match = false`, a TR extension
    /// whose `agent_did` does not match the identity credential (or when the
    /// identity credential is absent entirely) is passed through as-is. The
    /// discard guard is target-leg only today.
    #[tokio::test]
    async fn tr_extension_preserved_on_caller_leg_when_identity_ext_missing() {
        let msg = json!({
            "metadata": {
                TRUST_REGISTRY_EXTENSION: {
                    "agent_did": "did:web:other",
                    "trust_registry_did": "did:web:registry",
                    "provider_did": "did:web:provider",
                    "authority_did": "did:web:authority"
                }
            }
        });
        let ctx = build_agent_context(Some(&msg), None, None, false).await;
        assert!(!ctx.tr_identity_mismatch, "caller leg must not flag mismatch");
        assert_eq!(ctx.trust_verification, None, "caller leg must not set trust_verification on identity gap");
        assert_eq!(ctx.trust_registry_did, Some("did:web:registry".to_string()));
        assert_eq!(ctx.provider_did, Some("did:web:provider".to_string()));
        assert_eq!(ctx.authority_did, Some("did:web:authority".to_string()));
    }

    #[tokio::test]
    async fn tr_extension_kept_when_agent_did_matches_identity_ext_did() {
        let msg = json!({
            "metadata": {
                AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: { "did": "did:web:real" },
                TRUST_REGISTRY_EXTENSION: {
                    "agent_did": "did:web:real",
                    "trust_registry_did": "did:web:registry",
                    "provider_did": "did:web:provider"
                }
            }
        });
        let ctx = build_agent_context(Some(&msg), None, None, true).await;
        assert!(!ctx.tr_identity_mismatch, "no mismatch when DIDs match");
        assert_eq!(ctx.trust_registry_did, Some("did:web:registry".to_string()));
        assert_eq!(ctx.provider_did, Some("did:web:provider".to_string()));
    }

    #[tokio::test]
    async fn tr_extension_discarded_on_agent_card_mismatch() {
        let card = json!({
            "name": "Agent",
            "capabilities": {
                "extensions": [
                    {
                        "uri": AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "params": {
                            "did": "did:webvh:card-identity-did",
                            "verifiablePresentation": "{}"
                        }
                    },
                    {
                        "uri": TRUST_REGISTRY_EXTENSION,
                        "params": {
                            "agent_did": "did:webvh:different-tr-did",
                            "trust_registry_did": "did:web:registry",
                            "provider_did": "did:web:provider",
                            "authority_did": "did:web:authority"
                        }
                    }
                ]
            }
        });
        let ctx = build_agent_context(None, Some(&card), None, true).await;
        assert_eq!(ctx.did, None, "ctx.did must be cleared on card mismatch");
        assert_eq!(ctx.trust_verification, Some(false));
        assert!(ctx.tr_identity_mismatch);
        assert!(
            ctx.trust_registry_did
                .is_none()
        );
        assert!(ctx.provider_did.is_none());
    }
}
