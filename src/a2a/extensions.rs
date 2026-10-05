//! A2A-specific extension injection functions
//!
//! This module contains functions for handling A2A (Agent-to-Agent) protocol
//! extension injection into message bodies.

use serde_json::Value as JsonValue;
use std::sync::Arc;
use tracing::{debug, info};

use crate::proxy::backend_identity::ProtectedAgentIdentity;

/// Copy configured inbound HTTP headers into A2A message metadata.
///
/// Returns the modified body and the number of mapped headers. When no configured
/// headers are present, the body is returned unchanged and the extension URI is
/// not added to the message.
pub fn inject_header_metadata_extension(
    body_bytes: &bytes::Bytes,
    mapping: &crate::config::header_metadata_mapping::HeaderMetadataMappingConfig,
    headers: &axum::http::HeaderMap,
    channel_name: &str,
) -> anyhow::Result<(bytes::Bytes, usize)> {
    let mapped = mapping.map_headers(headers);
    if mapped.is_empty() {
        return Ok((body_bytes.clone(), 0));
    }

    let mut body_json: JsonValue =
        serde_json::from_slice(body_bytes).map_err(|e| anyhow::anyhow!("Failed to parse body as JSON: {}", e))?;

    let use_params = body_json
        .get("params")
        .and_then(|p| p.get("message"))
        .is_some();

    if !use_params
        && body_json
            .get("message")
            .is_none()
    {
        return Err(anyhow::anyhow!("No A2A message object found in body"));
    }

    let message = if use_params {
        body_json
            .get_mut("params")
            .and_then(|p| p.get_mut("message"))
            .ok_or_else(|| anyhow::anyhow!("No message object found in params"))?
    } else {
        body_json
            .get_mut("message")
            .ok_or_else(|| anyhow::anyhow!("No top-level message object found in body"))?
    };

    let message_obj = message
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("A2A message is not an object"))?;

    let extensions = message_obj
        .entry("extensions".to_string())
        .or_insert_with(|| JsonValue::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("Extensions field is not an array"))?;
    if !extensions
        .iter()
        .any(|e| e.as_str() == Some(mapping.extension_uri.as_str()))
    {
        extensions.push(JsonValue::String(mapping.extension_uri.clone()));
    }

    let metadata = message_obj
        .entry("metadata".to_string())
        .or_insert_with(|| JsonValue::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Metadata field is not an object"))?;

    let mapped_payload = JsonValue::Object(
        mapped
            .iter()
            .map(|(field, value)| (field.clone(), JsonValue::String(value.clone())))
            .collect(),
    );

    if let Some(existing) = metadata.get_mut(&mapping.extension_uri) {
        if let (Some(existing_obj), Some(mapped_obj)) = (existing.as_object_mut(), mapped_payload.as_object()) {
            for (field, value) in mapped_obj {
                existing_obj.insert(field.clone(), value.clone());
            }
        } else {
            *existing = mapped_payload;
        }
    } else {
        metadata.insert(mapping.extension_uri.clone(), mapped_payload);
    }

    let modified_json =
        serde_json::to_vec(&body_json).map_err(|e| anyhow::anyhow!("Failed to serialize modified JSON: {}", e))?;
    debug!(
        channel = channel_name,
        extension = %mapping.extension_uri,
        mapped_count = mapped.len(),
        "Mapped inbound headers into A2A metadata"
    );
    Ok((bytes::Bytes::from(modified_json), mapped.len()))
}

/// Inject custom metadata extension into the A2A request body
/// This modifies the message to add the AFFINIDI_AGENT_METADATA_EXTENSION to extensions array
/// and adds the metadata payload to the metadata object
pub async fn inject_custom_metadata_extension(
    body_bytes: &bytes::Bytes,
    custom_metadata: &crate::config::CustomMetadata,
    channel_name: &str,
    secrets_store: &Option<Arc<dyn crate::secrets::SecretsStore>>,
    runtime: crate::protocols::MetadataRuntimeContext<'_>,
) -> anyhow::Result<bytes::Bytes> {
    // Parse the body as JSON
    let mut body_json: JsonValue =
        serde_json::from_slice(body_bytes).map_err(|e| anyhow::anyhow!("Failed to parse body as JSON: {}", e))?;

    // Check if there's a payload to inject
    let metadata_payload = custom_metadata
        .payload
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Custom metadata is enabled but no payload configured"))?;

    let resolved_payload =
        crate::protocols::resolve_metadata_references(metadata_payload, secrets_store, channel_name, runtime).await?;

    // Navigate to the message object:
    //   - params.message for JSON-RPC requests (message/send)
    //   - result for JSON-RPC responses
    let use_params = body_json
        .get("params")
        .and_then(|p| p.get("message"))
        .is_some();

    if !use_params
        && body_json
            .get("result")
            .is_none()
    {
        return Err(anyhow::anyhow!("No message object found in body"));
    }

    let message = if use_params {
        body_json
            .get_mut("params")
            .and_then(|p| p.get_mut("message"))
            .ok_or_else(|| anyhow::anyhow!("No message object found in params"))?
    } else {
        body_json
            .get_mut("result")
            .ok_or_else(|| anyhow::anyhow!("No result object found in body"))?
    };

    // Check if extensions array exists, if not create it.
    if !message
        .as_object()
        .map(|o| o.contains_key("extensions"))
        .unwrap_or(false)
    {
        message
            .as_object_mut()
            .unwrap()
            .insert("extensions".to_string(), JsonValue::Array(vec![]));
    }
    let extensions = message
        .get_mut("extensions")
        .and_then(|e| e.as_array_mut())
        .ok_or_else(|| anyhow::anyhow!("Extensions field is not an array"))?;

    // Check if the custom metadata extension is already in the array
    let extension_uri = crate::config::AFFINIDI_AGENT_METADATA_EXTENSION;

    if !extensions
        .iter()
        .any(|e| e.as_str() == Some(extension_uri))
    {
        // Add the extension URI to the array
        extensions.push(JsonValue::String(extension_uri.to_string()));
        debug!(channel = channel_name, "Added custom metadata extension URI to extensions array");
    }

    // Get or create the metadata object
    if !message
        .as_object()
        .unwrap()
        .contains_key("metadata")
    {
        message
            .as_object_mut()
            .unwrap()
            .insert("metadata".to_string(), JsonValue::Object(serde_json::Map::new()));
    }

    let metadata = message
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("Metadata field is not an object"))?;

    // Merge the custom metadata payload under the extension URI
    // If metadata already exists for this extension (e.g., from GW1), merge the payloads
    // with this gateway's values overriding on key collision
    if let Some(existing) = metadata.get_mut(extension_uri) {
        if let (Some(existing_obj), Some(new_obj)) = (existing.as_object_mut(), resolved_payload.as_object()) {
            // Merge: add all keys from new payload, overriding existing ones on collision
            for (key, value) in new_obj {
                existing_obj.insert(key.clone(), value.clone());
            }
            debug!(
                channel = channel_name,
                extension = extension_uri,
                "Merged custom metadata payload (GW2 overrides GW1 on collision)"
            );
        } else {
            // Not both objects, just replace
            metadata.insert(extension_uri.to_string(), resolved_payload.clone());
            debug!(
                channel = channel_name,
                extension = extension_uri,
                "Replaced custom metadata payload (not mergeable)"
            );
        }
    } else {
        // No existing metadata for this extension, just add it
        metadata.insert(extension_uri.to_string(), resolved_payload.clone());
        debug!(channel = channel_name, extension = extension_uri, "Added custom metadata payload to metadata object");
    }

    // Serialize back to bytes
    let modified_json =
        serde_json::to_vec(&body_json).map_err(|e| anyhow::anyhow!("Failed to serialize modified JSON: {}", e))?;

    Ok(bytes::Bytes::from(modified_json))
}

/// Inject agent identity credential (VP) extension into the A2A request body
/// This is called when GW1 has computed a DID for an agent and wants to forward it to GW2
/// The VP contains a VC signed by the agent's DID, proving the identity
///
/// When `workload_binding` is supplied (Transit Point Workload Binding), the VC
/// carries the structured `workloadBinding` credential subject; otherwise it
/// falls back to the flat `identityFields` shape.
pub async fn inject_identity_credential_extension(
    body_bytes: &bytes::Bytes,
    agent_did: &str,
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    workload_binding: Option<serde_json::Value>,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
) -> anyhow::Result<(bytes::Bytes, String)> {
    // Create VP containing VC signed by agent DID
    let vp_jwt = vc_issuer
        .create_agent_identity_presentation_with_binding(agent_did, identity_fields, workload_binding, None, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create identity presentation: {}", e))?;

    info!(channel = channel_name, did = agent_did, "Created identity credential VP for forwarding");

    // Parse the body as JSON
    let mut body_json: JsonValue =
        serde_json::from_slice(body_bytes).map_err(|e| anyhow::anyhow!("Failed to parse body as JSON: {}", e))?;

    // Navigate to the message object (try params.message first, then message)
    let has_params = body_json
        .get("params")
        .and_then(|p| p.get("message"))
        .is_some();
    let message = if has_params {
        body_json
            .get_mut("params")
            .and_then(|p| p.get_mut("message"))
            .ok_or_else(|| anyhow::anyhow!("No message object found in params"))?
    } else {
        body_json
            .get_mut("message")
            .ok_or_else(|| anyhow::anyhow!("No message object found in request body"))?
    };

    // Get or create the extensions array. A2A messages may legitimately omit
    // `extensions`, so create an empty array when it is missing rather than
    // failing the whole request (mirrors the metadata handling below).
    if !message
        .as_object()
        .and_then(|o| o.get("extensions"))
        .map(|e| e.is_array())
        .unwrap_or(false)
    {
        message
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("Message is not a JSON object"))?
            .insert("extensions".to_string(), JsonValue::Array(Vec::new()));
    }
    let extensions = message
        .get_mut("extensions")
        .and_then(|e| e.as_array_mut())
        .ok_or_else(|| anyhow::anyhow!("Extensions field is not an array or doesn't exist"))?;

    // Remove the original agent identity extension URI if present
    let agent_identity_uri = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;
    extensions.retain(|e| e.as_str() != Some(agent_identity_uri));

    // Add the credential extension URI to the array
    let extension_uri = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
    if !extensions
        .iter()
        .any(|e| e.as_str() == Some(extension_uri))
    {
        extensions.push(JsonValue::String(extension_uri.to_string()));
        debug!(channel = channel_name, "Added identity credential extension URI to extensions array");
    }

    // Get or create the metadata object
    if !message
        .as_object()
        .unwrap()
        .contains_key("metadata")
    {
        message
            .as_object_mut()
            .unwrap()
            .insert("metadata".to_string(), JsonValue::Object(serde_json::Map::new()));
    }

    let metadata = message
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("Metadata field is not an object"))?;

    // Remove the original agent identity metadata if present
    metadata.remove(agent_identity_uri);

    // Add the VP to the metadata
    metadata.insert(
        extension_uri.to_string(),
        serde_json::json!({
            "verifiablePresentation": vp_jwt.clone(),
            "did": agent_did,
        }),
    );

    info!(channel = channel_name, "Injected identity credential VP into metadata, removed original identity extension");

    // Serialize back to bytes
    let modified_json =
        serde_json::to_vec(&body_json).map_err(|e| anyhow::anyhow!("Failed to serialize modified JSON: {}", e))?;

    Ok((bytes::Bytes::from(modified_json), vp_jwt))
}

/// A JSON-RPC `result` read as a Task or Message. A v1.0 `SendMessage` result
/// wraps its payload (`SendMessageResponse`), so an object-valued `result.task`
/// is read in its place; a `GetTask` or v0.3 result is returned unchanged.
pub fn unwrap_task_result(result: &JsonValue) -> &JsonValue {
    result
        .get("task")
        .filter(|task| task.is_object())
        .unwrap_or(result)
}

fn unwrap_task_result_mut(result: &mut JsonValue) -> &mut JsonValue {
    if result
        .get("task")
        .is_some_and(JsonValue::is_object)
    {
        &mut result["task"]
    } else {
        result
    }
}

/// Inject agent identity credential (VP) extension into A2A response body (outbound)
/// This removes agent-identity/v1 and injects agent-identity-credential/v1 with a signed VP
/// Response structure differs from request - check multiple locations for message
/// Returns the modified body AND the VP JWT string (for auditing), or `None`,
/// without signing, when no location carries the identity extension (for
/// example when the identity was resolved from an artifact).
pub async fn inject_identity_credential_into_response(
    body_bytes: &bytes::Bytes,
    agent_did: &str,
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    workload_binding: Option<serde_json::Value>,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
) -> anyhow::Result<Option<(bytes::Bytes, String)>> {
    let mut body_json: JsonValue = serde_json::from_slice(body_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse response body as JSON: {}", e))?;

    if !visit_credential_locations(&mut body_json, &mut |message, _| Ok(carries_identity_extension(message)))? {
        debug!(channel = channel_name, "No suitable location found for VP injection in response");
        return Ok(None);
    }

    let vp_jwt = vc_issuer
        .create_agent_identity_presentation_with_binding(agent_did, identity_fields, workload_binding, None, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create identity presentation: {}", e))?;

    info!(channel = channel_name, did = agent_did, "Created identity credential VP for outbound response");

    inject_credential_into_response_json(&mut body_json, &vp_jwt, agent_did, channel_name)?;

    let modified_json = serde_json::to_vec(&body_json)
        .map_err(|e| anyhow::anyhow!("Failed to serialize modified response JSON: {}", e))?;

    Ok(Some((bytes::Bytes::from(modified_json), vp_jwt)))
}

/// Replaces the raw identity extension with the credential at every response
/// location that carries it. Returns whether any location was changed.
fn inject_credential_into_response_json(
    body_json: &mut JsonValue,
    vp_jwt: &str,
    agent_did: &str,
    channel_name: &str,
) -> anyhow::Result<bool> {
    let agent_identity_uri = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;
    let extension_uri = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
    visit_credential_locations(body_json, &mut |message, location| {
        let injected =
            inject_vp_into_message_object(message, agent_identity_uri, extension_uri, vp_jwt, agent_did, channel_name)?;
        if injected {
            info!(channel = channel_name, location, "Injected VP into response");
        }
        Ok(injected)
    })
}

/// Visits the response locations that may hold the protected agent's message:
/// `result.message`, `result.status.message`, `result` itself when it carries
/// `extensions`, and a top-level `message`, with `result` read through
/// [`unwrap_task_result`]. Returns whether `visit` reported a match anywhere.
fn visit_credential_locations(
    body_json: &mut JsonValue,
    visit: &mut dyn FnMut(&mut JsonValue, &'static str) -> anyhow::Result<bool>,
) -> anyhow::Result<bool> {
    let mut matched = false;
    if let Some(outer) = body_json.get_mut("result") {
        let result = unwrap_task_result_mut(outer);
        if let Some(message) = result.get_mut("message") {
            matched |= visit(message, "result.message")?;
        }
        if let Some(message) = result
            .get_mut("status")
            .and_then(|status| status.get_mut("message"))
        {
            matched |= visit(message, "result.status.message")?;
        }
        if result
            .get("extensions")
            .is_some()
        {
            matched |= visit(result, "result")?;
        }
    }
    if let Some(message) = body_json.get_mut("message") {
        matched |= visit(message, "message")?;
    }
    Ok(matched)
}

/// Whether a message declares the raw identity extension or the credential.
fn carries_identity_extension(message: &JsonValue) -> bool {
    let agent_identity_uri = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;
    let extension_uri = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
    message
        .get("extensions")
        .and_then(|e| e.as_array())
        .is_some_and(|extensions| {
            extensions
                .iter()
                .any(|e| e.as_str() == Some(agent_identity_uri) || e.as_str() == Some(extension_uri))
        })
}

/// Helper function to inject VP into a message object's extensions and metadata
fn inject_vp_into_message_object(
    message: &mut JsonValue,
    agent_identity_uri: &str,
    extension_uri: &str,
    vp_jwt: &str,
    agent_did: &str,
    channel_name: &str,
) -> anyhow::Result<bool> {
    // Get extensions array
    let extensions = match message
        .get_mut("extensions")
        .and_then(|e| e.as_array_mut())
    {
        Some(arr) => arr,
        None => {
            debug!(channel = channel_name, "No extensions array found in message object");
            return Ok(false);
        }
    };

    // Check if either identity extension is present
    let has_identity_ext = extensions
        .iter()
        .any(|e| e.as_str() == Some(agent_identity_uri) || e.as_str() == Some(extension_uri));

    if !has_identity_ext {
        debug!(channel = channel_name, "No identity extension found in message, skipping");
        return Ok(false);
    }

    // Remove the original agent identity extension URI if present
    extensions.retain(|e| e.as_str() != Some(agent_identity_uri));

    // Add the credential extension URI if not already present
    if !extensions
        .iter()
        .any(|e| e.as_str() == Some(extension_uri))
    {
        extensions.push(JsonValue::String(extension_uri.to_string()));
        debug!(channel = channel_name, "Added identity credential extension URI to response extensions array");
    }

    // Get or create the metadata object
    if !message
        .as_object()
        .map(|o| o.contains_key("metadata"))
        .unwrap_or(false)
    {
        message
            .as_object_mut()
            .unwrap()
            .insert("metadata".to_string(), JsonValue::Object(serde_json::Map::new()));
    }

    let metadata = match message
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
    {
        Some(m) => m,
        None => {
            return Err(anyhow::anyhow!("Failed to get or create metadata object"));
        }
    };

    // Remove the original agent identity metadata if present
    metadata.remove(agent_identity_uri);

    // Add the VP to the metadata
    metadata.insert(
        extension_uri.to_string(),
        serde_json::json!({
            "verifiablePresentation": vp_jwt,
            "did": agent_did,
        }),
    );

    info!(channel = channel_name, "Injected identity credential VP into response metadata");

    Ok(true)
}

/// Replace `agent-identity/v1` with `agent-identity-credential/v1` in an agent card.
///
/// Agent cards use `capabilities.extensions[{ uri, params }]` rather than
/// the flat `extensions[]` + `metadata{}` used by messages. This function
/// finds the identity extension entry, creates a signed VP from the resolved
/// identity, and swaps the entry in-place.
#[async_trait::async_trait]
trait AgentIdentityPresenter: Send + Sync {
    async fn create_presentation(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> anyhow::Result<String>;
}

#[async_trait::async_trait]
impl AgentIdentityPresenter for crate::identity::VCIssuer {
    async fn create_presentation(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    ) -> anyhow::Result<String> {
        self.create_agent_identity_presentation(agent_did, identity_fields, None, None)
            .await
    }
}

pub async fn inject_credential_into_agent_card(
    agent_card: &mut JsonValue,
    resolved_identity: &ProtectedAgentIdentity,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
) -> anyhow::Result<()> {
    inject_credential_into_agent_card_inner(agent_card, resolved_identity, vc_issuer.as_ref(), channel_name, false)
        .await
}

pub async fn upsert_credential_into_agent_card(
    agent_card: &mut JsonValue,
    resolved_identity: &ProtectedAgentIdentity,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
) -> anyhow::Result<()> {
    inject_credential_into_agent_card_inner(agent_card, resolved_identity, vc_issuer.as_ref(), channel_name, true).await
}

async fn inject_credential_into_agent_card_inner(
    agent_card: &mut JsonValue,
    resolved_identity: &ProtectedAgentIdentity,
    presenter: &dyn AgentIdentityPresenter,
    channel_name: &str,
    allow_insert: bool,
) -> anyhow::Result<()> {
    let (agent_did, identity_fields) = match resolved_identity {
        ProtectedAgentIdentity::Managed { did, identity_fields } => (did, identity_fields),
        ProtectedAgentIdentity::Anonymous => {
            return Ok(());
        }
    };

    let identity_uri = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;
    let credential_uri = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;

    let extensions = agent_card
        .get_mut("capabilities")
        .and_then(|c| c.get_mut("extensions"))
        .and_then(|e| e.as_array_mut());

    let extensions = match extensions {
        Some(exts) => exts,
        None => {
            return Err(anyhow::anyhow!(
                "Agent card has no capabilities.extensions array but managed_identity is enabled"
            ));
        }
    };

    let identity_idx = extensions
        .iter()
        .position(|ext| {
            ext.get("uri")
                .and_then(|u| u.as_str())
                == Some(identity_uri)
        });

    let credential_idx = extensions
        .iter()
        .position(|ext| {
            ext.get("uri")
                .and_then(|u| u.as_str())
                == Some(credential_uri)
        });

    // If agent-identity-credential/v1 is already present the credential was
    // injected by an upstream gateway. GW1 does not need to re-inject its own
    // VP on top. This is correct for multi-hop fabric flows where GW2 already
    // resolved the agent identity and signed the credential with its own VC
    // issuer before forwarding the card to GW1.
    //
    // Security note: this path does not re-verify the upstream VP signature.
    // Trust in the upstream gateway's credential is established at the
    // transport layer (TLS + fabric DIDComm auth on the GW1->GW2 channel).
    // Structural consistency (DID matching VP holder/subject) is enforced in
    // the identity-resolution short-circuit in proxy/backend_identity.rs
    // before this function is reached, so a forged params.did is already
    // caught.
    if !allow_insert && credential_idx.is_some() {
        debug!(channel = channel_name, "Agent card already has agent-identity-credential/v1, skipping injection");
        return Ok(());
    }

    let existing_idx = identity_idx.or(credential_idx);

    let idx = match existing_idx {
        Some(i) => Some(i),
        None if allow_insert => None,
        None => {
            return Err(anyhow::anyhow!(
                "Agent card does not declare {} but managed_identity is enabled",
                identity_uri
            ));
        }
    };

    let vp_jwt = presenter
        .create_presentation(agent_did, identity_fields)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create identity presentation for agent card: {}", e))?;

    let credential_ext = serde_json::json!({
        "uri": credential_uri,
        "params": {
            "verifiablePresentation": vp_jwt,
            "did": agent_did,
        }
    });

    if let Some(idx) = idx {
        extensions[idx] = credential_ext;
    } else {
        extensions.push(credential_ext);
    }

    info!(channel = channel_name, did = agent_did, "Upserted agent-identity-credential/v1 in agent card");

    Ok(())
}

/// Inject VP into A2A response
/// Replaces raw identity extension with credential extension containing VP
pub async fn inject_vp_into_a2a_response(
    response_bytes: &bytes::Bytes,
    agent_did: &str,
    identity_fields: &std::collections::HashMap<String, serde_json::Value>,
    workload_binding: Option<serde_json::Value>,
    vc_issuer: &Arc<crate::identity::VCIssuer>,
    channel_name: &str,
    inbound_chained_vcs: Vec<serde_json::Value>,
) -> anyhow::Result<(bytes::Bytes, String)> {
    // Create VP containing the serverIdentity VC signed by the backend agent's
    // DID. When a workload_binding is supplied the VC uses structured
    // `workloadBinding` (agentIdentity + userIdentity), otherwise falls back
    // to legacy `identityFields`. Any VCs from the verified inbound
    // agentIdentity binding VP are flattened in so the receiver sees the
    // request-side provenance alongside the response-side serverIdentity.
    let chain_len = inbound_chained_vcs.len();
    let vp_jwt = vc_issuer
        .create_agent_identity_presentation_chained(
            agent_did,
            identity_fields,
            workload_binding,
            None,
            None,
            inbound_chained_vcs,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create identity presentation: {}", e))?;
    info!(
        channel = channel_name,
        did = agent_did,
        chained_vcs = chain_len,
        "Created serverIdentity VP for backend agent A2A response"
    );

    // Parse the response as JSON
    let mut response_json: JsonValue = serde_json::from_slice(response_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse response as JSON: {}", e))?;

    // Navigate to the message object - could be result.history[0] or result directly
    let message_obj = if let Some(result) = response_json.get_mut("result") {
        // Try history first (multi-message response)
        if let Some(history_arr) = result
            .get_mut("history")
            .and_then(|h| h.as_array_mut())
        {
            if let Some(first_msg) = history_arr.first_mut() {
                debug!(channel = channel_name, "VP injection: Using result.history[0]");
                first_msg
            } else {
                return Err(anyhow::anyhow!("History array is empty"));
            }
        } else if result
            .get("metadata")
            .is_some()
            || result
                .get("extensions")
                .is_some()
        {
            // Direct message response (single message)
            debug!(channel = channel_name, "VP injection: Using result directly");
            result
        } else {
            return Err(anyhow::anyhow!("No history array or metadata found in result"));
        }
    } else {
        return Err(anyhow::anyhow!("No result field found in response"));
    };

    // Get or create the extensions array
    if !message_obj
        .as_object()
        .map(|o| o.contains_key("extensions"))
        .unwrap_or(false)
        && let Some(msg_obj) = message_obj.as_object_mut()
    {
        msg_obj.insert("extensions".to_string(), JsonValue::Array(vec![]));
    }

    let extensions = message_obj
        .get_mut("extensions")
        .and_then(|e| e.as_array_mut())
        .ok_or_else(|| anyhow::anyhow!("Extensions field is not an array or doesn't exist"))?;

    // Remove the original agent identity extension URI if present
    let agent_identity_uri = crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION;
    extensions.retain(|e| e.as_str() != Some(agent_identity_uri));

    // Add the credential extension URI to the array
    let extension_uri = crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION;
    if !extensions
        .iter()
        .any(|e| e.as_str() == Some(extension_uri))
    {
        extensions.push(JsonValue::String(extension_uri.to_string()));
        debug!(channel = channel_name, "Added identity credential extension URI to response extensions array");
    }

    // Get or create the metadata object
    if !message_obj
        .as_object()
        .map(|o| o.contains_key("metadata"))
        .unwrap_or(false)
        && let Some(msg_obj) = message_obj.as_object_mut()
    {
        msg_obj.insert("metadata".to_string(), JsonValue::Object(serde_json::Map::new()));
    }

    let metadata = message_obj
        .get_mut("metadata")
        .and_then(|m| m.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("Metadata field is not an object"))?;

    // Remove the original agent identity metadata if present
    metadata.remove(agent_identity_uri);

    // Add the VP to the metadata
    metadata.insert(
        extension_uri.to_string(),
        serde_json::json!({
            "verifiablePresentation": vp_jwt,
            "did": agent_did,
        }),
    );

    info!(channel = channel_name, "Injected backend agent identity credential VP into response, removed raw identity");

    // Serialize back to bytes
    let modified_json = serde_json::to_vec(&response_json)
        .map_err(|e| anyhow::anyhow!("Failed to serialize modified response JSON: {}", e))?;

    Ok((bytes::Bytes::from(modified_json), vp_jwt))
}

/// Inject DID:webvh identity into an A2A message's extensions array
///
/// This function adds the DID:webvh identity to the message's extensions array,
/// making it available to the receiving agent in the A2A protocol format.
#[cfg(feature = "didwebvh")]
pub async fn inject_didwebvh_identity_extension(
    body_bytes: &bytes::Bytes,
    did_context: &crate::identity::didwebvh::SurfaceDidContext,
    channel_name: &str,
) -> anyhow::Result<bytes::Bytes> {
    use serde_json::Value as JsonValue;

    // Parse the body as JSON
    let mut body_json: JsonValue =
        serde_json::from_slice(body_bytes).map_err(|e| anyhow::anyhow!("Failed to parse body as JSON: {}", e))?;

    // Navigate to the message object (try params.message first, then message)
    let has_params = body_json
        .get("params")
        .and_then(|p| p.get("message"))
        .is_some();
    let message = if has_params {
        body_json
            .get_mut("params")
            .and_then(|p| p.get_mut("message"))
            .ok_or_else(|| anyhow::anyhow!("No message object found in params"))?
    } else {
        body_json
            .get_mut("message")
            .ok_or_else(|| anyhow::anyhow!("No message object found in request body"))?
    };

    // Get or create the extensions array
    let extensions = message
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Message is not an object"))?
        .entry("extensions")
        .or_insert_with(|| JsonValue::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("Extensions is not an array"))?;

    // Create the DID:webvh identity extension
    let extension_uri = "https://fabric.affinidi.io/extensions/didwebvh-identity/v1";
    let identity_extension = serde_json::json!({
        "type": extension_uri,
        "did": did_context.did(),
        "uai": {
            "llm_provider": did_context.uai().llm_provider,
            "llm_model": did_context.uai().llm_model,
            "deployment_location": did_context.uai().deployment_location,
        }
    });

    // Add the extension
    extensions.push(identity_extension);

    debug!(
        channel = channel_name,
        extension_uri = extension_uri,
        did = %did_context.did(),
        "Injected DID:webvh identity into A2A extensions array"
    );

    // Serialize back to bytes
    let modified_json =
        serde_json::to_vec(&body_json).map_err(|e| anyhow::anyhow!("Failed to serialize modified JSON: {}", e))?;

    Ok(bytes::Bytes::from(modified_json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::backend_identity::ProtectedAgentIdentity;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    const IDENTITY_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";
    const CREDENTIAL_URI: &str = "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";

    fn agent_message() -> serde_json::Value {
        json!({
            "role": "ROLE_AGENT",
            "parts": [{ "text": "done" }],
            "extensions": [IDENTITY_URI],
            "metadata": { IDENTITY_URI: { "name": "backend-agent" } }
        })
    }

    fn assert_carries_credential(message: &serde_json::Value) {
        assert_eq!(message["extensions"], json!([CREDENTIAL_URI]));
        assert!(
            message["metadata"]
                .get(IDENTITY_URI)
                .is_none()
        );
        assert_eq!(
            message["metadata"][CREDENTIAL_URI],
            json!({ "verifiablePresentation": "vp.jwt", "did": "did:web:agent" })
        );
    }

    #[test]
    fn credential_is_injected_into_a_wrapped_v1_task_status_message() {
        let mut body = json!({
            "result": { "task": { "id": "t", "status": { "state": "TASK_STATE_COMPLETED", "message": agent_message() } } }
        });
        assert!(inject_credential_into_response_json(&mut body, "vp.jwt", "did:web:agent", "ch").unwrap());
        assert_carries_credential(&body["result"]["task"]["status"]["message"]);
    }

    #[test]
    fn credential_is_injected_into_a_bare_task_status_message() {
        let mut body = json!({
            "result": { "kind": "task", "id": "t", "status": { "state": "completed", "message": agent_message() } }
        });
        assert!(inject_credential_into_response_json(&mut body, "vp.jwt", "did:web:agent", "ch").unwrap());
        assert_carries_credential(&body["result"]["status"]["message"]);
    }

    #[test]
    fn wrapped_task_is_read_in_place_of_result() {
        let mut body = json!({
            "result": {
                "message": agent_message(),
                "task": { "id": "t", "status": { "state": "TASK_STATE_COMPLETED", "message": agent_message() } }
            }
        });
        assert!(inject_credential_into_response_json(&mut body, "vp.jwt", "did:web:agent", "ch").unwrap());
        assert_carries_credential(&body["result"]["task"]["status"]["message"]);
        assert_eq!(
            body["result"]["message"],
            agent_message(),
            "the sibling of a wrapped task is not a response location"
        );
    }

    #[test]
    fn artifact_only_identity_has_no_credential_location() {
        let mut body = json!({
            "result": { "task": {
                "id": "t",
                "status": { "state": "TASK_STATE_COMPLETED" },
                "artifacts": [{ "artifactId": "a", "parts": [], "extensions": [IDENTITY_URI], "metadata": { IDENTITY_URI: {} } }]
            } }
        });
        let before = body.clone();
        assert!(
            !visit_credential_locations(&mut body, &mut |message, _| Ok(carries_identity_extension(message))).unwrap()
        );
        assert!(!inject_credential_into_response_json(&mut body, "vp.jwt", "did:web:agent", "ch").unwrap());
        assert_eq!(body, before, "an artifact keeps its raw extension");
    }

    #[test]
    fn non_object_task_is_not_unwrapped() {
        let result = json!({ "task": "t", "extensions": [IDENTITY_URI] });
        assert_eq!(unwrap_task_result(&result), &result);
    }

    #[test]
    fn inject_header_metadata_extension_adds_metadata_and_extension_uri() {
        let body = bytes::Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "method": "message/send",
                "params": {
                    "message": {
                        "role": "user",
                        "parts": [{ "kind": "text", "text": "hello" }]
                    }
                },
                "id": "1"
            }))
            .unwrap(),
        );
        let mapping = crate::config::header_metadata_mapping::HeaderMetadataMappingConfig {
            headers: vec![crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                header: "x-agent-id".to_string(),
                field: "agent_id".to_string(),
            }],
            ..Default::default()
        };
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("X-Agent-ID", axum::http::HeaderValue::from_static("agent-123"));

        let (modified, mapped_count) =
            inject_header_metadata_extension(&body, &mapping, &headers, "test-channel").expect("inject metadata");
        let json: serde_json::Value = serde_json::from_slice(&modified).expect("modified body should be JSON");

        assert_eq!(mapped_count, 1);
        assert_eq!(json["params"]["message"]["metadata"][&mapping.extension_uri]["agent_id"], "agent-123");
        assert!(
            json["params"]["message"]["extensions"]
                .as_array()
                .expect("extensions should be an array")
                .iter()
                .any(|value| value.as_str() == Some(mapping.extension_uri.as_str()))
        );
    }

    #[test]
    fn inject_header_metadata_extension_skips_when_headers_are_missing() {
        let body = bytes::Bytes::from(
            serde_json::to_vec(&json!({
                "message": {
                    "role": "user",
                    "parts": [{ "kind": "text", "text": "hello" }]
                }
            }))
            .unwrap(),
        );
        let mapping = crate::config::header_metadata_mapping::HeaderMetadataMappingConfig {
            headers: vec![crate::config::header_metadata_mapping::HeaderMetadataFieldMapping {
                header: "x-agent-id".to_string(),
                field: "agent_id".to_string(),
            }],
            ..Default::default()
        };

        let (modified, mapped_count) =
            inject_header_metadata_extension(&body, &mapping, &axum::http::HeaderMap::new(), "test-channel")
                .expect("missing headers should not fail");

        assert_eq!(mapped_count, 0);
        assert_eq!(modified, body);
    }

    fn identity_fields() -> HashMap<String, serde_json::Value> {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), json!("test-agent"));
        fields
    }

    /// Create a VCIssuer, register an identity, and return the issuer + real DID.
    async fn issuer_with_identity() -> (Arc<crate::identity::VCIssuer>, String, tempfile::TempDir) {
        let (issuer, tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let resp = issuer
            .issue_or_get_credential(identity_fields(), None, None, None)
            .await
            .expect("issue_or_get_credential should succeed");
        (issuer, resp.did, tmp)
    }

    fn managed_identity_with_did(did: &str) -> ProtectedAgentIdentity {
        ProtectedAgentIdentity::Managed {
            did: did.to_string(),
            identity_fields: identity_fields(),
        }
    }

    fn agent_card_with_identity() -> JsonValue {
        json!({
            "name": "test-agent",
            "url": "http://example.com/a2a",
            "capabilities": {
                "extensions": [
                    {
                        "uri": IDENTITY_URI,
                        "params": {
                            "name": "test-agent"
                        }
                    }
                ]
            }
        })
    }

    struct FailingPresenter;

    #[async_trait::async_trait]
    impl AgentIdentityPresenter for FailingPresenter {
        async fn create_presentation(
            &self,
            _agent_did: &str,
            _identity_fields: &HashMap<String, serde_json::Value>,
        ) -> anyhow::Result<String> {
            anyhow::bail!("presentation creation failed")
        }
    }

    // ── Anonymous short-circuit ──────────────────────────────────────────

    #[tokio::test]
    async fn anonymous_identity_is_noop() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);

        let mut card = agent_card_with_identity();
        let original = card.clone();

        let result =
            inject_credential_into_agent_card(&mut card, &ProtectedAgentIdentity::Anonymous, &issuer, "test-channel")
                .await;

        assert!(result.is_ok());
        assert_eq!(card, original, "card should be unchanged for Anonymous");
    }

    // ── Error: no capabilities.extensions ────────────────────────────────

    #[tokio::test]
    async fn error_when_no_capabilities_key() {
        let (issuer, _did, _tmp) = issuer_with_identity().await;

        let mut card = json!({ "name": "test-agent" });

        let result =
            inject_credential_into_agent_card(&mut card, &managed_identity_with_did(&_did), &issuer, "test-channel")
                .await;

        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("no capabilities.extensions array"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn error_when_extensions_is_not_array() {
        let (issuer, _did, _tmp) = issuer_with_identity().await;

        let mut card = json!({
            "capabilities": { "extensions": "not-an-array" }
        });

        let result =
            inject_credential_into_agent_card(&mut card, &managed_identity_with_did(&_did), &issuer, "test-channel")
                .await;

        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("no capabilities.extensions array"),
            "unexpected error: {err}"
        );
    }

    // ── Error: agent-identity/v1 not declared ────────────────────────────

    #[tokio::test]
    async fn error_when_identity_extension_missing() {
        let (issuer, _did, _tmp) = issuer_with_identity().await;

        let mut card = json!({
            "capabilities": {
                "extensions": [
                    { "uri": "https://example.com/other-ext", "params": {} }
                ]
            }
        });

        let result =
            inject_credential_into_agent_card(&mut card, &managed_identity_with_did(&_did), &issuer, "test-channel")
                .await;

        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("does not declare"),
            "unexpected error: {err}"
        );
    }

    // When the card already carries agent-identity-credential/v1 (injected by
    // an upstream gateway), injection must be a no-op — not a 502 error.
    #[tokio::test]
    async fn skip_when_credential_already_present() {
        let (issuer, _did, _tmp) = issuer_with_identity().await;
        let forwarded_did = "did:webvh:QmForeignCardDid:gw2.example:surface:123";
        let forwarded_vp = "eyJhbGciOiJFZERTQSJ9.e30.sig";

        let mut card = json!({
            "capabilities": {
                "extensions": [
                    {
                        "uri": crate::config::AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION,
                        "params": {
                            "did": forwarded_did,
                            "verifiablePresentation": forwarded_vp
                        }
                    }
                ]
            }
        });

        let original = card.clone();

        let result = inject_credential_into_agent_card(
            &mut card,
            &managed_identity_with_did(forwarded_did),
            &issuer,
            "test-channel",
        )
        .await;

        // Must succeed (Ok) — card unchanged since credential already present
        assert!(result.is_ok(), "expected Ok but got: {:?}", result.unwrap_err());
        assert_eq!(card, original, "forwarded credentialed card must remain unchanged");
    }

    #[tokio::test]
    async fn error_when_empty_extensions_array() {
        let (issuer, _did, _tmp) = issuer_with_identity().await;

        let mut card = json!({
            "capabilities": { "extensions": [] }
        });

        let result =
            inject_credential_into_agent_card(&mut card, &managed_identity_with_did(&_did), &issuer, "test-channel")
                .await;

        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("does not declare"),
            "unexpected error: {err}"
        );
    }

    // ── Error: VP creation fails ─────────────────────────────────────────

    #[tokio::test]
    async fn error_when_vp_creation_fails() {
        let mut card = agent_card_with_identity();
        let identity = managed_identity_with_did("did:key:zTestAgent");

        let result =
            inject_credential_into_agent_card_inner(&mut card, &identity, &FailingPresenter, "test-channel", false)
                .await;

        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("Failed to create identity presentation"),
            "unexpected error: {err}"
        );
    }

    // ── Happy path ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn replaces_identity_with_credential_extension() {
        let (issuer, did, _tmp) = issuer_with_identity().await;

        let mut card = agent_card_with_identity();

        let result =
            inject_credential_into_agent_card(&mut card, &managed_identity_with_did(&did), &issuer, "test-channel")
                .await;

        assert!(result.is_ok(), "injection should succeed: {:?}", result.err());

        let extensions = card["capabilities"]["extensions"]
            .as_array()
            .expect("extensions should be an array");
        assert_eq!(extensions.len(), 1, "should still have exactly one extension");

        let ext = &extensions[0];
        assert_eq!(ext["uri"].as_str().unwrap(), CREDENTIAL_URI, "URI should be credential extension");

        let params = ext
            .get("params")
            .expect("should have params");
        assert!(
            params
                .get("verifiablePresentation")
                .is_some(),
            "params should contain verifiablePresentation"
        );

        // VP can be a compact JWT (3 dot-separated segments) or a JSON-LD object with proof
        let vp = &params["verifiablePresentation"];
        let is_jwt = vp
            .as_str()
            .is_some_and(|s| s.split('.').count() == 3);
        let is_json_ld = vp.is_object() && vp.get("proof").is_some();
        let is_json_string = vp
            .as_str()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
            .is_some_and(|obj| obj.get("proof").is_some());
        assert!(
            is_jwt || is_json_ld || is_json_string,
            "verifiablePresentation should be a valid VP (JWT or JSON-LD), got: {vp}"
        );

        assert_eq!(
            params["did"]
                .as_str()
                .unwrap(),
            did,
            "params.did should match the managed identity DID"
        );
    }

    #[tokio::test]
    async fn preserves_other_extensions() {
        let (issuer, did, _tmp) = issuer_with_identity().await;

        let other_ext_uri = "https://example.com/other/v1";
        let mut card = json!({
            "capabilities": {
                "extensions": [
                    { "uri": other_ext_uri, "params": { "foo": "bar" } },
                    { "uri": IDENTITY_URI, "params": { "name": "test-agent" } }
                ]
            }
        });

        let result =
            inject_credential_into_agent_card(&mut card, &managed_identity_with_did(&did), &issuer, "test-channel")
                .await;

        assert!(result.is_ok());

        let extensions = card["capabilities"]["extensions"]
            .as_array()
            .unwrap();
        assert_eq!(extensions.len(), 2, "should still have two extensions");

        let uris: Vec<&str> = extensions
            .iter()
            .filter_map(|e| e["uri"].as_str())
            .collect();
        assert!(uris.contains(&other_ext_uri), "other extension should be preserved");
        assert!(uris.contains(&CREDENTIAL_URI), "credential extension should be present");
        assert!(!uris.contains(&IDENTITY_URI), "raw identity extension should be gone");

        let other = extensions
            .iter()
            .find(|e| e["uri"].as_str() == Some(other_ext_uri))
            .unwrap();
        assert_eq!(
            other["params"]["foo"]
                .as_str()
                .unwrap(),
            "bar"
        );
    }
}
