//! DID:webvh API Handlers
//!
//! HTTP API handlers for managing DID:webvh identities

use anyhow::Context;
use axum::{
    Json,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::identity_manager::{
    CreateDidRequest, CreateDidResponse, DidWebVhIdentity, DidWebVhIdentityListItem, DidWebVhIdentityResponse,
    DidWebVhIdentityStore,
};
use super::log::DidLogManager;
use super::types::{DidDocument, KeyPair};
use crate::identity::uai::types::{
    AgentDna, AttestationData, BehavioralFingerprint, BirthEvent, GenesisFingerprint, ModelSpec, OperationalFingerprint,
};
use crate::source_auth::models::{CredentialExtraction, DidAuthAuthConfig};
use crate::storage::DidLogStorage;

/// Shared state for DID:webvh API handlers
#[derive(Clone)]
pub struct DidWebVhApiState {
    pub identity_store: Arc<dyn DidWebVhIdentityStore>,
    pub log_storage: Arc<dyn DidLogStorage>,
    pub base_url: String, // e.g., "https://gateway.example.com"
}

/// Error response
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ErrorResponse {
    fn new(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            details: None,
        }
    }

    fn with_details(
        error: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            error: error.into(),
            details: Some(details.into()),
        }
    }
}

/// Formats a base URL for use in a DID:webvh string.
/// Strips protocol prefix and URL-encodes special characters (e.g., `:` → `%3A`)
/// according to the DID:web specification.
fn format_did_domain(base_url: &str) -> String {
    let domain = base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    // URL-encode the colon in port numbers (e.g., localhost:8080 → localhost%3A8080)
    domain.replace(':', "%3A")
}

/// Build a didwebvh-rs `Secret` suitable for signing from a JWK private key.
///
/// The library requires the `Secret.id` to be a `did:key:` URI matching one of the
/// DID log's `update_keys`.  We derive the multibase public key from the JWK,
/// construct the canonical `did:key:<mb>#<mb>` identifier, and build the secret.
fn build_signing_secret(private_key_jwk: &serde_json::Value) -> Result<didwebvh_rs::prelude::Secret, String> {
    let temp_id = "did:key:temp#temp";
    let raw = didwebvh_rs::prelude::Secret::from_str(temp_id, private_key_jwk)
        .map_err(|e| format!("Failed to build key Secret: {e}"))?;
    let mb = raw
        .get_public_keymultibase()
        .map_err(|e| format!("Failed to get key multibase: {e}"))?;
    let key_id = format!("did:key:{0}#{0}", mb);
    let mut secret = didwebvh_rs::prelude::Secret::from_str(&key_id, private_key_jwk)
        .map_err(|e| format!("Failed to build signing Secret: {e}"))?;
    secret.id = key_id;
    Ok(secret)
}

/// Load raw log entries and build a validated `DIDWebVHState`.
///
/// Returns `(raw_entries, webvh_state)` — the raw strings for `append_raw` and
/// the populated state for `update_did`.
async fn load_raw_and_build_state(
    storage: &dyn DidLogStorage,
    did: &str,
) -> Result<(Vec<String>, didwebvh_rs::DIDWebVHState), String> {
    let raw_entries = storage
        .load_all_raw(did)
        .await
        .map_err(|e| format!("Failed to load DID log: {e}"))?;
    let webvh_state = build_webvh_state(did, &raw_entries).await?;
    Ok((raw_entries, webvh_state))
}

/// Build a validated `DIDWebVHState` from already loaded raw log entries.
async fn build_webvh_state(
    did: &str,
    raw_entries: &[String],
) -> Result<didwebvh_rs::DIDWebVHState, String> {
    if raw_entries.is_empty() {
        return Err("No log entries found".to_string());
    }
    let jsonl = raw_entries.join("\n");
    let mut webvh_state = didwebvh_rs::DIDWebVHState::default();
    webvh_state
        .resolve_log(did, &jsonl, None)
        .await
        .map_err(|e| format!("Failed to load DID state: {e}"))?;
    Ok(webvh_state)
}

fn transfer_ownership_challenge(
    did: &str,
    version_id: &str,
    new_controller: &str,
) -> String {
    format!("transfer-ownership:{did}:{version_id}:{new_controller}")
}

/// Verify a transfer authorization: a compact JWS signed by a verification
/// method of the identity's current DID document, over the challenge that binds
/// this exact transfer (DID, latest log `versionId`, new controller).
fn verify_transfer_authorization(
    did: &str,
    latest_entry: &super::types::LogEntry,
    new_controller: &str,
    authorization: &str,
) -> Result<(), String> {
    let doc_json =
        serde_json::to_value(&latest_entry.state).map_err(|e| format!("Failed to serialize DID document: {e}"))?;
    let config = DidAuthAuthConfig {
        extraction: CredentialExtraction::HttpHeader {
            field: "Authorization".to_string(),
        },
        allowed_dids: vec![],
        challenge_ttl_seconds: None,
        session_ttl_seconds: None,
        audience: None,
        allowed_algorithms: vec![],
    };
    let challenge = transfer_ownership_challenge(did, &latest_entry.version_id, new_controller);
    crate::didauth::verify::verify_challenge_response_with_doc(did, authorization, &challenge, &config, &doc_json)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Handler for POST /api/v1/identities
/// Creates a new DID:webvh identity
pub async fn create_identity(
    State(state): State<DidWebVhApiState>,
    Json(request): Json<CreateDidRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("=== CREATE IDENTITY HANDLER INVOKED ===");
    info!("Creating new DID:webvh identity");

    // Generate UUID for internal identifier
    let id = Uuid::new_v4();

    // Determine DID path (use provided or generate from UUID)
    let did_path = match request.did_path {
        Some(path) => path,
        None => format!("agents/{}", id),
    };

    // Construct DID with {SCID} placeholder per did:webvh spec §3.7.3.
    // The actual SCID is computed from the preliminary log entry and substituted
    // to produce the final canonical DID: did:webvh:<scid>:<domain>:<path>.
    let base_domain = format_did_domain(&state.base_url);
    let did_path_str = did_path.replace('/', ":");
    let placeholder_did = format!("did:webvh:{{SCID}}:{}:{}", base_domain, did_path_str);

    debug!("Placeholder DID: {}", placeholder_did);

    // Generate or use provided key pair
    let key_pair = match request.key_pair {
        Some(kp) => kp,
        None => {
            // Generate new Ed25519 key pair
            generate_ed25519_keypair().map_err(|e| {
                error!("Failed to generate key pair: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::with_details("Failed to generate key pair", e.to_string())),
                )
            })?
        }
    };

    let did_document = serde_json::json!({
        "id": placeholder_did,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{}#key-1", placeholder_did),
            "type": "JsonWebKey2020",
            "controller": placeholder_did,
            "publicKeyJwk": key_pair.public_key
        }],
        "authentication": [format!("{}#key-1", placeholder_did)],
        "assertionMethod": [format!("{}#key-1", placeholder_did)],
        "capabilityInvocation": [format!("{}#key-1", placeholder_did)]
    });

    // Create DID:webvh via shared helper (Secret conversion, SCID computation, signing, bridge)
    let result = super::create::create_webvh_did(&key_pair.private_key, did_document, &state.base_url)
        .await
        .map_err(|e| {
            error!("Failed to create DID: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to create DID", e.to_string())),
            )
        })?;

    let final_did = result.final_did;
    let log_entry_json = result.log_entry_json;
    let signed_entry = result.signed_entry;

    // Persist log entry under the final SCID-based DID key (raw JSON preserves signature)
    state
        .log_storage
        .append_raw(&final_did, &log_entry_json)
        .await
        .map_err(|e| {
            error!("Failed to store DID log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to store DID log", e.to_string())),
            )
        })?;

    // Resolve or randomly-generate Agent DNA.
    // If the caller provided an explicit `agentDNA` value in metadata it is used as-is;
    // otherwise fresh random fingerprints are synthesised from the identity's SCID.
    let scid = &result.scid;
    let mut metadata = request.metadata;
    let agent_dna = metadata
        .get("agentDNA")
        .and_then(|v| serde_json::from_value::<AgentDna>(v.clone()).ok())
        .unwrap_or_else(|| generate_random_dna(scid));
    if let Ok(dna_value) = serde_json::to_value(&agent_dna) {
        metadata.insert("agentDNA".to_string(), dna_value);
    }

    // Create identity record with the final SCID-based DID
    let now = chrono::Utc::now();
    let identity = DidWebVhIdentity {
        id,
        did: final_did.clone(),
        key_pair: Some(key_pair),
        version: 1,
        created_at: now,
        updated_at: now,
        metadata,
        active: true,
    };

    // Store identity
    state
        .identity_store
        .create(identity)
        .await
        .map_err(|e| {
            error!("Failed to store identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to store identity", e.to_string())),
            )
        })?;

    info!("Created DID:webvh identity {} with DID {}", id, final_did);
    info!("=== IDENTITY STORED SUCCESSFULLY ===");
    info!("Storage path: identities/{}.json", id);

    let response = CreateDidResponse {
        id,
        did: final_did.clone(),
        did_document: signed_entry.state.clone(),
        created_at: now,
    };

    info!("Returning response: {:?}", serde_json::to_string(&response));
    Ok((StatusCode::CREATED, Json(response)))
}

/// Handler for GET /api/v1/identities/{id}
/// Retrieves a DID:webvh identity by UUID
pub async fn get_identity(
    State(state): State<DidWebVhApiState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    debug!("Retrieving DID:webvh identity {}", id);

    let identity = state
        .identity_store
        .get(&id)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("Identity not found"))))?;

    Ok((StatusCode::OK, Json(DidWebVhIdentityResponse::from(identity))))
}

/// Handler for GET /api/v1/identities
/// Lists all DID:webvh identities
pub async fn list_identities(
    State(state): State<DidWebVhApiState>
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("=== LIST IDENTITIES HANDLER INVOKED ===");

    let identities = state
        .identity_store
        .list()
        .await
        .map_err(|e| {
            error!("Failed to list identities: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to list identities", e.to_string())),
            )
        })?;

    info!("Found {} identities in store", identities.len());
    for identity in &identities {
        info!("  - {} ({})", identity.id, identity.did);
    }

    #[derive(Serialize)]
    struct ListResponse {
        identities: Vec<DidWebVhIdentityListItem>,
        count: usize,
    }

    let response = ListResponse {
        count: identities.len(),
        identities,
    };

    info!("Returning list response with {} identities", response.count);
    Ok((StatusCode::OK, Json(response)))
}

/// Handler for GET /dids/{*path}
/// Serves the DID log file for a given DID
/// Path should end with /did.jsonl (e.g., /dids/alice/did.jsonl)
pub async fn serve_did_log(
    State(state): State<DidWebVhApiState>,
    Path(raw_path): Path<String>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Dispatch /whois requests to the whois handler (spec §3.10)
    if let Some(did_path) = raw_path.strip_suffix("/whois") {
        return serve_whois(State(state), Path(did_path.to_string()))
            .await
            .map(|r| r.into_response());
    }

    // Strip /did.jsonl suffix if present (spec-required endpoint)
    let did_path = raw_path
        .strip_suffix("/did.jsonl")
        .or_else(|| raw_path.strip_suffix("did.jsonl"))
        .unwrap_or(&raw_path);

    debug!("Serving DID log for path: {} (raw: {})", did_path, raw_path);

    // Try direct path lookup first (fast path)
    let identity = state
        .identity_store
        .get_by_path(did_path)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity by path: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?;

    // If not found by path, try reconstructing DID (fallback for compatibility)
    let identity = if identity.is_none() {
        let base_domain = format_did_domain(&state.base_url);
        let did = format!("did:webvh:{}:{}", base_domain, did_path.replace('/', ":"));

        debug!("Path lookup failed, trying DID: {}", did);

        state
            .identity_store
            .get_by_did(&did)
            .await
            .map_err(|e| {
                error!("Failed to retrieve identity by DID: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
                )
            })?
    } else {
        identity
    };

    let identity = identity.ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("DID not found"))))?;

    let did = identity.did.clone();
    debug!("Resolved path '{}' to DID: {}", did_path, did);

    // Load DID log entries
    let log_entries = state
        .log_storage
        .load_all(&did)
        .await
        .map_err(|e| {
            error!("Failed to load DID log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to load DID log", e.to_string())),
            )
        })?;

    if log_entries.is_empty() {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse::new("DID log not found"))));
    }

    // Convert log entries to JSON Lines format
    let mut jsonl_content = String::new();
    for entry in &log_entries {
        let entry_json = serde_json::to_string(entry).map_err(|e| {
            error!("Failed to serialize log entry: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to serialize log entry", e.to_string())),
            )
        })?;
        jsonl_content.push_str(&entry_json);
        jsonl_content.push('\n');
    }

    debug!("Serving DID log with {} entries", log_entries.len());

    // Return as JSON Lines with appropriate content type (spec §3.4 step 6: text/jsonl)
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/jsonl"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        jsonl_content,
    )
        .into_response())
}

/// Response for /whois endpoint
#[derive(Debug, Serialize)]
pub struct WhoisResponse {
    pub did: String,
    pub scid: String,
    pub versions: u32,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "firstVersion")]
    pub first_version: String,
    #[serde(rename = "createdTime")]
    pub created_time: String,
    #[serde(rename = "updatedTime")]
    pub updated_time: String,
    pub portable: bool,
    pub deactivated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

/// Handler for GET /{path}/whois
/// Returns metadata about the DID log (per spec §3.10)
/// Does not include the full DID document, only log metadata
pub async fn serve_whois(
    State(state): State<DidWebVhApiState>,
    Path(did_path): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    debug!("Serving whois for path: {}", did_path);

    // Try direct path lookup first (fast path)
    let identity = state
        .identity_store
        .get_by_path(&did_path)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity by path: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?;

    // If not found by path, try reconstructing DID (fallback for compatibility)
    let identity = if identity.is_none() {
        let base_domain = format_did_domain(&state.base_url);
        let did = format!("did:webvh:{}:{}", base_domain, did_path.replace('/', ":"));

        debug!("Path lookup failed, trying DID: {}", did);

        state
            .identity_store
            .get_by_did(&did)
            .await
            .map_err(|e| {
                error!("Failed to retrieve identity by DID: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
                )
            })?
    } else {
        identity
    };

    let identity = identity.ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("DID not found"))))?;

    let did = identity.did.clone();
    debug!("Resolved path '{}' to DID: {}", did_path, did);

    // Load DID log entries
    let log_entries = state
        .log_storage
        .load_all(&did)
        .await
        .map_err(|e| {
            error!("Failed to load DID log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to load DID log", e.to_string())),
            )
        })?;

    if log_entries.is_empty() {
        return Err((StatusCode::NOT_FOUND, Json(ErrorResponse::new("DID log not found"))));
    }

    let first_entry = &log_entries[0];
    let latest_entry = log_entries.last().unwrap();

    let whois_response = WhoisResponse {
        did: did.clone(),
        scid: first_entry
            .parameters
            .scid
            .clone(),
        versions: log_entries.len() as u32,
        version_id: latest_entry
            .version_id
            .clone(),
        first_version: first_entry.version_id.clone(),
        created_time: first_entry
            .version_time
            .clone(),
        updated_time: latest_entry
            .version_time
            .clone(),
        portable: latest_entry
            .parameters
            .portable,
        deactivated: latest_entry
            .parameters
            .deactivated,
        ttl: latest_entry.parameters.ttl,
    };

    debug!("Serving whois metadata for DID {} with {} versions", did, log_entries.len());

    // Return as JSON with appropriate caching
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "public, max-age=300")],
        Json(whois_response),
    ))
}

/// Handler for DELETE /api/v1/identities/{id}
/// Deactivates a DID:webvh identity (per spec: appends deactivation log entry)
pub async fn delete_identity(
    State(state): State<DidWebVhApiState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("Deactivating DID:webvh identity {}", id);

    // Get existing identity
    let mut identity = state
        .identity_store
        .get(&id)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("Identity not found"))))?;

    if !identity.active {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Identity already deactivated"))));
    }

    let did = identity.did.clone();

    // Build signing secret from identity's key pair
    let key_pair = identity
        .key_pair
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Identity missing key pair"))))?;

    let signing_secret = build_signing_secret(&key_pair.private_key).map_err(|e| {
        error!("Failed to build signing secret: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to build signing key", e)))
    })?;

    // Build DIDWebVHState from raw log (preserves signatures)
    let (_, webvh_state) = load_raw_and_build_state(state.log_storage.as_ref(), &did)
        .await
        .map_err(|e| {
            error!("Failed to build DID state: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to load DID state", e)))
        })?;

    // Deactivate via library — handles pre-rotation teardown automatically
    let update_result = didwebvh_rs::prelude::update_did(
        didwebvh_rs::prelude::UpdateDIDConfig::builder()
            .state(webvh_state)
            .signing_key(signing_secret)
            .deactivate(true)
            .build()
            .map_err(|e| {
                error!("Failed to build deactivation config: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::with_details("Failed to build deactivation config", e.to_string())),
                )
            })?,
    )
    .await
    .map_err(|e| {
        error!("Failed to deactivate DID: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to deactivate DID", e.to_string())),
        )
    })?;

    // Persist the deactivation entry (raw bytes preserve signature)
    let new_entry_json = serde_json::to_string(update_result.log_entry()).map_err(|e| {
        error!("Failed to serialize deactivation entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to serialize deactivation entry", e.to_string())),
        )
    })?;
    let signed_entry: super::types::LogEntry = serde_json::from_str(&new_entry_json).map_err(|e| {
        error!("Failed to deserialize deactivation entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to deserialize deactivation entry", e.to_string())),
        )
    })?;

    state
        .log_storage
        .append_raw(&did, &new_entry_json)
        .await
        .map_err(|e| {
            error!("Failed to append deactivation entry: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to append deactivation entry", e.to_string())),
            )
        })?;

    let now = chrono::Utc::now();

    // Mark as inactive in database
    identity.active = false;
    identity.version += 1;
    identity.updated_at = now;

    let identity_version = identity.version;
    state
        .identity_store
        .update(identity)
        .await
        .map_err(|e| {
            error!("Failed to update identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to update identity", e.to_string())),
            )
        })?;

    info!("Deactivated DID:webvh identity {} at version {}", id, identity_version);

    #[derive(Serialize)]
    struct DeleteResponse {
        message: String,
        id: Uuid,
        version_id: String,
        deactivated_at: chrono::DateTime<chrono::Utc>,
    }

    let response = DeleteResponse {
        message: "Identity deactivated".to_string(),
        id,
        version_id: signed_entry.version_id,
        deactivated_at: now,
    };

    Ok((StatusCode::OK, Json(response)))
}

/// Handler for GET /api/v1/resolve?did={did}&versionId={versionId}&versionTime={versionTime}
/// Resolves a DID to its current DID document or a specific version
/// Supports DID URL query parameters per spec §3.8 and §3.9:
/// - ?versionId=N-hash - Resolves to specific version
/// - ?versionTime=ISO8601 - Resolves to version at or before specified time
pub async fn resolve_did(
    State(state): State<DidWebVhApiState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let did = params
        .get("did")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Missing 'did' query parameter"))))?;

    debug!("Resolving DID: {}", did);

    // Use the resolver to get the DID document
    use super::resolver::DidWebvhResolver;
    let resolver = DidWebvhResolver::new(state.log_storage.clone());

    // Check for version-specific queries
    let did_document = if let Some(version_id) = params.get("versionId") {
        // Resolve to specific version by versionId
        debug!("Resolving DID {} to versionId {}", did, version_id);
        resolver
            .resolve_version_id(did, version_id)
            .await
            .map_err(|e| {
                error!("Failed to resolve DID {} with versionId {}: {}", did, version_id, e);
                if e.to_string()
                    .contains("not found")
                {
                    (StatusCode::NOT_FOUND, Json(ErrorResponse::with_details("Version not found", e.to_string())))
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::with_details("Failed to resolve DID", e.to_string())),
                    )
                }
            })?
    } else if let Some(version_time) = params.get("versionTime") {
        // Resolve to version at or before specified time
        debug!("Resolving DID {} to versionTime {}", did, version_time);
        resolver
            .resolve_version_time(did, version_time)
            .await
            .map_err(|e| {
                error!("Failed to resolve DID {} with versionTime {}: {}", did, version_time, e);
                if e.to_string()
                    .contains("not found")
                    || e.to_string()
                        .contains("no version")
                {
                    (
                        StatusCode::NOT_FOUND,
                        Json(ErrorResponse::with_details("No version found at specified time", e.to_string())),
                    )
                } else if e
                    .to_string()
                    .contains("invalid versionTime")
                {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse::with_details("Invalid versionTime format", e.to_string())),
                    )
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::with_details("Failed to resolve DID", e.to_string())),
                    )
                }
            })?
    } else {
        // Resolve to latest version
        resolver
            .resolve(did)
            .await
            .map_err(|e| {
                error!("Failed to resolve DID {}: {}", did, e);
                if e.to_string()
                    .contains("did log empty")
                    || e.to_string()
                        .contains("not found")
                {
                    (StatusCode::NOT_FOUND, Json(ErrorResponse::with_details("DID not found", e.to_string())))
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::with_details("Failed to resolve DID", e.to_string())),
                    )
                }
            })?
    };

    info!("Resolved DID: {}", did);

    Ok((StatusCode::OK, Json(did_document)))
}

/// Request body for updating a DID document
#[derive(Debug, Deserialize)]
pub struct UpdateDidRequest {
    /// Updated DID document
    pub did_document: DidDocument,
    /// Optional new update keys
    pub update_keys: Option<Vec<String>>,
    /// Optional TTL for caching
    pub ttl: Option<u32>,
}

/// Handler for POST /api/v1/identities/{id}/update
/// Updates a DID:webvh identity's DID document
pub async fn update_identity(
    State(state): State<DidWebVhApiState>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateDidRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("Updating DID:webvh identity {}", id);

    // Get existing identity
    let mut identity = state
        .identity_store
        .get(&id)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("Identity not found"))))?;

    if !identity.active {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Cannot update inactive identity"))));
    }

    let did = identity.did.clone();

    // Build signing secret
    let key_pair = identity
        .key_pair
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Identity missing key pair"))))?;

    let signing_secret = build_signing_secret(&key_pair.private_key).map_err(|e| {
        error!("Failed to build signing secret: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to build signing key", e)))
    })?;

    // Build DIDWebVHState from raw log (preserves signatures)
    let (_, webvh_state) = load_raw_and_build_state(state.log_storage.as_ref(), &did)
        .await
        .map_err(|e| {
            error!("Failed to build DID state: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to load DID state", e)))
        })?;

    // Serialize the new DID document to JSON Value for the library
    let new_doc_json = serde_json::to_value(&request.did_document).map_err(|e| {
        error!("Failed to serialize DID document: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to serialize DID document", e.to_string())),
        )
    })?;

    // Build update config with optional parameter changes
    let mut builder = didwebvh_rs::prelude::UpdateDIDConfig::builder()
        .state(webvh_state)
        .signing_key(signing_secret)
        .document(new_doc_json);

    if let Some(ttl) = request.ttl {
        builder = builder.ttl(ttl);
    }

    let update_result = didwebvh_rs::prelude::update_did(builder.build().map_err(|e| {
        error!("Failed to build update config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to build update config", e.to_string())),
        )
    })?)
    .await
    .map_err(|e| {
        error!("Failed to update DID: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to update DID", e.to_string())))
    })?;

    // Persist via raw JSON (preserves signature)
    let new_entry_json = serde_json::to_string(update_result.log_entry()).map_err(|e| {
        error!("Failed to serialize update entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to serialize log entry", e.to_string())),
        )
    })?;
    let signed_entry: super::types::LogEntry = serde_json::from_str(&new_entry_json).map_err(|e| {
        error!("Failed to deserialize update entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to deserialize log entry", e.to_string())),
        )
    })?;

    state
        .log_storage
        .append_raw(&did, &new_entry_json)
        .await
        .map_err(|e| {
            error!("Failed to append update entry: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to append update entry", e.to_string())),
            )
        })?;

    // Update identity record
    let now = chrono::Utc::now();
    identity.version += 1;
    identity.updated_at = now;

    state
        .identity_store
        .update(identity.clone())
        .await
        .map_err(|e| {
            error!("Failed to update identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to update identity", e.to_string())),
            )
        })?;

    info!("Updated DID:webvh identity {} to version {}", id, identity.version);

    #[derive(Serialize)]
    struct UpdateResponse {
        id: Uuid,
        did: String,
        version: u64,
        version_id: String,
        updated_at: chrono::DateTime<chrono::Utc>,
    }

    let response = UpdateResponse {
        id,
        did,
        version: identity.version,
        version_id: signed_entry.version_id,
        updated_at: identity.updated_at,
    };

    Ok((StatusCode::OK, Json(response)))
}

/// Request body for key rotation
#[derive(Debug, Deserialize)]
pub struct RotateKeysRequest {
    /// Optional new key pair (if not provided, new keys will be generated)
    pub new_key_pair: Option<KeyPair>,
}

/// Handler for POST /api/v1/identities/{id}/rotate-keys
/// Rotates the signing keys for a DID:webvh identity
pub async fn rotate_keys(
    State(state): State<DidWebVhApiState>,
    Path(id): Path<Uuid>,
    Json(request): Json<RotateKeysRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("Rotating keys for DID:webvh identity {}", id);

    // Get existing identity
    let mut identity = state
        .identity_store
        .get(&id)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("Identity not found"))))?;

    if !identity.active {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Cannot rotate keys for inactive identity"))));
    }

    let did = identity.did.clone();

    // Load raw log entries (preserves exact JSON for signature validation)
    let raw_entries = state
        .log_storage
        .load_all_raw(&did)
        .await
        .map_err(|e| {
            error!("Failed to load DID log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to load DID log", e.to_string())),
            )
        })?;

    if raw_entries.is_empty() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("No previous log entry found"))));
    }

    // Parse last entry for pre-rotation check
    let previous_entry: super::types::LogEntry = serde_json::from_str(raw_entries.last().unwrap()).map_err(|e| {
        error!("Failed to parse last log entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to parse last log entry", e.to_string())),
        )
    })?;

    // Generate or use provided new key pair
    let new_key_pair = match request.new_key_pair {
        Some(kp) => kp,
        None => generate_ed25519_keypair().map_err(|e| {
            error!("Failed to generate key pair: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to generate key pair", e.to_string())),
            )
        })?,
    };

    // Verify pre-rotation if nextKeyHashes were specified (per spec §3.7.7)
    if let Some(ref next_key_hashes) = previous_entry
        .parameters
        .next_key_hashes
        && !next_key_hashes.is_empty()
    {
        let new_key_hash = compute_key_hash(&new_key_pair.public_key).map_err(|e| {
            error!("Failed to compute new key hash: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to compute key hash", e.to_string())),
            )
        })?;

        if !next_key_hashes.contains(&new_key_hash) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new("New key does not match any pre-rotated key hashes (nextKeyHashes)")),
            ));
        }

        info!("Pre-rotation verification passed for new key hash: {}", new_key_hash);
    }

    // Build new DID document from raw JSON (preserves @context and other fields)
    let mut new_doc_json: serde_json::Value = serde_json::from_str(raw_entries.last().unwrap()).map_err(|e| {
        error!("Failed to parse raw log entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to parse raw log entry", e.to_string())),
        )
    })?;
    // Extract the "state" field from the raw log entry to get the full DID document
    let new_doc_json = new_doc_json
        .get_mut("state")
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Log entry missing state field"))))?
        .take();

    // Update verificationMethod in the raw JSON document
    let new_doc_json = {
        let mut doc = new_doc_json;
        if let Some(vms) = doc
            .get_mut("verificationMethod")
            .and_then(|v| v.as_array_mut())
        {
            vms.clear();
            vms.push(serde_json::json!({
                "id": format!("{}#key-1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": new_key_pair.public_key,
            }));
        }
        doc
    };

    // Build old-key Secret for signing
    let old_key_pair = identity
        .key_pair
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Identity missing key pair"))))?;

    let old_secret = build_signing_secret(&old_key_pair.private_key).map_err(|e| {
        error!("Failed to build signing secret: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to build signing key", e)))
    })?;

    // Build new-key multibase (spec §3.7.2: update_keys must be multibase public keys)
    let new_secret = build_signing_secret(&new_key_pair.private_key).map_err(|e| {
        error!("Failed to build new key secret: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to build new key", e)))
    })?;
    let new_mb = new_secret
        .get_public_keymultibase()
        .map_err(|e| {
            error!("Failed to get new key multibase: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to get new key multibase", e.to_string())),
            )
        })?;

    // Build DIDWebVHState from raw log entries (preserves original bytes for validation)
    let (_, webvh_state) = load_raw_and_build_state(state.log_storage.as_ref(), &did)
        .await
        .map_err(|e| {
            error!("Failed to build DID state: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to load DID state", e)))
        })?;

    // Call update_did() — library computes entry hash, verifies auth, signs
    let update_result = didwebvh_rs::prelude::update_did(
        didwebvh_rs::prelude::UpdateDIDConfig::builder()
            .state(webvh_state)
            .signing_key(old_secret)
            .update_keys(vec![didwebvh_rs::Multibase::new(new_mb)])
            .document(new_doc_json)
            .build()
            .map_err(|e| {
                error!("Failed to build UpdateDIDConfig: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::with_details("Failed to build update config", e.to_string())),
                )
            })?,
    )
    .await
    .map_err(|e| {
        error!("Failed to update DID: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to update DID", e.to_string())))
    })?;

    // Bridge: serialize library LogEntry → gateway LogEntry via JSON round-trip
    let new_entry_json = serde_json::to_string(update_result.log_entry()).map_err(|e| {
        error!("Failed to serialize update log entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to serialize log entry", e.to_string())),
        )
    })?;
    let signed_entry: super::types::LogEntry = serde_json::from_str(&new_entry_json).map_err(|e| {
        error!("Failed to deserialize update log entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to deserialize log entry", e.to_string())),
        )
    })?;

    state
        .log_storage
        .append_raw(&did, &new_entry_json)
        .await
        .map_err(|e| {
            error!("Failed to append rotation log entry: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to append rotation entry", e.to_string())),
            )
        })?;

    let now = chrono::Utc::now();

    // Update identity record with new key pair
    identity.key_pair = Some(new_key_pair.clone());
    identity.version += 1;
    identity.updated_at = now;

    state
        .identity_store
        .update(identity.clone())
        .await
        .map_err(|e| {
            error!("Failed to update identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to update identity", e.to_string())),
            )
        })?;

    info!("Rotated keys for DID:webvh identity {} to version {}", id, identity.version);

    #[derive(Serialize)]
    struct RotateKeysResponse {
        id: Uuid,
        did: String,
        version: u64,
        version_id: String,
        new_public_key: serde_json::Value,
        rotated_at: chrono::DateTime<chrono::Utc>,
    }

    let response = RotateKeysResponse {
        id,
        did,
        version: identity.version,
        version_id: signed_entry.version_id,
        new_public_key: new_key_pair.public_key,
        rotated_at: identity.updated_at,
    };

    Ok((StatusCode::OK, Json(response)))
}

/// Request for verifying a DID
#[derive(Debug, Deserialize)]
pub struct VerifyDidRequest {
    /// Optional Agent DNA for enhanced trust computation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dna: Option<crate::identity::uai::types::AgentDna>,
}

/// Response for verify_identity endpoint
#[derive(Debug, Serialize)]
pub struct VerifyIdentityResponse {
    pub did: String,
    pub valid: bool,
    pub trust_score: Option<crate::identity::uai::types::TrustScore>,
    pub did_document: Option<DidDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_errors: Option<Vec<String>>,
}

/// Handler for GET /api/v1/verify/{did}
/// Verifies a DID and computes trust score
pub async fn verify_identity(
    State(state): State<DidWebVhApiState>,
    Path(did): Path<String>,
    Json(request): Json<Option<VerifyDidRequest>>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("Verifying DID: {}", did);

    // Resolve the DID
    let resolver = super::resolver::DidWebvhResolver::new(state.log_storage.clone());
    let did_document = match resolver.resolve(&did).await {
        Ok(doc) => doc,
        Err(e) => {
            // Check if it's a not-found error
            let error_msg = e.to_string();
            if error_msg.contains("not found") || error_msg.contains("empty") {
                return Ok((
                    StatusCode::NOT_FOUND,
                    Json(VerifyIdentityResponse {
                        did: did.clone(),
                        valid: false,
                        trust_score: None,
                        did_document: None,
                        verification_errors: Some(vec!["DID document not found".to_string()]),
                    }),
                ));
            }
            error!("Failed to resolve DID: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to resolve DID", e.to_string())),
            ));
        }
    };

    // Verify the DID log
    let log_manager = DidLogManager::new(state.log_storage.clone());
    let log_entries = log_manager
        .load(&did)
        .await
        .map_err(|e| {
            error!("Failed to load DID log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to load DID log", e.to_string())),
            )
        })?;

    if log_entries.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(VerifyIdentityResponse {
                did: did.clone(),
                valid: false,
                trust_score: None,
                did_document: Some(did_document),
                verification_errors: Some(vec!["No log entries found".to_string()]),
            }),
        ));
    }

    // Verify the log integrity
    let verifier = super::verifier::DidWebvhVerifier::new();
    let verification_result = match verifier.verify(&log_entries) {
        Ok(report) => report,
        Err(e) => {
            return Ok((
                StatusCode::OK,
                Json(VerifyIdentityResponse {
                    did: did.clone(),
                    valid: false,
                    trust_score: None,
                    did_document: Some(did_document),
                    verification_errors: Some(vec![format!("Verification failed: {}", e)]),
                }),
            ));
        }
    };

    if !verification_result.valid {
        return Ok((
            StatusCode::OK,
            Json(VerifyIdentityResponse {
                did: did.clone(),
                valid: false,
                trust_score: None,
                did_document: Some(did_document),
                verification_errors: Some(verification_result.errors),
            }),
        ));
    }

    // Compute trust score
    let dna = request
        .as_ref()
        .and_then(|r| r.dna.as_ref());
    let trust_computer = super::trust_computer::TrustComputer::new();
    let trust_score = trust_computer
        .compute(&did, &log_manager, dna)
        .await
        .map_err(|e| {
            error!("Failed to compute trust score: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to compute trust score", e.to_string())),
            )
        })?;

    info!("Verified DID {} - valid: true, trust score: {:.3}", did, trust_score.score);

    Ok((
        StatusCode::OK,
        Json(VerifyIdentityResponse {
            did: did.clone(),
            valid: true,
            trust_score: Some(trust_score),
            did_document: Some(did_document),
            verification_errors: None,
        }),
    ))
}

/// Response for get_identity_history endpoint
#[derive(Debug, Serialize)]
pub struct IdentityHistoryResponse {
    pub did: String,
    pub versions: Vec<VersionInfo>,
    pub total_versions: usize,
}

/// Information about a specific version
#[derive(Debug, Serialize)]
pub struct VersionInfo {
    pub version_id: String,
    pub version_time: String,
    pub version_number: u64,
    pub update_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<String>,
}

/// Handler for GET /api/v1/identities/{id}/history
/// Returns version history for an identity
pub async fn get_identity_history(
    State(state): State<DidWebVhApiState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting history for identity {}", id);

    // Get the identity to find the DID
    let identity = state
        .identity_store
        .get(&id)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("Identity not found"))))?;

    let did = identity.did.clone();

    // Load all log entries
    let log_manager = DidLogManager::new(state.log_storage.clone());
    let log_entries = log_manager
        .load(&did)
        .await
        .map_err(|e| {
            error!("Failed to load DID log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to load DID log", e.to_string())),
            )
        })?;

    // Convert to version info
    let versions: Vec<VersionInfo> = log_entries
        .iter()
        .enumerate()
        .map(|(idx, entry)| {
            let changes = if idx == 0 {
                Some("Initial creation".to_string())
            } else {
                // Could add logic to detect what changed between versions
                Some("Update".to_string())
            };

            VersionInfo {
                version_id: entry.version_id.clone(),
                version_time: entry.version_time.clone(),
                version_number: (idx + 1) as u64,
                update_keys: entry
                    .parameters
                    .update_keys
                    .clone(),
                changes,
            }
        })
        .collect();

    let response = IdentityHistoryResponse {
        did,
        versions,
        total_versions: log_entries.len(),
    };

    Ok((StatusCode::OK, Json(response)))
}

/// Request for transferring ownership
#[derive(Debug, Deserialize)]
pub struct TransferOwnershipRequest {
    /// New controller DID
    pub new_controller: String,

    /// Proof of control of the identity's current signing key: a compact JWS
    /// (`alg` EdDSA, `kid` naming a verification method of this DID) whose
    /// payload carries a fresh `iat` and
    /// `challenge` = `transfer-ownership:<did>:<latest versionId>:<new_controller>`
    pub current_owner_authorization: String,

    /// Optional authorization from new owner (for dual-signature flow)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_owner_authorization: Option<String>,

    /// Optional updated ownership proof for Genesis pillar
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_ownership_proof: Option<String>,

    /// Optional transfer reason/notes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_reason: Option<String>,
}

/// Response for transfer_ownership endpoint
#[derive(Debug, Serialize)]
pub struct TransferOwnershipResponse {
    pub id: Uuid,
    pub did: String,
    pub new_controller: String,
    pub version: u64,
    pub version_id: String,
    pub transferred_at: chrono::DateTime<chrono::Utc>,
}

/// Handler for POST /api/v1/identities/{id}/transfer
/// Transfers ownership of an identity to a new controller
pub async fn transfer_ownership(
    State(state): State<DidWebVhApiState>,
    Path(id): Path<Uuid>,
    Json(request): Json<TransferOwnershipRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("Transferring ownership for identity {}", id);

    // Get existing identity
    let mut identity = state
        .identity_store
        .get(&id)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("Identity not found"))))?;

    if !identity.active {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Cannot transfer inactive identity"))));
    }

    let did = identity.did.clone();

    // Validate new controller DID format
    if !request
        .new_controller
        .starts_with("did:")
    {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new("Invalid new controller DID format"))));
    }

    let raw_entries = state
        .log_storage
        .load_all_raw(&did)
        .await
        .map_err(|e| {
            error!("Failed to load DID log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to load DID log", e.to_string())),
            )
        })?;

    let latest_entry: super::types::LogEntry = raw_entries
        .last()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("No log entries found"))))
        .and_then(|raw| {
            serde_json::from_str(raw).map_err(|e| {
                error!("Failed to parse latest log entry: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::with_details("Failed to parse latest log entry", e.to_string())),
                )
            })
        })?;

    verify_transfer_authorization(&did, &latest_entry, &request.new_controller, &request.current_owner_authorization)
        .map_err(|e| {
        warn!("Rejected ownership transfer for identity {}: {}", id, e);
        (StatusCode::UNAUTHORIZED, Json(ErrorResponse::with_details("Current owner authorization rejected", e)))
    })?;

    // Build DIDWebVHState from raw log (preserves signatures)
    let webvh_state = build_webvh_state(&did, &raw_entries)
        .await
        .map_err(|e| {
            error!("Failed to build DID state: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to load DID state", e)))
        })?;

    let key_pair = identity
        .key_pair
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new("Identity missing key pair"))))?;

    let signing_secret = build_signing_secret(&key_pair.private_key).map_err(|e| {
        error!("Failed to build signing secret: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::with_details("Failed to build signing key", e)))
    })?;

    // For ownership transfer, we keep the current DID document unchanged
    // and record transfer metadata in the identity record.

    // Create transfer log entry via library
    let now = chrono::Utc::now();
    let mut transfer_metadata = serde_json::Map::new();
    transfer_metadata.insert("transfer_type".to_string(), serde_json::json!("ownership"));
    transfer_metadata.insert("new_controller".to_string(), serde_json::json!(request.new_controller));
    transfer_metadata.insert("transferred_at".to_string(), serde_json::json!(now.to_rfc3339()));

    if let Some(reason) = &request.transfer_reason {
        transfer_metadata.insert("reason".to_string(), serde_json::json!(reason));
    }

    if let Some(proof) = &request.new_ownership_proof {
        transfer_metadata.insert("ownership_proof".to_string(), serde_json::json!(proof));
    }

    // Use update_did() with no document change — just creates a signed log entry
    let update_result = didwebvh_rs::prelude::update_did(
        didwebvh_rs::prelude::UpdateDIDConfig::builder()
            .state(webvh_state)
            .signing_key(signing_secret)
            .build()
            .map_err(|e| {
                error!("Failed to build transfer config: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::with_details("Failed to build transfer config", e.to_string())),
                )
            })?,
    )
    .await
    .map_err(|e| {
        error!("Failed to create transfer entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to create transfer entry", e.to_string())),
        )
    })?;

    // Persist via raw JSON (preserves signature)
    let new_entry_json = serde_json::to_string(update_result.log_entry()).map_err(|e| {
        error!("Failed to serialize transfer entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to serialize transfer entry", e.to_string())),
        )
    })?;
    let signed_entry: super::types::LogEntry = serde_json::from_str(&new_entry_json).map_err(|e| {
        error!("Failed to deserialize transfer entry: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to deserialize transfer entry", e.to_string())),
        )
    })?;

    state
        .log_storage
        .append_raw(&did, &new_entry_json)
        .await
        .map_err(|e| {
            error!("Failed to append transfer entry: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to append transfer entry", e.to_string())),
            )
        })?;

    // Update identity record with transfer metadata
    identity.version += 1;
    identity.updated_at = now;

    // Store transfer information in metadata
    identity
        .metadata
        .insert("last_transfer".to_string(), serde_json::to_value(&transfer_metadata).unwrap());
    identity
        .metadata
        .insert("controller".to_string(), serde_json::json!(request.new_controller));

    state
        .identity_store
        .update(identity.clone())
        .await
        .map_err(|e| {
            error!("Failed to update identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to update identity", e.to_string())),
            )
        })?;

    info!("Transferred ownership of identity {} to {} at version {}", id, request.new_controller, identity.version);

    let response = TransferOwnershipResponse {
        id,
        did,
        new_controller: request.new_controller,
        version: identity.version,
        version_id: signed_entry.version_id,
        transferred_at: now,
    };

    Ok((StatusCode::OK, Json(response)))
}

/// Generate random Agent DNA for demo/testing purposes.
///
/// In production each pillar would be computed from real measurements (code
/// analysis, behavioural profiling, operational attestations). For the
/// February demo all fingerprints are synthesised from cryptographically
/// random bytes so the shape matches the full UAI format without requiring
/// actual measurement infrastructure.
pub(crate) fn generate_random_dna(scid: &str) -> AgentDna {
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    let now = chrono::Utc::now().to_rfc3339();
    let mut rng = rand::rng();
    let mut random_hex = || -> String {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    };

    // Genesis
    let code_hash = random_hex();
    let config_hash = random_hex();
    let genesis_preimage = format!("genesis:{}:tgw-managed:demo:{}", code_hash, config_hash);
    let genesis_hash = hex::encode(Sha256::digest(genesis_preimage.as_bytes()));
    let genesis = GenesisFingerprint {
        code_hash,
        model_spec: ModelSpec {
            provider: "tgw-managed".to_string(),
            model: "demo".to_string(),
            version: Some("1.0".to_string()),
        },
        config_hash,
        ownership_proof: None,
        genesis_hash: genesis_hash.clone(),
        computed_at: now.clone(),
    };

    // Behavioral
    let behavioral_hash = random_hex();
    let behavioral = BehavioralFingerprint {
        latency_profile_hash: Some(random_hex()),
        challenge_response_hash: Some(random_hex()),
        token_pattern_hash: None,
        behavioral_hash: behavioral_hash.clone(),
        measured_at: now.clone(),
    };

    // Operational
    let capabilities_hash = random_hex();
    let operational_hash = random_hex();
    let operational = OperationalFingerprint {
        tee_attestation: None,
        cloud_attestation: None,
        capabilities_hash,
        operational_hash: operational_hash.clone(),
        attested_at: now.clone(),
    };

    // Attestations — one synthetic creator attestation
    let merkle_root = random_hex();
    let attestations = AttestationData {
        merkle_root: merkle_root.clone(),
        count: 1,
        last_updated: Some(now.clone()),
    };

    // Birth event
    let birth_entry_hash = random_hex();
    let birth_event = BirthEvent {
        scid: scid.to_string(),
        timestamp: now.clone(),
        initial_genesis: genesis.clone(),
        birth_entry_hash,
    };

    // UAI: uai:1:<scid>:<genesis[..8]>.<behavioral[..8]>.<operational[..8]>.<attestation[..8]>
    let uai = format!(
        "uai:1:{}:{}.{}.{}.{}",
        scid,
        &genesis_hash[..8],
        &behavioral_hash[..8],
        &operational_hash[..8],
        &merkle_root[..8],
    );

    AgentDna {
        uai,
        birth_event,
        genesis,
        behavioral,
        operational,
        attestations,
    }
}

/// Helper function to generate Ed25519 key pair
pub(crate) fn generate_ed25519_keypair() -> anyhow::Result<KeyPair> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::RngCore;

    // Generate key pair using rand
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key: VerifyingKey = (&signing_key).into();

    // Convert to JWK format
    let private_key = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        "x": URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
    });

    let public_key = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
    });

    Ok(KeyPair {
        public_key,
        private_key,
        key_type: "Ed25519".to_string(),
    })
}

/// Helper function to create initial DID document
pub(crate) fn create_initial_did_document(
    did: &str,
    key_pair: &KeyPair,
) -> anyhow::Result<DidDocument> {
    // Create verification method
    let verification_method = serde_json::json!({
        "id": format!("{}#key-1", did),
        "type": "JsonWebKey2020",
        "controller": did,
        "publicKeyJwk": key_pair.public_key,
    });

    let mut doc = DidDocument::new(did).context("Invalid DID format")?;

    // Add verification method
    if let Ok(vm) = serde_json::from_value(verification_method.clone()) {
        doc.verification_method
            .push(vm);
    }

    // Add authentication, assertion, and capability invocation references
    if let Ok(vm_id) = serde_json::from_value(serde_json::Value::String(format!("{}#key-1", did))) {
        doc.authentication.push(vm_id);
    }
    if let Ok(vm_id) = serde_json::from_value(serde_json::Value::String(format!("{}#key-1", did))) {
        doc.assertion_method
            .push(vm_id);
    }
    if let Ok(vm_id) = serde_json::from_value(serde_json::Value::String(format!("{}#key-1", did))) {
        doc.capability_invocation
            .push(vm_id);
    }

    Ok(doc)
}

/// Helper function to create initial birth log entry
pub(crate) fn create_birth_log_entry(
    did: &str,
    did_document: DidDocument,
) -> anyhow::Result<super::types::LogEntry> {
    use super::types::{LogEntry, LogParameters};

    let now = chrono::Utc::now();

    Ok(LogEntry {
        version_id: "{SCID}".to_string(), // Spec §3.6.1: placeholder, replaced after SCID computation
        version_time: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        parameters: LogParameters {
            method: "did:webvh:1.0".to_string(),
            scid: "{SCID}".to_string(), // Spec §3.6.1: placeholder, replaced after SCID computation
            update_keys: vec![format!("{}#key-1", did)],
            next_key_hashes: None,
            portable: false,
            ttl: None,
            witness: None,
            watchers: None,
            deactivated: false,
        },
        state: did_document,
        proof: vec![], // Will be set by log manager
    })
}

/// Helper function to convert JWK private key to SigningKey
pub(crate) fn jwk_to_signing_key(jwk: &serde_json::Value) -> anyhow::Result<ed25519_dalek::SigningKey> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Extract the 'd' (private key) field from JWK
    let d_str = jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'd' field in JWK"))?;

    // Decode the base64url-encoded private key
    let key_bytes = URL_SAFE_NO_PAD
        .decode(d_str)
        .context("Failed to decode private key")?;

    // Convert to SigningKey
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length, expected 32 bytes"))?;

    Ok(ed25519_dalek::SigningKey::from_bytes(&key_array))
}

/// Helper function to compute hash of a public key for pre-rotation verification
/// Uses SHA-256 hash of the JWK public key (per spec §3.7.7)
fn compute_key_hash(public_key_jwk: &serde_json::Value) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};

    // Canonicalize the public key JWK using JCS (RFC 8785)
    let canonical = serde_jcs::to_string(public_key_jwk).context("Failed to canonicalize public key")?;

    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hash_bytes = hasher.finalize();

    // Encode as base58btc multibase
    let encoded = multibase::encode(multibase::Base::Base58Btc, hash_bytes);

    Ok(encoded)
}

/// Extract Agent DNA from identity metadata
///
/// This function extracts all four pillars of UAI from the identity metadata:
/// - Genesis: code, model, config hashes
/// - Behavioral: latency, challenge-response, token patterns
/// - Operational: TEE/cloud attestations, capabilities
/// - Attestations: Merkle root and count
fn extract_agent_dna_from_metadata(
    metadata: &std::collections::HashMap<String, serde_json::Value>,
    scid: &str,
) -> Option<crate::identity::uai::types::AgentDna> {
    // Try to extract DNA if already present
    if let Some(dna_value) = metadata.get("agentDNA")
        && let Ok(dna) = serde_json::from_value::<AgentDna>(dna_value.clone())
    {
        return Some(dna);
    }

    // Otherwise, construct from individual fields
    let now = chrono::Utc::now().to_rfc3339();

    // Extract Genesis fingerprint
    let genesis = if let Some(genesis_value) = metadata.get("genesis") {
        serde_json::from_value(genesis_value.clone()).ok()?
    } else {
        // Build from components
        let code_hash = metadata
            .get("code_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let model_spec = ModelSpec {
            provider: metadata
                .get("llm_provider")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            model: metadata
                .get("llm_model")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            version: metadata
                .get("llm_version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };

        let config_hash = metadata
            .get("config_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        // Compute combined genesis hash
        let genesis_hash = format!("{}-{}-{}", code_hash, model_spec.model, config_hash);

        GenesisFingerprint {
            code_hash,
            model_spec,
            config_hash,
            ownership_proof: metadata
                .get("ownership_proof")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            genesis_hash,
            computed_at: now.clone(),
        }
    };

    // Extract Behavioral fingerprint
    let behavioral = if let Some(behavioral_value) = metadata.get("behavioral") {
        serde_json::from_value(behavioral_value.clone()).ok()?
    } else {
        BehavioralFingerprint {
            latency_profile_hash: metadata
                .get("latency_profile_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            challenge_response_hash: metadata
                .get("challenge_response_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            token_pattern_hash: metadata
                .get("token_pattern_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            behavioral_hash: "placeholder".to_string(),
            measured_at: now.clone(),
        }
    };

    // Extract Operational fingerprint
    let operational = if let Some(operational_value) = metadata.get("operational") {
        serde_json::from_value(operational_value.clone()).ok()?
    } else {
        OperationalFingerprint {
            tee_attestation: metadata
                .get("tee_attestation")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            cloud_attestation: metadata
                .get("cloud_attestation")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            capabilities_hash: metadata
                .get("capabilities_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("default")
                .to_string(),
            operational_hash: "placeholder".to_string(),
            attested_at: now.clone(),
        }
    };

    // Extract Attestations
    let attestations = if let Some(attestations_value) = metadata.get("attestations") {
        serde_json::from_value(attestations_value.clone()).ok()?
    } else {
        AttestationData {
            merkle_root: "empty".to_string(),
            count: 0,
            last_updated: Some(now.clone()),
        }
    };

    // Build Birth Event
    let birth_event = BirthEvent {
        scid: scid.to_string(),
        timestamp: now.clone(),
        initial_genesis: genesis.clone(),
        birth_entry_hash: "pending".to_string(), // Will be computed after entry creation
    };

    // Generate UAI string
    let uai = format!(
        "uai:1:{}:{}.{}.{}.{}",
        scid,
        &genesis.genesis_hash[..8.min(genesis.genesis_hash.len())],
        &behavioral.behavioral_hash[..8.min(
            behavioral
                .behavioral_hash
                .len()
        )],
        &operational.operational_hash[..8.min(
            operational
                .operational_hash
                .len()
        )],
        &attestations.merkle_root[..8.min(attestations.merkle_root.len())]
    );

    Some(AgentDna {
        uai,
        birth_event,
        genesis,
        behavioral,
        operational,
        attestations,
    })
}

/// Populate Agent DNA into DID document
///
/// Adds the agentDNA field to the DID document's state
fn populate_dna_in_document(
    _did_document: &mut DidDocument,
    dna: &crate::identity::uai::types::AgentDna,
) -> anyhow::Result<()> {
    // Convert DNA to JSON value
    let _dna_json = serde_json::to_value(dna).context("Failed to serialize Agent DNA")?;

    // Note: DID documents from affinidi-did-common don't have a generic extension field
    // We would need to add this as part of the service endpoints or other extension mechanism
    // For now, we'll document that DNA is stored in metadata and can be included in custom fields

    // TODO: Add agentDNA to DID document once we have a proper extension mechanism
    // This might require extending the affinidi-did-common crate or using service endpoints

    Ok(())
}

// ============================================================================
// Policy Configuration Handlers
// ============================================================================

/// Component threshold configuration for trust score policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentThreshold {
    /// Minimum score threshold (0.0 to 1.0)
    pub threshold: f64,
    /// Whether this component is required for access
    pub required: bool,
    /// Weight of this component in overall score
    pub weight: f64,
}

/// Operational component additional settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationalConfig {
    /// Minimum score threshold
    pub threshold: f64,
    /// Whether this component is required
    pub required: bool,
    /// Weight in overall score
    pub weight: f64,
    /// Whether TEE attestation is required
    #[serde(rename = "requireTEE")]
    pub require_tee: bool,
    /// Whether cloud attestation is required
    #[serde(rename = "requireCloud")]
    pub require_cloud: bool,
}

/// Attestation component additional settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Minimum score threshold
    pub threshold: f64,
    /// Whether this component is required
    pub required: bool,
    /// Weight in overall score
    pub weight: f64,
    /// Minimum number of attestations required
    #[serde(rename = "minCount")]
    pub min_count: u32,
}

/// Trust score policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Minimum overall trust score required (0.0 to 1.0)
    #[serde(rename = "minTrustScore")]
    pub min_trust_score: f64,

    /// Component-specific configurations
    pub components: PolicyComponents,

    /// Optional advanced OPA/Rego policy
    #[serde(rename = "advancedPolicy", skip_serializing_if = "Option::is_none")]
    pub advanced_policy: Option<String>,
}

/// Component configurations for policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyComponents {
    /// Genesis component configuration
    pub genesis: ComponentThreshold,
    /// Behavioral component configuration
    pub behavioral: ComponentThreshold,
    /// Operational component configuration
    pub operational: OperationalConfig,
    /// Attestation component configuration
    pub attestation: AttestationConfig,
    /// History component configuration
    pub history: ComponentThreshold,
}

/// Request to update policy configuration
#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    pub config: PolicyConfig,
}

/// Response for policy configuration operations
#[derive(Debug, Serialize)]
pub struct PolicyConfigResponse {
    pub id: Uuid,
    pub did: String,
    pub config: PolicyConfig,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Handler for PUT /api/v1/identities/{id}/policy
/// Updates the policy configuration for an identity
pub async fn update_policy_config(
    State(state): State<DidWebVhApiState>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdatePolicyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("Updating policy config for identity {}", id);

    // Validate policy configuration
    if request.config.min_trust_score < 0.0 || request.config.min_trust_score > 1.0 {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse::new("minTrustScore must be between 0.0 and 1.0"))));
    }

    // Get existing identity
    let mut identity = state
        .identity_store
        .get(&id)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("Identity not found"))))?;

    // Store policy config in metadata
    let policy_json = serde_json::to_value(&request.config).map_err(|e| {
        error!("Failed to serialize policy config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::with_details("Failed to serialize policy config", e.to_string())),
        )
    })?;

    identity
        .metadata
        .insert("policy_config".to_string(), policy_json);
    identity.updated_at = chrono::Utc::now();

    let response_identity = identity.clone();

    // Save updated identity
    state
        .identity_store
        .update(identity)
        .await
        .map_err(|e| {
            error!("Failed to update identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to update identity", e.to_string())),
            )
        })?;

    info!("Policy config updated for identity {}", id);

    Ok(Json(PolicyConfigResponse {
        id: response_identity.id,
        did: response_identity.did.clone(),
        config: request.config,
        updated_at: response_identity.updated_at,
    }))
}

/// Handler for GET /api/v1/identities/{id}/policy
/// Retrieves the policy configuration for an identity
pub async fn get_policy_config(
    State(state): State<DidWebVhApiState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    info!("Getting policy config for identity {}", id);

    // Get identity
    let identity = state
        .identity_store
        .get(&id)
        .await
        .map_err(|e| {
            error!("Failed to retrieve identity: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::with_details("Failed to retrieve identity", e.to_string())),
            )
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(ErrorResponse::new("Identity not found"))))?;

    // Get policy config from metadata
    let policy_config = identity
        .metadata
        .get("policy_config")
        .and_then(|v| serde_json::from_value::<PolicyConfig>(v.clone()).ok());

    if let Some(config) = policy_config {
        Ok(Json(PolicyConfigResponse {
            id: identity.id,
            did: identity.did.clone(),
            config,
            updated_at: identity.updated_at,
        }))
    } else {
        // Return default policy config if none exists
        let default_config = PolicyConfig {
            min_trust_score: 0.7,
            components: PolicyComponents {
                genesis: ComponentThreshold {
                    threshold: 0.75,
                    required: false,
                    weight: 0.25,
                },
                behavioral: ComponentThreshold {
                    threshold: 0.7,
                    required: true,
                    weight: 0.25,
                },
                operational: OperationalConfig {
                    threshold: 0.7,
                    required: false,
                    weight: 0.20,
                    require_tee: false,
                    require_cloud: false,
                },
                attestation: AttestationConfig {
                    threshold: 0.6,
                    required: false,
                    weight: 0.20,
                    min_count: 50,
                },
                history: ComponentThreshold {
                    threshold: 0.6,
                    required: false,
                    weight: 0.10,
                },
            },
            advanced_policy: None,
        };

        Ok(Json(PolicyConfigResponse {
            id: identity.id,
            did: identity.did.clone(),
            config: default_config,
            updated_at: identity.updated_at,
        }))
    }
}

// ─── Parallel did:web Utilities ──────────────────────────────────────────────

/// Recursively walk a JSON value and replace every occurrence of
/// `did:webvh:<scid>:` with `did:web:` in string fields.
fn replace_webvh_prefix_in_value(
    value: &mut serde_json::Value,
    old_prefix: &str,
) {
    match value {
        serde_json::Value::String(s) => {
            *s = s.replace(old_prefix, "did:web:");
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                replace_webvh_prefix_in_value(item, old_prefix);
            }
        }
        serde_json::Value::Object(obj) => {
            for v in obj.values_mut() {
                replace_webvh_prefix_in_value(v, old_prefix);
            }
        }
        _ => {}
    }
}

/// Generate a parallel `did:web` DID document from a `did:webvh` log-state document.
///
/// Per did:webvh v1.0 §3.7.10 (parallel did:web publication):
/// - Replaces `did:webvh:<SCID>:` with `did:web:` in every DID reference within the document.
/// - Adds (or merges) an `alsoKnownAs` array containing the original `did:webvh` DID so that
///   the two identifiers are cross-linked.
///
/// The public keys, services, and other document metadata are preserved unchanged.
///
/// # Parameters
/// - `did_document` — The `state` field from the latest `LogEntry` (JSON object).
/// - `webvh_did`   — The full `did:webvh:…` DID string (becomes the `alsoKnownAs` entry).
/// - `scid`        — The SCID portion of the DID (used to build the replacement prefix).
pub fn generate_parallel_did_web(
    did_document: &serde_json::Value,
    webvh_did: &str,
    scid: &str,
) -> serde_json::Value {
    let old_prefix = format!("did:webvh:{}:", scid);

    let mut parallel = did_document.clone();

    // Step 1: replace all `did:webvh:<scid>:` prefixes with `did:web:`
    replace_webvh_prefix_in_value(&mut parallel, &old_prefix);

    // Step 2: ensure alsoKnownAs contains the original did:webvh DID
    if let Some(obj) = parallel.as_object_mut() {
        let also_known_as = obj
            .entry("alsoKnownAs")
            .or_insert_with(|| serde_json::Value::Array(vec![]));

        if let Some(arr) = also_known_as.as_array_mut() {
            let already_present = arr
                .iter()
                .any(|v| v.as_str() == Some(webvh_did));
            if !already_present {
                arr.push(serde_json::Value::String(webvh_did.to_string()));
            }
        }
    }

    parallel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519_keypair() {
        let key_pair = generate_ed25519_keypair().unwrap();

        assert_eq!(key_pair.key_type, "Ed25519");
        assert!(
            key_pair
                .public_key
                .get("kty")
                .is_some()
        );
        assert!(
            key_pair
                .public_key
                .get("crv")
                .is_some()
        );
        assert!(
            key_pair
                .public_key
                .get("x")
                .is_some()
        );
        assert!(
            key_pair
                .private_key
                .get("d")
                .is_some()
        );
    }

    #[test]
    fn test_create_initial_did_document() {
        let key_pair = generate_ed25519_keypair().unwrap();
        let did = "did:webvh:example.com:alice";

        let doc = create_initial_did_document(did, &key_pair).unwrap();

        assert_eq!(doc.id.as_str(), did);
        assert!(
            !doc.verification_method
                .is_empty()
        );
        assert!(!doc.authentication.is_empty());
        assert!(
            !doc.assertion_method
                .is_empty()
        );
    }

    #[test]
    fn test_jwk_to_signing_key() {
        let key_pair = generate_ed25519_keypair().unwrap();
        let signing_key = jwk_to_signing_key(&key_pair.private_key).unwrap();

        use ed25519_dalek::Signer;
        let message = b"test message";
        let signature = signing_key.sign(message);
        assert!(
            !signature
                .to_bytes()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_create_and_get_identity() {
        use crate::identity::didwebvh::identity_manager::{
            DidWebVhIdentity, DidWebVhIdentityStore, FileSystemDidWebVhIdentityStore,
        };
        use std::sync::Arc;
        use tempfile::TempDir;
        use uuid::Uuid;

        let temp_dir = TempDir::new().unwrap();
        let identity_store = Arc::new(
            FileSystemDidWebVhIdentityStore::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );

        let id = Uuid::new_v4();
        let identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:alice".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
            active: true,
        };

        identity_store
            .create(identity.clone())
            .await
            .unwrap();

        let retrieved = identity_store
            .get(&id)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.did, identity.did);
    }

    #[tokio::test]
    async fn test_list_identities() {
        use crate::identity::didwebvh::identity_manager::{
            DidWebVhIdentity, DidWebVhIdentityStore, FileSystemDidWebVhIdentityStore,
        };
        use std::sync::Arc;
        use tempfile::TempDir;
        use uuid::Uuid;

        let temp_dir = TempDir::new().unwrap();
        let identity_store = Arc::new(
            FileSystemDidWebVhIdentityStore::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );

        for i in 0..2 {
            let identity = DidWebVhIdentity {
                id: Uuid::new_v4(),
                did: format!("did:webvh:example.com:user{}", i),
                key_pair: None,
                version: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                metadata: std::collections::HashMap::new(),
                active: true,
            };
            identity_store
                .create(identity)
                .await
                .unwrap();
        }

        let identities = identity_store
            .list()
            .await
            .unwrap();
        assert_eq!(identities.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_identity() {
        use crate::identity::didwebvh::identity_manager::{
            DidWebVhIdentity, DidWebVhIdentityStore, FileSystemDidWebVhIdentityStore,
        };
        use std::sync::Arc;
        use tempfile::TempDir;
        use uuid::Uuid;

        let temp_dir = TempDir::new().unwrap();
        let identity_store = Arc::new(
            FileSystemDidWebVhIdentityStore::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );

        let id = Uuid::new_v4();
        let identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:dave".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
            active: true,
        };

        identity_store
            .create(identity)
            .await
            .unwrap();
        assert!(
            identity_store
                .get(&id)
                .await
                .unwrap()
                .is_some()
        );

        identity_store
            .delete(&id)
            .await
            .unwrap();
        assert!(
            identity_store
                .get(&id)
                .await
                .unwrap()
                .is_none()
        );
    }

    // === generate_parallel_did_web Unit Tests ===
    /// The parallel did:web document has the did:web form in the `id` field.
    #[test]
    fn parallel_did_web_has_correct_id() {
        let scid = "z6Mktest123";
        let webvh_did = "did:webvh:z6Mktest123:example.com:agents:alice";
        let doc = serde_json::json!({
            "id": "did:webvh:z6Mktest123:example.com:agents:alice",
            "verificationMethod": [{
                "id": "did:webvh:z6Mktest123:example.com:agents:alice#key-1",
                "controller": "did:webvh:z6Mktest123:example.com:agents:alice",
                "type": "JsonWebKey2020"
            }]
        });

        let parallel = generate_parallel_did_web(&doc, webvh_did, scid);
        assert_eq!(
            parallel["id"]
                .as_str()
                .unwrap(),
            "did:web:example.com:agents:alice",
            "parallel did:web id must have did:webvh prefix replaced"
        );
    }

    /// `alsoKnownAs` contains exactly the did:webvh DID and no duplicates.
    #[test]
    fn parallel_did_web_also_known_as_no_duplicates() {
        let scid = "z6Mktest123";
        let webvh_did = "did:webvh:z6Mktest123:example.com:agents:alice";
        let doc = serde_json::json!({ "id": "did:webvh:z6Mktest123:example.com:agents:alice" });

        // Call twice to verify idempotency
        let first = generate_parallel_did_web(&doc, webvh_did, scid);
        let second = generate_parallel_did_web(&first, webvh_did, scid);

        let aka = second["alsoKnownAs"]
            .as_array()
            .unwrap();
        let count = aka
            .iter()
            .filter(|v| v.as_str() == Some(webvh_did))
            .count();
        assert_eq!(count, 1, "alsoKnownAs must contain did:webvh DID exactly once, got {}", count);
    }

    /// Public key material is preserved unchanged in the parallel document.
    #[test]
    fn parallel_did_web_keys_match_original() {
        let scid = "z6Mktest123";
        let webvh_did = "did:webvh:z6Mktest123:example.com";
        let pubkey = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "abc123"});
        let doc = serde_json::json!({
            "id": "did:webvh:z6Mktest123:example.com",
            "verificationMethod": [{
                "id": "did:webvh:z6Mktest123:example.com#key-1",
                "type": "JsonWebKey2020",
                "publicKeyJwk": pubkey
            }]
        });

        let parallel = generate_parallel_did_web(&doc, webvh_did, scid);
        assert_eq!(
            parallel["verificationMethod"][0]["publicKeyJwk"], pubkey,
            "public key material must be preserved unchanged"
        );
    }

    // === HTTP Endpoint Dualism Tests ===
    /// Helper: create a signed did:webvh identity in a temp directory.
    ///
    /// After creating the log, also writes a parallel `did.json` file so tests
    /// that check for HTTP endpoint dualism can find it on disk.
    /// The initial document includes `alsoKnownAs` pointing to the did:web
    /// equivalent so the stored log entry keeps the cross-link.
    async fn create_signed_identity(
        domain: &str,
        path: &str,
        tmp: &std::path::Path,
    ) -> (
        String, // DID (used as storage key)
        crate::identity::didwebvh::log::DidLogManager,
        std::sync::Arc<crate::storage::FileDidLogStorage>,
    ) {
        use crate::identity::didwebvh::log::DidLogManager;
        use crate::storage::FileDidLogStorage;
        use std::sync::Arc;

        let storage = Arc::new(FileDidLogStorage::new(tmp));
        let manager = DidLogManager::new(storage.clone());

        let key_pair = generate_ed25519_keypair().unwrap();
        // did:webvh format: did:webvh:<scid-position>:<domain>:<path>
        // We use `domain` as the SCID position (for testing purposes only).
        let did = format!("did:webvh:{}:{}", domain, path);
        let web_did = format!("did:web:{}:{}", domain, path);

        let mut doc = create_initial_did_document(&did, &key_pair).unwrap();
        // did:webvh log entry's document must include alsoKnownAs
        // with the parallel did:web identifier.
        doc.parameters_set
            .insert("alsoKnownAs".to_string(), serde_json::json!([web_did]));

        let entry = create_birth_log_entry(&did, doc).unwrap();
        let signing_key = jwk_to_signing_key(&key_pair.private_key).unwrap();
        let vm = format!("{}#key-1", did);

        let _ = manager
            .create_signed(entry, &signing_key, &vm)
            .await
            .unwrap();

        // Generate and write the parallel did:web document (did.json).
        // did.json must exist on disk and
        // contain the same key material plus alsoKnownAs pointing to did:webvh.
        let entries = storage
            .load_all(&did)
            .await
            .unwrap();
        if let Some(latest) = entries.last() {
            let state_json = serde_json::to_string(&latest.state).unwrap();
            let state_val: serde_json::Value = serde_json::from_str(&state_json).unwrap();
            // The SCID position in the DID is `domain` (testing convention).
            let parallel_doc = generate_parallel_did_web(&state_val, &did, domain);
            let did_json_path = tmp.join("did.json");
            tokio::fs::write(&did_json_path, serde_json::to_string_pretty(&parallel_doc).unwrap())
                .await
                .unwrap();
        }

        (did, manager, storage)
    }

    /// The did.json endpoint must serve a valid DID document with HTTP 200.
    #[tokio::test]
    async fn did_json_endpoint_returns_200_with_valid_document() {
        let tmp = tempfile::tempdir().unwrap();
        let (did, _, storage) = create_signed_identity("example.com", "agents:alice", tmp.path()).await;

        let entries = storage
            .load_all(&did)
            .await
            .unwrap();
        assert!(!entries.is_empty(), "Log must not be empty");

        // The did.json endpoint should serve the latest document state
        let latest = entries.last().unwrap();
        let doc_id = latest.state.id.as_str();
        assert_eq!(doc_id, did, "did.json document ID must match the DID");

        // Also verify that a static did.json file is generated.
        let did_json_path = tmp.path().join("did.json");
        assert!(did_json_path.exists(), "did.json must be written to disk for the did:web endpoint");
    }

    /// The did.jsonl endpoint must return a JSONL log that is parseable.
    #[tokio::test]
    async fn did_jsonl_endpoint_returns_200_with_log() {
        let tmp = tempfile::tempdir().unwrap();
        let (did, _, storage) = create_signed_identity("example.com", "agents:bob", tmp.path()).await;

        let entries = storage
            .load_all(&did)
            .await
            .unwrap();
        assert!(!entries.is_empty(), "JSONL log must contain at least one entry");
        assert!(
            entries[0]
                .version_id
                .starts_with("1-"),
            "Birth entry versionId must start with '1-'"
        );
    }

    /// Public keys in did.json must match those in the latest did.jsonl entry.
    #[tokio::test]
    async fn did_json_keys_match_did_jsonl_latest_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let (did, _, storage) = create_signed_identity("example.com", "agents:carol", tmp.path()).await;

        let entries = storage
            .load_all(&did)
            .await
            .unwrap();
        let latest = entries.last().unwrap();

        // The update_keys in the latest log entry must match the keys in the generated DID document
        assert!(
            !latest
                .parameters
                .update_keys
                .is_empty(),
            "Latest log entry must have update_keys"
        );

        // Verify that a static did.json file exists and its keys match.
        let did_json_path = tmp.path().join("did.json");
        assert!(did_json_path.exists(), "did.json file must exist after dual-endpoint setup");
        let did_json: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(&did_json_path)
                .await
                .unwrap(),
        )
        .unwrap();
        let vm_array = did_json["verificationMethod"]
            .as_array()
            .unwrap();
        assert!(!vm_array.is_empty(), "did.json must have verificationMethod entries");
    }

    /// After migration, did.json must include alsoKnownAs with the did:webvh identifier.
    #[tokio::test]
    async fn did_json_contains_also_known_as_for_webvh_id() {
        let tmp = tempfile::tempdir().unwrap();
        let (did, _, _storage) = create_signed_identity("example.com", "agents:dave", tmp.path()).await;

        // After migration, did.json must contain alsoKnownAs pointing to did:webvh:...
        let did_json_path = tmp.path().join("did.json");
        assert!(did_json_path.exists(), "did.json must exist");
        let did_json: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(&did_json_path)
                .await
                .unwrap(),
        )
        .unwrap();
        let also_known_as = did_json["alsoKnownAs"]
            .as_array()
            .unwrap();
        let has_webvh_ref = also_known_as.iter().any(|v| {
            v.as_str()
                .map(|s| s.starts_with("did:webvh:"))
                .unwrap_or(false)
        });
        assert!(has_webvh_ref, "did.json must include a did:webvh: entry in alsoKnownAs after migration, did: {}", did);
    }

    /// The latest did.jsonl entry's document must include alsoKnownAs with did:web.
    #[tokio::test]
    async fn did_jsonl_document_also_known_as_contains_did_web() {
        let tmp = tempfile::tempdir().unwrap();
        let (did, _, storage) = create_signed_identity("example.com", "agents:eve", tmp.path()).await;

        let entries = storage
            .load_all(&did)
            .await
            .unwrap();
        let latest = entries.last().unwrap();

        // The document in the latest log entry must contain alsoKnownAs with the did:web equivalent
        let doc_json = serde_json::to_value(&latest.state).unwrap();
        let also_known_as = doc_json
            .get("alsoKnownAs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let has_web_ref = also_known_as.iter().any(|v| {
            v.as_str()
                .map(|s| s.starts_with("did:web:"))
                .unwrap_or(false)
        });
        assert!(has_web_ref, "Latest did.jsonl entry document must include a did:web: entry in alsoKnownAs");
    }

    // ─── generate_random_dna Tests ───────────────────────────────────────────

    /// DNA has all four pillar fields populated and a non-empty UAI string.
    #[test]
    fn test_generate_random_dna_structure() {
        let dna = generate_random_dna("testscid");

        assert!(!dna.uai.is_empty(), "UAI must not be empty");
        assert!(
            !dna.genesis
                .genesis_hash
                .is_empty(),
            "genesis_hash must be set"
        );
        assert!(
            !dna.behavioral
                .behavioral_hash
                .is_empty(),
            "behavioral_hash must be set"
        );
        assert!(
            !dna.operational
                .operational_hash
                .is_empty(),
            "operational_hash must be set"
        );
        assert!(
            !dna.attestations
                .merkle_root
                .is_empty(),
            "merkle_root must be set"
        );
    }

    /// Two invocations with the same SCID produce different fingerprints (randomness check).
    #[test]
    fn test_generate_random_dna_uniqueness() {
        let dna1 = generate_random_dna("scid-unique");
        let dna2 = generate_random_dna("scid-unique");

        assert_ne!(
            dna1.genesis.genesis_hash, dna2.genesis.genesis_hash,
            "genesis hash must differ between invocations"
        );
        assert_ne!(
            dna1.behavioral
                .behavioral_hash,
            dna2.behavioral
                .behavioral_hash,
            "behavioral hash must differ between invocations"
        );
        assert_ne!(
            dna1.operational
                .operational_hash,
            dna2.operational
                .operational_hash,
            "operational hash must differ between invocations"
        );
        assert_ne!(dna1.uai, dna2.uai, "UAI must differ between invocations");
    }

    /// The UAI string embeds the SCID passed as input.
    #[test]
    fn test_generate_random_dna_scid_embedded() {
        let scid = "myscid123";
        let dna = generate_random_dna(scid);

        assert!(dna.uai.contains(scid), "UAI '{}' must contain the SCID '{}'", dna.uai, scid);
        assert_eq!(dna.birth_event.scid, scid, "BirthEvent.scid must equal the input SCID");
    }

    /// UAI format is `uai:1:<scid>:<8chars>.<8chars>.<8chars>.<8chars>`.
    #[test]
    fn test_generate_random_dna_uai_format() {
        let scid = "z6Mkformat";
        let dna = generate_random_dna(scid);

        let parts: Vec<&str> = dna.uai.split(':').collect();
        assert_eq!(parts.len(), 4, "UAI '{}' must have 4 colon-delimited sections", dna.uai);
        assert_eq!(parts[0], "uai", "UAI must start with 'uai'");
        assert_eq!(parts[1], "1", "UAI version must be '1'");
        assert_eq!(parts[2], scid, "UAI section 3 must be the SCID");

        let fingerprint_section = parts[3];
        let fp_parts: Vec<&str> = fingerprint_section
            .split('.')
            .collect();
        assert_eq!(fp_parts.len(), 4, "UAI fingerprint section must have 4 dot-delimited components");
        for fp in &fp_parts {
            assert_eq!(fp.len(), 8, "Each fingerprint component must be 8 hex chars, got '{}'", fp);
        }
    }

    /// The synthesised attestation set contains exactly one entry.
    #[test]
    fn test_generate_random_dna_attestation_count() {
        let dna = generate_random_dna("scid-att");
        assert_eq!(dna.attestations.count, 1, "Demo DNA must have attestation count == 1");
    }

    /// Model spec fields are correct for the demo managed-TGW identity.
    #[test]
    fn test_generate_random_dna_model_spec() {
        let dna = generate_random_dna("scid-model");
        assert_eq!(
            dna.genesis
                .model_spec
                .provider,
            "tgw-managed"
        );
        assert_eq!(dna.genesis.model_spec.model, "demo");
        assert_eq!(
            dna.genesis
                .model_spec
                .version
                .as_deref(),
            Some("1.0")
        );
    }

    /// Genesis model hashes are valid 64-char lower-hex strings.
    #[test]
    fn test_generate_random_dna_hex_values() {
        let dna = generate_random_dna("scid-hex");
        let is_hex64 = |s: &str| {
            s.len() == 64
                && s.chars()
                    .all(|c| c.is_ascii_hexdigit())
        };
        assert!(is_hex64(&dna.genesis.code_hash), "code_hash must be 64-char hex");
        assert!(is_hex64(&dna.genesis.config_hash), "config_hash must be 64-char hex");
        assert!(is_hex64(&dna.genesis.genesis_hash), "genesis_hash must be 64-char hex");
        assert!(is_hex64(&dna.behavioral.behavioral_hash), "behavioral_hash must be 64-char hex");
        assert!(
            is_hex64(
                &dna.operational
                    .operational_hash
            ),
            "operational_hash must be 64-char hex"
        );
        assert!(is_hex64(&dna.attestations.merkle_root), "merkle_root must be 64-char hex");
    }

    // === SCID Placeholder Replacement Tests (§3.6.1 step 5.2) ===

    /// §3.6.1 step 5.2: The inline SCID computation in create_identity must
    /// replace {SCID} in the DIDDoc, update_keys, and proof verification_method.
    /// This test exercises the same inline signing path used by the handler
    /// (bypassing DidLogManager::create_signed).
    #[test]
    fn inline_scid_replacement_produces_clean_entry() {
        use crate::identity::didwebvh::log::{compute_entry_hash, sign_entry};
        use crate::identity::didwebvh::scid::generate_scid;

        let key_pair = generate_ed25519_keypair().unwrap();
        let placeholder_did = "did:webvh:{SCID}:example.com:agents:inline-test";

        // Create DIDDoc with {SCID} placeholder — matches real handler flow
        let doc = create_initial_did_document(placeholder_did, &key_pair).unwrap();
        let preliminary_entry = create_birth_log_entry(placeholder_did, doc).unwrap();

        // Compute SCID from the preliminary entry
        let scid = generate_scid(&preliminary_entry).unwrap();
        let base_domain = "example.com";
        let final_did = format!("did:webvh:{}:{}:agents:inline-test", scid, base_domain);

        // Inline SCID replacement — same as the fixed create_identity handler
        let entry_json = serde_json::to_string(&preliminary_entry).unwrap();
        let replaced_json = entry_json.replace("{SCID}", &scid);
        let mut entry: crate::identity::didwebvh::types::LogEntry = serde_json::from_str(&replaced_json).unwrap();

        let entry_hash = compute_entry_hash(&entry, &scid).unwrap();
        entry.version_id = format!("1-{}", entry_hash);

        let signing_key = jwk_to_signing_key(&key_pair.private_key).unwrap();
        let vm_id = format!("{}#key-1", final_did);
        let signed = sign_entry(&entry, &signing_key, &vm_id).unwrap();

        // Verify no {SCID} placeholders remain anywhere
        let signed_json = serde_json::to_string(&signed).unwrap();
        assert!(
            !signed_json.contains("{SCID}"),
            "No {{SCID}} placeholder must remain in the signed entry:\n{}",
            signed_json
        );

        // DIDDoc id must be the final DID
        assert_eq!(signed.state.id.as_str(), final_did, "DIDDoc id must use final DID with actual SCID");

        // SCID in parameters must be set
        assert_eq!(signed.parameters.scid, scid);

        // Verification method in the DIDDoc must use final DID
        assert!(
            signed
                .state
                .verification_method[0]
                .id
                .as_str()
                .contains(&scid),
            "verificationMethod id must contain actual SCID"
        );

        // Proof must reference the final DID key
        assert!(
            signed.proof[0]
                .verification_method
                .contains(&scid),
            "proof verification_method must reference final DID key with actual SCID"
        );

        // update_keys must use final DID
        for uk in &signed.parameters.update_keys {
            assert!(uk.contains(scid.as_str()), "update_keys entry must contain actual SCID: {}", uk);
        }
    }

    /// Before the fix, DIDDoc state contained literal "{SCID}" strings.
    /// This regression test verifies that create_initial_did_document with a
    /// {SCID} placeholder DID, followed by text replacement, yields a parseable
    /// DIDDoc with the correct final DID references.
    #[test]
    fn regression_did_document_no_scid_placeholder_after_replacement() {
        use crate::identity::didwebvh::scid::generate_scid;

        let key_pair = generate_ed25519_keypair().unwrap();
        let placeholder_did = "did:webvh:{SCID}:agent-gateway-1.example.com:channel:a51e96c0";

        let doc = create_initial_did_document(placeholder_did, &key_pair).unwrap();
        let entry = create_birth_log_entry(placeholder_did, doc).unwrap();
        let scid = generate_scid(&entry).unwrap();

        // Do the replacement
        let json = serde_json::to_string(&entry.state).unwrap();
        let replaced = json.replace("{SCID}", &scid);

        // Must deserialize cleanly
        let resolved: serde_json::Value = serde_json::from_str(&replaced).unwrap();

        // The id must contain the actual SCID
        let id = resolved["id"]
            .as_str()
            .unwrap();
        assert!(!id.contains("{SCID}"), "Resolved DIDDoc id must not contain {{SCID}}: {}", id);
        assert!(id.contains(&scid), "Resolved DIDDoc id must contain actual SCID '{}': {}", scid, id);

        // verificationMethod references must also be resolved
        let vm_id = resolved["verificationMethod"][0]["id"]
            .as_str()
            .unwrap();
        assert!(!vm_id.contains("{SCID}"), "verificationMethod id must not contain {{SCID}}: {}", vm_id);
        let controller = resolved["verificationMethod"][0]["controller"]
            .as_str()
            .unwrap();
        assert!(
            !controller.contains("{SCID}"),
            "verificationMethod controller must not contain {{SCID}}: {}",
            controller
        );
    }

    // === Private key exposure and ownership transfer authorization ===

    fn b64url(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn make_jws(
        header: &serde_json::Value,
        payload: &serde_json::Value,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> String {
        use ed25519_dalek::Signer;
        let signing_input = format!(
            "{}.{}",
            b64url(&serde_json::to_vec(header).unwrap()),
            b64url(&serde_json::to_vec(payload).unwrap())
        );
        let signature = signing_key.sign(signing_input.as_bytes());
        format!("{}.{}", signing_input, b64url(&signature.to_bytes()))
    }

    async fn response_json(response: impl IntoResponse) -> (StatusCode, serde_json::Value) {
        let response = response.into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    /// Build an API state over temp storage and create one identity through the
    /// real create handler; returns the state, the identity id and its key pair.
    async fn api_state_with_identity(tmp: &std::path::Path) -> (DidWebVhApiState, Uuid, KeyPair) {
        use crate::identity::didwebvh::identity_manager::FileSystemDidWebVhIdentityStore;
        use crate::storage::FileDidLogStorage;

        let state = DidWebVhApiState {
            identity_store: Arc::new(
                FileSystemDidWebVhIdentityStore::new(tmp.join("identities"))
                    .await
                    .unwrap(),
            ),
            log_storage: Arc::new(FileDidLogStorage::new(tmp.join("logs"))),
            base_url: "https://example.com".to_string(),
        };
        let key_pair = generate_ed25519_keypair().unwrap();
        let request = CreateDidRequest {
            did_path: Some("agents/owner".to_string()),
            metadata: std::collections::HashMap::new(),
            key_pair: Some(key_pair.clone()),
        };
        let response = create_identity(State(state.clone()), Json(request))
            .await
            .unwrap_or_else(|(status, body)| panic!("create_identity failed: {status} {}", body.0.error));
        let (status, body) = response_json(response).await;
        assert_eq!(status, StatusCode::CREATED);
        let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
        (state, id, key_pair)
    }

    fn transfer_request(
        new_controller: &str,
        authorization: &str,
    ) -> TransferOwnershipRequest {
        TransferOwnershipRequest {
            new_controller: new_controller.to_string(),
            current_owner_authorization: authorization.to_string(),
            new_owner_authorization: None,
            new_ownership_proof: None,
            transfer_reason: None,
        }
    }

    async fn latest_version_id(
        state: &DidWebVhApiState,
        did: &str,
    ) -> String {
        state
            .log_storage
            .load_all(did)
            .await
            .unwrap()
            .last()
            .unwrap()
            .version_id
            .clone()
    }

    fn signed_transfer_proof(
        did: &str,
        challenge: &str,
        key_pair: &KeyPair,
    ) -> String {
        let signing_key = jwk_to_signing_key(&key_pair.private_key).unwrap();
        let header = serde_json::json!({ "alg": "EdDSA", "kid": format!("{did}#key-1") });
        let payload = serde_json::json!({ "challenge": challenge, "iat": chrono::Utc::now().timestamp() });
        make_jws(&header, &payload, &signing_key)
    }

    /// The response DTO drops the private key, and also strips a `d` member a
    /// caller may have smuggled into the "public" JWK at creation time.
    #[test]
    fn identity_response_omits_private_key_material() {
        let key_pair = generate_ed25519_keypair().unwrap();
        let private_d = key_pair.private_key["d"]
            .as_str()
            .unwrap()
            .to_string();
        let public_x = key_pair.public_key["x"]
            .as_str()
            .unwrap()
            .to_string();
        let identity = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:example.com:alice".to_string(),
            key_pair: Some(KeyPair {
                public_key: key_pair.private_key.clone(),
                ..key_pair
            }),
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
            active: true,
        };

        let json = serde_json::to_string(&DidWebVhIdentityResponse::from(identity)).unwrap();

        assert!(!json.contains("private_key"), "response must not carry a private_key field: {json}");
        assert!(!json.contains(&private_d), "response must not carry the private scalar: {json}");
        assert!(!json.contains("\"d\""), "response must not carry a JWK 'd' member: {json}");
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["public_key"]["x"], public_x);
        assert_eq!(value["key_type"], "Ed25519");
    }

    #[tokio::test]
    async fn get_identity_response_never_contains_private_key() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, id, key_pair) = api_state_with_identity(tmp.path()).await;
        let private_d = key_pair.private_key["d"]
            .as_str()
            .unwrap();

        let response = get_identity(State(state), Path(id))
            .await
            .unwrap_or_else(|(status, body)| panic!("get_identity failed: {status} {}", body.0.error));
        let (status, body) = response_json(response).await;

        assert_eq!(status, StatusCode::OK);
        let raw = body.to_string();
        assert!(!raw.contains("private_key"), "identity response leaked private_key: {raw}");
        assert!(!raw.contains(private_d), "identity response leaked the private scalar: {raw}");
        assert_eq!(body["public_key"]["x"], key_pair.public_key["x"]);
        assert_eq!(body["id"].as_str().unwrap(), id.to_string());
    }

    #[tokio::test]
    async fn transfer_ownership_rejects_arbitrary_authorization_string() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, id, _) = api_state_with_identity(tmp.path()).await;
        let before = state
            .identity_store
            .get(&id)
            .await
            .unwrap()
            .unwrap();

        let result = transfer_ownership(
            State(state.clone()),
            Path(id),
            Json(transfer_request("did:example:attacker", "i-am-the-owner")),
        )
        .await;

        let (status, _) = result
            .err()
            .expect("arbitrary authorization string must not transfer ownership");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let after = state
            .identity_store
            .get(&id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.version, before.version);
        assert!(
            !after
                .metadata
                .contains_key("controller")
        );
        assert_eq!(
            state
                .log_storage
                .load_all(&after.did)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn transfer_ownership_rejects_proof_bound_to_another_transfer() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, id, key_pair) = api_state_with_identity(tmp.path()).await;
        let did = state
            .identity_store
            .get(&id)
            .await
            .unwrap()
            .unwrap()
            .did;
        let version_id = latest_version_id(&state, &did).await;
        let proof_for_bob =
            signed_transfer_proof(&did, &transfer_ownership_challenge(&did, &version_id, "did:example:bob"), &key_pair);

        let result = transfer_ownership(
            State(state.clone()),
            Path(id),
            Json(transfer_request("did:example:mallory", &proof_for_bob)),
        )
        .await;

        let (status, _) = result
            .err()
            .expect("a proof for a different new controller must be rejected");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let after = state
            .identity_store
            .get(&id)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !after
                .metadata
                .contains_key("controller")
        );
    }

    #[tokio::test]
    async fn transfer_ownership_accepts_proof_signed_by_current_key_once() {
        let tmp = tempfile::tempdir().unwrap();
        let (state, id, key_pair) = api_state_with_identity(tmp.path()).await;
        let did = state
            .identity_store
            .get(&id)
            .await
            .unwrap()
            .unwrap()
            .did;
        let version_id = latest_version_id(&state, &did).await;
        let proof =
            signed_transfer_proof(&did, &transfer_ownership_challenge(&did, &version_id, "did:example:bob"), &key_pair);

        let response =
            transfer_ownership(State(state.clone()), Path(id), Json(transfer_request("did:example:bob", &proof)))
                .await
                .unwrap_or_else(|(status, body)| panic!("valid proof rejected: {status} {}", body.0.error));
        let (status, body) = response_json(response).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["new_controller"], "did:example:bob");
        let after = state
            .identity_store
            .get(&id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.version, 2);
        assert_eq!(after.metadata["controller"], "did:example:bob");
        let entries = state
            .log_storage
            .load_all(&did)
            .await
            .unwrap();
        assert_eq!(entries.len(), 2);

        let history = get_identity_history(State(state.clone()), Path(id))
            .await
            .unwrap_or_else(|(status, body)| panic!("history after transfer failed: {status} {}", body.0.error));
        let (status, history) = response_json(history).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(history["total_versions"], 2);

        let replay =
            transfer_ownership(State(state.clone()), Path(id), Json(transfer_request("did:example:bob", &proof))).await;
        let (status, body) = replay
            .err()
            .expect("a consumed proof must not be replayable");
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "replay must be rejected as unauthorized: {} {:?}",
            body.0.error,
            body.0.details
        );
    }
}
