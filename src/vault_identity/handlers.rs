// Handlers for vault identity generation

use crate::identity::VCIssuer;
use affinidi_tdk_common::secrets_resolver::secrets::Secret;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};

/// Extract the domain segment from an issuer DID, decoding encoded localhost ports.
fn extract_domain_from_did(issuer_did: &str) -> String {
    crate::identity::utils::extract_domain_from_did(issuer_did)
}

/// Generate a new did:webvh identity with a birth log entry.
/// Returns the DID and the identity record — caller is responsible for storing the record.
/// Persists a `did.jsonl` birth log to `{identities_base}/{uuid}/did.jsonl` when the
/// identity store reports a filesystem base path.
#[cfg(feature = "didwebvh")]
pub async fn generate_did_webvh_identity(
    vc_issuer: &crate::identity::VCIssuer,
    path_segment: &str,
    purpose: Option<String>,
) -> anyhow::Result<(String, crate::identity::AgentIdentityRecord)> {
    use affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial;
    use didwebvh_rs::prelude::{CreateDIDConfig, Parameters, create_did};

    let issuer_did = vc_issuer
        .get_issuer_did()
        .await?;
    let domain = extract_domain_from_did(&issuer_did);
    let safe_domain = domain.replace(':', "%3A");

    let identity_id = uuid::Uuid::new_v4().to_string();
    let placeholder_did = format!("did:webvh:{{SCID}}:{}:{}:{}", safe_domain, path_segment, identity_id);

    // --- 1. Generate key material ---
    let mut ed25519_secret = Secret::generate_ed25519(None, None);
    let mut x25519_secret =
        Secret::generate_x25519(None, None).map_err(|e| anyhow::anyhow!("Failed to generate X25519 key: {:?}", e))?;
    let mut p256_secret =
        Secret::generate_p256(None, None).map_err(|e| anyhow::anyhow!("Failed to generate P-256 key: {:?}", e))?;

    ed25519_secret.id = format!("{}#key-1", placeholder_did);
    x25519_secret.id = format!("{}#key-2", placeholder_did);
    p256_secret.id = format!("{}#key-3", placeholder_did);

    // --- 2. Extract Ed25519 JWK ---
    let ed25519_jwk_value = match &ed25519_secret.secret_material {
        SecretMaterial::JWK(jwk) => {
            serde_json::to_value(jwk).map_err(|e| anyhow::anyhow!("Failed to serialize JWK: {}", e))?
        }
        _ => return Err(anyhow::anyhow!("Ed25519 secret is not a JWK")),
    };
    let ed25519_pub_jwk = {
        let mut pub_jwk = ed25519_jwk_value.clone();
        if let Some(obj) = pub_jwk.as_object_mut() {
            obj.remove("d");
        }
        pub_jwk
    };

    // --- 3. Convert Ed25519 key to library Secret for multibase public key ---
    let temp_key_id = "did:key:temp#temp".to_string();
    let raw_secret = didwebvh_rs::prelude::Secret::from_str(&temp_key_id, &ed25519_jwk_value)
        .map_err(|e| anyhow::anyhow!("Failed to convert Ed25519 key to Secret: {}", e))?;
    let multibase_pubkey = raw_secret
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get multibase public key: {}", e))?;
    let did_key_id = format!("did:key:{0}#{0}", multibase_pubkey);
    let mut auth_secret = didwebvh_rs::prelude::Secret::from_str(&did_key_id, &ed25519_jwk_value)
        .map_err(|e| anyhow::anyhow!("Failed to build auth secret: {}", e))?;
    auth_secret.id = did_key_id;

    // --- 4. Build DID document JSON with {SCID} placeholder ---
    // Publish the Ed25519 key in BOTH formats: `#key-1` as JsonWebKey2020
    // (publicKeyJwk) and `#key-2` as Multikey (publicKeyMultibase). Agent VP/VC
    // proofs use the `eddsa-rdfc-2022` cryptosuite, whose verifier requires a
    // Multikey verification method — so `#key-2` must be present and referenced
    // by assertionMethod, mirroring `serve_agent_did_document`.
    let did_document_json = serde_json::json!({
        "id": placeholder_did,
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "verificationMethod": [
            {
                "id": format!("{}#key-1", placeholder_did),
                "type": "JsonWebKey2020",
                "controller": placeholder_did,
                "publicKeyJwk": ed25519_pub_jwk
            },
            {
                "id": format!("{}#key-2", placeholder_did),
                "type": "Multikey",
                "controller": placeholder_did,
                "publicKeyMultibase": multibase_pubkey.clone()
            }
        ],
        "authentication": [format!("{}#key-1", placeholder_did)],
        "assertionMethod": [
            format!("{}#key-1", placeholder_did),
            format!("{}#key-2", placeholder_did)
        ]
    });

    // --- 5. Build Parameters with multibase update_keys ---
    let parameters = Parameters {
        update_keys: Some(std::sync::Arc::new(vec![didwebvh_rs::Multibase::new(multibase_pubkey.clone())])),
        ..Default::default()
    };

    // --- 6. Call create_did() — library handles SCID, hash, signing ---
    let base_url = crate::identity::didwebvh::base_url_for_domain(&domain);
    let create_result = create_did(
        CreateDIDConfig::builder()
            .address(base_url)
            .authorization_key(auth_secret)
            .did_document(did_document_json)
            .parameters(parameters)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build CreateDIDConfig: {}", e))?,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create DID: {}", e))?;

    let final_did = create_result
        .did()
        .to_string();

    // --- 7. Bridge: serialize library LogEntry → gateway LogEntry ---
    let log_entry_json = serde_json::to_string(create_result.log_entry())
        .map_err(|e| anyhow::anyhow!("Failed to serialize log entry: {}", e))?;
    let _signed_entry: crate::identity::didwebvh::types::LogEntry =
        serde_json::from_str(&log_entry_json).map_err(|e| anyhow::anyhow!("Failed to deserialize log entry: {}", e))?;

    // --- 8. Persist birth log if the identity store has a filesystem base path ---
    if let Some(base_path) = vc_issuer
        .get_identity_store()
        .base_path()
    {
        let id_path = base_path.join(&identity_id);
        tokio::fs::create_dir_all(&id_path).await?;
        crate::storage::did_artifacts::write_did_log_raw(&id_path, &log_entry_json).await?;
    }

    // --- 9. Build the private key JWK for the record ---
    let private_key_jwk = match &ed25519_secret.secret_material {
        SecretMaterial::JWK(jwk) => serde_json::to_value(jwk).ok(),
        _ => None,
    };

    // Update secret IDs to reference the final DID
    ed25519_secret.id = format!("{}#key-1", final_did);
    x25519_secret.id = format!("{}#key-2", final_did);
    p256_secret.id = format!("{}#key-3", final_did);

    let record = crate::identity::AgentIdentityRecord {
        did: final_did.clone(),
        identity_hash: identity_id.clone(),
        created_at: chrono::Utc::now(),
        identity_fields: std::collections::HashMap::from([
            ("purpose".to_string(), json!(purpose.unwrap_or_else(|| path_segment.to_string()))),
            ("type".to_string(), json!(format!("{}_identity", path_segment))),
        ]),
        usage_count: 0,
        last_used_at: None,
        channel_usage: vec![],
        private_key: private_key_jwk,
        channel_config_id: None,
        is_local: true,
        verified: true,
        origin: None,
    };

    info!("[Identity Generation] Generated did:webvh identity: {}", final_did);
    Ok((final_did, record))
}

/// Request to generate a new did:web identity
#[derive(Debug, Deserialize)]
pub struct GenerateIdentityRequest {
    /// Optional purpose or description for the identity
    pub purpose: Option<String>,
    /// Type of vault item: "apikey" or "cert"
    pub item_type: Option<String>,
}

/// Response containing the generated DID
#[derive(Debug, Serialize)]
pub struct GenerateIdentityResponse {
    pub did: String,
}

/// Generate a new did:webvh identity for use with API keys or certificates
/// This creates a new DID with associated keys stored in the identity store
pub async fn generate_identity(
    State(vc_issuer): State<Arc<VCIssuer>>,
    Json(request): Json<GenerateIdentityRequest>,
) -> impl IntoResponse {
    info!("[Vault Identity] Generating new did:webvh identity");

    let path_segment = match request.item_type.as_deref() {
        Some("apikey") => "apikey",
        Some("cert") => "cert",
        _ => "vault",
    };

    #[cfg(feature = "didwebvh")]
    let identity_result = generate_did_webvh_identity(&vc_issuer, path_segment, request.purpose).await;
    #[cfg(not(feature = "didwebvh"))]
    let identity_result: anyhow::Result<(String, crate::identity::AgentIdentityRecord)> =
        Err(anyhow::anyhow!("didwebvh feature is required"));

    let (did, record) = match identity_result {
        Ok(result) => result,
        Err(e) => {
            error!("[Vault Identity] Failed to generate identity: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Failed to generate identity: {}", e)})),
            )
                .into_response();
        }
    };

    let identity_store = vc_issuer.get_identity_store();

    if let Err(e) = identity_store
        .create(record)
        .await
    {
        error!("[Vault Identity] Failed to store identity: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("Failed to store identity: {}", e)})))
            .into_response();
    }

    info!("[Vault Identity] Successfully created and stored identity: {}", did);

    (StatusCode::CREATED, Json(GenerateIdentityResponse { did })).into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::identity::{
        FilesystemIdentityStore, IdentityStore, VpChallengeStore, vc_issuer::VCIssuer,
        vp_challenge_store::FilesystemVpChallengeStore,
    };

    async fn make_issuer(base_dir: &std::path::Path) -> VCIssuer {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let id_store = Arc::new(
            FilesystemIdentityStore::new(base_dir.join("identity"))
                .await
                .unwrap(),
        ) as Arc<dyn IdentityStore>;
        let vp_store = Arc::new(
            FilesystemVpChallengeStore::new(base_dir.join("vp_challenges"))
                .await
                .unwrap(),
        ) as Arc<dyn VpChallengeStore>;
        VCIssuer::new(base_dir.join("issuer"), "proxy.example.com", id_store, vp_store, None, None)
            .await
            .unwrap()
    }

    // === Vault Identity Tests ===
    /// cert path segment must produce a DID containing ':cert:'.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn generate_identity_cert_format() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let (did, _) = super::generate_did_webvh_identity(&issuer, "cert", None)
            .await
            .unwrap();

        assert!(did.contains(":cert:"), "DID must contain ':cert:' segment, got: {}", did);
        assert!(did.starts_with("did:webvh:"), "DID must start with 'did:webvh:', got: {}", did);
    }

    /// The returned identity record must have is_local = true.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn identity_record_is_local_true() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let (_, record) = super::generate_did_webvh_identity(&issuer, "apikey", None)
            .await
            .unwrap();

        assert!(record.is_local, "Identity record must have is_local = true");
    }

    // === did:webvh Vault Identity Tests ===
    /// generate_did_webvh_identity must produce a did:webvh DID.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn generate_webvh_identity_produces_didwebvh_did() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let (did, _) = super::generate_did_webvh_identity(&issuer, "apikey", None)
            .await
            .unwrap();

        assert!(did.starts_with("did:webvh:"), "generate_did_webvh_identity must return did:webvh:..., got: {}", did);
    }

    /// Path segment must appear in the did:webvh DID.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn generate_webvh_identity_path_segment_in_did() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let (did, _) = super::generate_did_webvh_identity(&issuer, "apikey", None)
            .await
            .unwrap();

        assert!(did.contains(":apikey:"), "DID must contain ':apikey:' path segment, got: {}", did);
    }

    /// Same issuer, different calls → different DIDs (UUID-based, non-deterministic).
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn generate_webvh_identity_distinct_dids_per_call() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let (did1, _) = super::generate_did_webvh_identity(&issuer, "apikey", None)
            .await
            .unwrap();
        let (did2, _) = super::generate_did_webvh_identity(&issuer, "apikey", None)
            .await
            .unwrap();

        assert_ne!(did1, did2, "Two independent calls must produce distinct DIDs");
    }

    /// Record returned by generate_did_webvh_identity must have a private_key.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn generate_webvh_identity_record_has_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = make_issuer(dir.path()).await;

        let (_, record) = super::generate_did_webvh_identity(&issuer, "cert", None)
            .await
            .unwrap();

        assert!(record.private_key.is_some(), "Record must contain a private_key JWK");
    }

    /// did.jsonl birth log is written to {identities_base}/{uuid}/did.jsonl.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn generate_webvh_identity_writes_did_jsonl() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();

        // Build an issuer backed by a real FilesystemIdentityStore so base_path() returns Some.
        let id_store = Arc::new(
            FilesystemIdentityStore::new(dir.path().join("identity"))
                .await
                .unwrap(),
        ) as Arc<dyn IdentityStore>;
        let vp_store = Arc::new(
            FilesystemVpChallengeStore::new(
                dir.path()
                    .join("vp_challenges"),
            )
            .await
            .unwrap(),
        ) as Arc<dyn VpChallengeStore>;
        let issuer = VCIssuer::new(dir.path().join("issuer"), "example.com", id_store, vp_store, None, None)
            .await
            .unwrap();

        let (did, record) = super::generate_did_webvh_identity(&issuer, "apikey", None)
            .await
            .unwrap();

        // The UUID is the identity_hash field in the record.
        let uuid = &record.identity_hash;
        let jsonl_path = dir
            .path()
            .join("identity")
            .join(uuid)
            .join("did.jsonl");

        assert!(
            jsonl_path.exists(),
            "did.jsonl must be written to {{identities}}/{uuid}/did.jsonl, path: {}",
            jsonl_path.display()
        );

        let content = tokio::fs::read_to_string(&jsonl_path)
            .await
            .unwrap();
        assert!(!content.is_empty(), "did.jsonl must not be empty");

        // First line must be parseable JSON containing a valid log entry
        let first_line = content
            .lines()
            .next()
            .unwrap();
        let entry: serde_json::Value =
            serde_json::from_str(first_line).expect("First line of did.jsonl must be valid JSON");

        // Must have versionId with "1-" prefix (birth entry)
        let version_id = entry["versionId"]
            .as_str()
            .unwrap_or("");
        assert!(version_id.starts_with("1-"), "Birth entry versionId must start with '1-', got: {}", version_id);

        // state.id must reference the identity path segments (placeholder DID reference)
        let state_id = entry["state"]["id"]
            .as_str()
            .unwrap_or("");
        assert!(state_id.contains("apikey"), "state.id must contain the 'apikey' path segment, got: {}", state_id);
        let _ = did; // used for context
    }
}
