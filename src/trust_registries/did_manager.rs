//! Trust Registry Per-Registry DID Identity Manager
//!
//! Generates and manages a unique did:web, did:peer, or did:webvh identity per
//! trust registry connection. For did:webvh, identities are stored through the
//! shared DidWebVhIdentityStore and DidLogStorage (same as channel identities).
//! For did:web/did:peer, keys are stored on disk under {storage_path}/{id}/.

use affinidi_did_common::{DID, PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint};
use affinidi_tdk_common::secrets_resolver::secrets::Secret;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

#[cfg(feature = "didwebvh")]
const E_KEY_SECRET_ID_METADATA_KEY: &str = "e_key_secret_id";

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DidMethod {
    #[default]
    Web,
    Peer,
    #[cfg(feature = "didwebvh")]
    Webvh,
}

/// Generates a unique did:web identity for a trust registry connection.
///
/// Creates 2 key pairs matching the trust registry service's connection point format:
/// - P-256: Authentication/assertion (verification)
/// - secp256k1: Key agreement (DIDComm encryption)
///
/// # Arguments
/// * `trust_registry_id` - Unique ID of the trust registry
/// * `domain` - The gateway's domain (from NetworkConfig.did.domain)
/// * `storage_path` - Base storage path for trust registries
/// * `mediator_url` - Mediator URL (used for logging / diagnostics)
/// * `mediator_did` - Mediator DID, used as the DIDCommMessaging service
///   endpoint so the mediator recognises this DID as one of its own local
///   accounts (a URL endpoint is treated as a remote mediator and relayed).
///
/// # Returns
/// (did_string, Vec<Secret>, did_document)
pub async fn generate_trust_registry_identity(
    trust_registry_id: &str,
    domain: &str,
    storage_path: &std::path::Path,
    mediator_url: &str,
    mediator_did: &str,
    did_method: DidMethod,
    #[cfg(feature = "didwebvh")] identity_store: Option<
        std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>,
    >,
    #[cfg(feature = "didwebvh")] log_storage: Option<std::sync::Arc<dyn crate::storage::DidLogStorage>>,
) -> Result<(String, Vec<Secret>, serde_json::Value)> {
    // Create storage directory for this trust registry's keys
    let tr_keys_path = storage_path.join(trust_registry_id);
    tokio::fs::create_dir_all(&tr_keys_path).await?;

    // Generate key pairs — Ed25519 for verification, X25519 for key agreement (DIDComm)
    let mut v_key = Secret::generate_ed25519(None, None);
    let mut e_key =
        Secret::generate_x25519(None, None).map_err(|e| anyhow::anyhow!("Failed to generate X25519 key: {:?}", e))?;

    let (did, did_document) = match did_method {
        DidMethod::Web => {
            // Construct did:web DID (domain colons must be percent-encoded)
            let safe_domain = domain.replace(':', "%3A");
            let did = format!("did:web:{}:trust-registries:{}", safe_domain, trust_registry_id);

            info!("Generating trust registry did:web: {}", did);
            info!("  Service endpoint (mediator): {}", mediator_url);

            // Update secret IDs to reference the DID
            v_key.id = format!("{}#key-1", did);
            e_key.id = format!("{}#key-2", did);

            // Build DID document
            let did_document = build_did_web_document(&did, &[v_key.clone(), e_key.clone()], mediator_did)?;
            (did, did_document)
        }
        #[cfg(feature = "didwebvh")]
        DidMethod::Webvh => {
            info!("Generating trust registry did:webvh for: {}", trust_registry_id);
            info!("  Service endpoint (mediator): {}", mediator_url);

            use crate::identity::didwebvh::create::{create_webvh_did, strip_jwk_private_key};
            use crate::identity::didwebvh::identity_manager::DidWebVhIdentity;
            use crate::identity::didwebvh::{generate_ed25519_keypair, generate_random_dna};
            use base64::Engine;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;

            let identity_store =
                identity_store.ok_or_else(|| anyhow::anyhow!("DID:webvh identity store required for Webvh method"))?;
            let log_storage =
                log_storage.ok_or_else(|| anyhow::anyhow!("DID:webvh log storage required for Webvh method"))?;

            let safe_domain = domain.replace(':', "%3A");
            let did_path_str = format!("trust-registries:{}", trust_registry_id);
            let placeholder_did = format!("did:webvh:{{SCID}}:{}:{}", safe_domain, did_path_str);

            // --- 1. Generate Ed25519 key pair ---
            let key_pair = generate_ed25519_keypair()?;

            // --- 2. Generate X25519 key for DIDComm key agreement (#key-2) ---
            let mut e_key = Secret::generate_x25519(None, None)
                .map_err(|e| anyhow::anyhow!("Failed to generate X25519 key: {:?}", e))?;
            e_key.id = format!("{}#key-2", placeholder_did);

            let x25519_pub_jwk = if let affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial::JWK(jwk) =
                &e_key.secret_material
            {
                let v =
                    serde_json::to_value(jwk).map_err(|e| anyhow::anyhow!("Failed to serialize X25519 JWK: {}", e))?;
                strip_jwk_private_key(&v)
            } else {
                return Err(anyhow::anyhow!("X25519 secret is not JWK material"));
            };

            // --- 3. Build DID document JSON with {SCID} placeholder ---
            let ed25519_pub_jwk = strip_jwk_private_key(&key_pair.public_key);
            let did_document_json = serde_json::json!({
                "id": placeholder_did,
                "@context": ["https://www.w3.org/ns/did/v1"],
                "verificationMethod": [
                    {
                        "id": format!("{}#key-1", placeholder_did),
                        "type": "JsonWebKey2020",
                        "controller": placeholder_did,
                        "publicKeyJwk": ed25519_pub_jwk
                    },
                    {
                        "id": format!("{}#key-2", placeholder_did),
                        "type": "JsonWebKey2020",
                        "controller": placeholder_did,
                        "publicKeyJwk": x25519_pub_jwk
                    }
                ],
                "authentication": [format!("{}#key-1", placeholder_did)],
                "assertionMethod": [format!("{}#key-1", placeholder_did)],
                "keyAgreement": [format!("{}#key-2", placeholder_did)],
                "service": [{
                    "id": format!("{}#service", placeholder_did),
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{
                        "uri": mediator_did,
                        "accept": ["didcomm/v2"],
                        "routingKeys": []
                    }]
                }]
            });

            // --- 4. Create DID:webvh via shared helper ---
            let base_url = crate::identity::didwebvh::base_url_for_domain(domain);
            let result = create_webvh_did(&key_pair.private_key, did_document_json, &base_url).await?;

            let final_did = result.final_did;
            let scid = result.scid;
            let log_entry_json = result.log_entry_json;
            let signed_entry = result.signed_entry;

            // --- 5. Update e_key id to final DID ---
            e_key.id = format!("{}#key-2", final_did);

            // --- 6. Persist birth log ---
            log_storage
                .append_raw(&final_did, &log_entry_json)
                .await?;

            crate::storage::did_artifacts::write_did_log_raw(&tr_keys_path, &log_entry_json).await?;

            let state_json = serde_json::to_string(&signed_entry.state)?;
            let parallel_doc = crate::identity::didwebvh::generate_parallel_did_web(
                &serde_json::from_str(&state_json)?,
                &final_did,
                &scid,
            );
            let did_doc_json = serde_json::to_string_pretty(&parallel_doc)?;
            crate::storage::did_artifacts::write_did_document(&tr_keys_path, &did_doc_json).await?;

            // --- 7. Persist identity record ---
            let id = uuid::Uuid::new_v4();
            let now = chrono::Utc::now();
            let agent_dna = generate_random_dna(&scid);
            let mut metadata = std::collections::HashMap::new();
            if let Ok(dna_value) = serde_json::to_value(&agent_dna) {
                metadata.insert("agentDNA".to_string(), dna_value);
            }
            metadata.insert("trust_registry_id".to_string(), serde_json::Value::String(trust_registry_id.to_string()));

            let identity = DidWebVhIdentity {
                id,
                did: final_did.clone(),
                key_pair: Some(key_pair.clone()),
                version: 1,
                created_at: now,
                updated_at: now,
                metadata,
                active: true,
            };

            identity_store
                .create(identity)
                .await?;

            // --- 8. Build return secrets ---
            let key_id_1 = format!("{}#key-1", final_did);
            let ed25519_d_str = key_pair
                .private_key
                .get("d")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Missing 'd' in Ed25519 private key"))?;
            let ed25519_bytes = URL_SAFE_NO_PAD.decode(ed25519_d_str)?;
            let ed25519_seed: [u8; 32] = ed25519_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid Ed25519 key length"))?;
            let mut ed25519_secret = Secret::generate_ed25519(Some(&key_id_1), Some(&ed25519_seed));
            ed25519_secret.id = key_id_1;

            let secrets = vec![ed25519_secret, e_key];
            let didcomm_doc = build_did_web_document(&final_did, &secrets, mediator_did)?;

            // Persist on disk (parity with did:web/did:peer); never the operator-facing secrets store.
            for (i, secret) in secrets.iter().enumerate() {
                let secret_json = serde_json::to_string_pretty(secret)?;
                crate::encryption::secret_file::write_secret_file(
                    &tr_keys_path.join(format!("key_{}.json", i)),
                    &secret_json,
                )
                .await?;
            }

            info!("Trust registry did:webvh identity generated: {}", final_did);

            return Ok((final_did, secrets, didcomm_doc));
        }
        DidMethod::Peer => {
            info!("Generating trust registry did:peer for: {}", trust_registry_id);
            info!("  Service endpoint (mediator): {}", mediator_url);

            let v_multibase = v_key
                .get_public_keymultibase()
                .map_err(|e| anyhow::anyhow!("Failed to get V multibase: {:?}", e))?;
            let e_multibase = e_key
                .get_public_keymultibase()
                .map_err(|e| anyhow::anyhow!("Failed to get E multibase: {:?}", e))?;

            let keys = vec![
                PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, v_multibase),
                PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, e_multibase),
            ];
            let services = vec![PeerService {
                id: None,
                type_: "dm".into(),
                endpoint: PeerServiceEndpoint::Uri(mediator_did.to_string()),
            }];

            let (peer_did, _) = DID::generate_peer(&keys, Some(&services))
                .map_err(|e| anyhow::anyhow!("Failed to generate did:peer: {:?}", e))?;

            let did_str = peer_did.to_string();

            // Update secret IDs to reference the DID
            v_key.id = format!("{}#key-1", did_str);
            e_key.id = format!("{}#key-2", did_str);

            let did_document = peer_did
                .resolve()
                .map_err(|e| anyhow::anyhow!("Failed to resolve did:peer document: {:?}", e))?;
            let did_document = serde_json::to_value(&did_document)
                .map_err(|e| anyhow::anyhow!("Failed to serialize did:peer document: {}", e))?;

            (did_str, did_document)
        }
    };

    let secrets = vec![v_key, e_key];

    // Save secrets to disk
    for (i, secret) in secrets.iter().enumerate() {
        let secret_json = serde_json::to_string_pretty(&secret)?;
        crate::encryption::secret_file::write_secret_file(&tr_keys_path.join(format!("key_{}.json", i)), &secret_json)
            .await?;
    }

    // Save DID document to disk
    let did_doc_json = serde_json::to_string_pretty(&did_document)?;
    crate::storage::did_artifacts::write_did_document(&tr_keys_path, &did_doc_json).await?;

    info!("Trust registry '{}' identity generated: {}", trust_registry_id, did);

    Ok((did, secrets, did_document))
}

/// Loads secrets for a trust registry from disk.
///
/// # Arguments
/// * `trust_registry_id` - Unique ID of the trust registry
/// * `storage_path` - Base storage path for trust registries
pub async fn load_trust_registry_secrets(
    trust_registry_id: &str,
    storage_path: &std::path::Path,
) -> Result<Vec<Secret>> {
    let tr_keys_path = storage_path.join(trust_registry_id);

    let mut secrets = vec![];
    for i in 0.. {
        let key_file = tr_keys_path.join(format!("key_{}.json", i));
        let Some(content) = crate::encryption::secret_file::read_secret_file(&key_file).await? else {
            break;
        };
        let secret: Secret = serde_json::from_str(&content)?;
        secrets.push(secret);
    }

    if secrets.is_empty() {
        return Err(anyhow::anyhow!("No key files found in {:?}", tr_keys_path));
    }

    Ok(secrets)
}

/// Builds a DIDComm-compatible DID document from secrets.
///
/// Creates a W3C DID document with verification methods derived from the provided
/// secrets, plus authentication, keyAgreement, and DIDComm service sections.
/// Works with any DID scheme (did:web, did:webvh, etc.).
pub(crate) fn build_did_web_document(
    did: &str,
    secrets: &[Secret],
    mediator_url: &str,
) -> Result<serde_json::Value> {
    let mut public_jwks = Vec::new();

    for secret in secrets.iter() {
        if let affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial::JWK(jwk) = &secret.secret_material {
            let mut jwk_value =
                serde_json::to_value(jwk).map_err(|e| anyhow::anyhow!("Failed to serialize JWK: {}", e))?;
            // Remove private key component to create public key
            if let Some(obj) = jwk_value.as_object_mut() {
                obj.remove("d");
            }
            public_jwks.push(jwk_value);
        } else {
            return Err(anyhow::anyhow!("Secret is not a JWK"));
        }
    }

    let did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#key-1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_jwks[0]
            },
            {
                "id": format!("{}#key-2", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_jwks[1]
            }
        ],
        "authentication": [
            format!("{}#key-1", did)
        ],
        "assertionMethod": [
            format!("{}#key-1", did)
        ],
        "keyAgreement": [
            format!("{}#key-2", did)
        ],
        "service": [
            {
                "id": format!("{}#service", did),
                "type": ["DIDCommMessaging"],
                "serviceEndpoint": [
                    {
                        "uri": mediator_url,
                        "accept": ["didcomm/v2"],
                        "routingKeys": []
                    }
                ]
            }
        ]
    });

    Ok(did_document)
}

/// Load a stored DIDComm secret from the secrets store by its `secret_id`.
#[cfg(feature = "didwebvh")]
async fn load_trust_registry_didcomm_secret(
    secrets_store: &std::sync::Arc<dyn crate::secrets::SecretsStore>,
    secret_id: &str,
) -> Result<Secret> {
    let stored_secret = secrets_store
        .list_all()
        .await?
        .into_iter()
        .find(|secret| secret.secret_id == secret_id)
        .ok_or_else(|| anyhow::anyhow!("Secret not found for secret_id: {}", secret_id))?;

    let value = secrets_store
        .get(&stored_secret.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Secret payload not found for secret_id: {}", secret_id))?
        .value;

    serde_json::from_str(&value)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize stored DIDComm secret {}: {}", secret_id, e))
}

/// Derive DIDComm secrets from a DID:webvh identity stored in the shared identity store.
///
/// Loads the identity by DID, extracts the Ed25519 key pair, and derives:
/// - Ed25519 secret (signing/authentication)
/// - X25519 secret (key agreement/encryption, derived from Ed25519)
///
/// This replaces the old approach of reading separate key_*.json files from disk.
#[cfg(feature = "didwebvh")]
pub async fn derive_didcomm_secrets_from_identity_store(
    identity_store: &std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>,
    secrets_store: Option<&std::sync::Arc<dyn crate::secrets::SecretsStore>>,
    did: &str,
) -> Result<Vec<Secret>> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha512};

    let identity = identity_store
        .get_by_did(did)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Identity not found for DID: {}", did))?;

    let key_pair = identity
        .key_pair
        .ok_or_else(|| anyhow::anyhow!("Identity has no key pair: {}", did))?;

    // Extract Ed25519 seed bytes from the stored JWK private key
    let ed25519_d = key_pair
        .private_key
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing 'd' in Ed25519 key"))?;
    let ed25519_bytes = URL_SAFE_NO_PAD.decode(ed25519_d)?;
    let ed25519_seed: [u8; 32] = ed25519_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid Ed25519 key length"))?;

    // Ed25519 secret using generate_ed25519 (properly marks as signing secret)
    let key_id = format!("{}#key-1", did);
    let mut ed25519_secret = Secret::generate_ed25519(Some(&key_id), Some(&ed25519_seed));
    ed25519_secret.id = key_id.clone();

    // New identities keep the secp256k1 DIDComm key in the encrypted secrets store.
    // Older identities may still have the raw secret in metadata, and the oldest ones
    // derive X25519 from Ed25519 for backward compatibility.
    let e_secret = if let Some(secret_id_val) = identity
        .metadata
        .get(E_KEY_SECRET_ID_METADATA_KEY)
    {
        let secret_id = secret_id_val
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{} must be a string", E_KEY_SECRET_ID_METADATA_KEY))?;
        let secrets_store = secrets_store.ok_or_else(|| {
            anyhow::anyhow!("Secrets store required to load {} for DID {}", E_KEY_SECRET_ID_METADATA_KEY, did)
        })?;
        let mut e_secret = load_trust_registry_didcomm_secret(secrets_store, secret_id).await?;
        e_secret.id = format!("{}#key-2", did);
        e_secret
    } else if let Some(e_key_val) = identity.metadata.get("e_key") {
        let mut e_secret: Secret = serde_json::from_value(e_key_val.clone())
            .map_err(|e| anyhow::anyhow!("Failed to deserialize e_key from metadata: {}", e))?;
        e_secret.id = format!("{}#key-2", did);
        e_secret
    } else {
        let mut h = Sha512::digest(ed25519_seed);
        h[0] &= 248;
        h[31] &= 127;
        h[31] |= 64;
        let mut x25519_seed = [0u8; 32];
        x25519_seed.copy_from_slice(&h[..32]);
        Secret::generate_x25519(Some(&format!("{}#key-2", did)), Some(&x25519_seed))
            .map_err(|e| anyhow::anyhow!("Failed to derive X25519 secret: {:?}", e))?
    };

    Ok(vec![ed25519_secret, e_secret])
}

/// Moves a pre-disk-persistence `did:webvh` registry's DIDComm key off the operator-facing
/// secrets store onto disk. Disk-first (write+verify before delete) so an interruption never
/// loses key material; idempotent. Returns `true` when a migration was performed.
#[cfg(feature = "didwebvh")]
pub async fn migrate_didcomm_secret_to_disk(
    identity_store: &std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>,
    secrets_store: &std::sync::Arc<dyn crate::secrets::SecretsStore>,
    storage_path: &std::path::Path,
    trust_registry_id: &str,
    did: &str,
) -> Result<bool> {
    let Some(mut identity) = identity_store
        .get_by_did(did)
        .await?
    else {
        return Ok(false);
    };

    let Some(secret_id) = identity
        .metadata
        .get(E_KEY_SECRET_ID_METADATA_KEY)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    else {
        return Ok(false);
    };

    let tr_keys_path = storage_path.join(trust_registry_id);

    // Ensure keys exist on disk (write + verify) before touching the store.
    if load_trust_registry_secrets(trust_registry_id, storage_path)
        .await
        .is_err()
    {
        let secrets = derive_didcomm_secrets_from_identity_store(identity_store, Some(secrets_store), did).await?;
        tokio::fs::create_dir_all(&tr_keys_path).await?;
        for (i, secret) in secrets.iter().enumerate() {
            let secret_json = serde_json::to_string_pretty(secret)?;
            crate::encryption::secret_file::write_secret_file(
                &tr_keys_path.join(format!("key_{}.json", i)),
                &secret_json,
            )
            .await?;
        }
        load_trust_registry_secrets(trust_registry_id, storage_path).await?;
    }

    if let Some(stored) = secrets_store
        .get_by_secret_id(&secret_id)
        .await?
    {
        secrets_store
            .delete(&stored.id)
            .await?;
    }

    identity
        .metadata
        .remove(E_KEY_SECRET_ID_METADATA_KEY);
    identity.updated_at = chrono::Utc::now();
    identity_store
        .update(identity)
        .await?;

    info!("Trust registry '{}': migrated DIDComm key off the secrets store to disk", trust_registry_id);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_generate_trust_registry_identity() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage_path = temp_dir.path().to_path_buf();

        let (did, secrets, did_doc) = generate_trust_registry_identity(
            "test-tr-id",
            "example.com",
            &storage_path,
            "https://mediator.example.com",
            "did:web:mediator.example.com",
            DidMethod::Web,
            #[cfg(feature = "didwebvh")]
            None,
            #[cfg(feature = "didwebvh")]
            None,
        )
        .await
        .expect("Failed to generate identity");

        // Verify DID format
        assert!(did.starts_with("did:web:example.com:trust-registries:test-tr-id"));

        // Verify 2 secrets
        assert_eq!(secrets.len(), 2);

        // Verify secret IDs match DID
        for secret in &secrets {
            assert!(secret.id.starts_with(&did));
        }

        // Verify DID document has service endpoint
        let service = did_doc["service"][0]["serviceEndpoint"][0]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(service, "did:web:mediator.example.com");

        // Verify files saved on disk
        let keys_path = storage_path.join("test-tr-id");
        assert!(
            keys_path
                .join("key_0.json")
                .exists()
        );
        assert!(
            keys_path
                .join("key_1.json")
                .exists()
        );
        assert!(
            keys_path
                .join("did.json")
                .exists()
        );
    }

    #[tokio::test]
    async fn test_load_trust_registry_secrets() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage_path = temp_dir.path().to_path_buf();

        // Generate first
        let (_did, original_secrets, _doc) = generate_trust_registry_identity(
            "test-tr-load",
            "example.com",
            &storage_path,
            "https://mediator.example.com",
            "did:web:mediator.example.com",
            DidMethod::Web,
            #[cfg(feature = "didwebvh")]
            None,
            #[cfg(feature = "didwebvh")]
            None,
        )
        .await
        .expect("Failed to generate identity");

        // Load secrets
        let loaded_secrets = load_trust_registry_secrets("test-tr-load", &storage_path)
            .await
            .expect("Failed to load secrets");

        assert_eq!(loaded_secrets.len(), 2);
        assert_eq!(loaded_secrets[0].id, original_secrets[0].id);
        assert_eq!(loaded_secrets[1].id, original_secrets[1].id);
    }

    #[tokio::test]
    async fn test_generate_peer_identity() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage_path = temp_dir.path().to_path_buf();

        let (did, secrets, _did_doc) = generate_trust_registry_identity(
            "test-tr-peer",
            "example.com",
            &storage_path,
            "https://mediator.example.com",
            "did:web:mediator.example.com",
            DidMethod::Peer,
            #[cfg(feature = "didwebvh")]
            None,
            #[cfg(feature = "didwebvh")]
            None,
        )
        .await
        .expect("Failed to generate peer identity");

        assert!(did.starts_with("did:peer:"));
        assert_eq!(secrets.len(), 2);
        for secret in &secrets {
            assert!(secret.id.starts_with(&did));
        }

        let keys_path = storage_path.join("test-tr-peer");
        assert!(
            keys_path
                .join("key_0.json")
                .exists()
        );
        assert!(
            keys_path
                .join("key_1.json")
                .exists()
        );
        assert!(
            keys_path
                .join("did.json")
                .exists()
        );
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn test_generate_webvh_identity() {
        use crate::identity::didwebvh::FileSystemDidWebVhIdentityStore;
        use crate::secrets::FilesystemSecretsStore;
        use crate::storage::FileDidLogStorage;

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage_path = temp_dir.path().to_path_buf();

        let identity_store = std::sync::Arc::new(
            FileSystemDidWebVhIdentityStore::new(
                temp_dir
                    .path()
                    .join("didwebvh"),
            )
            .await
            .expect("Failed to create identity store"),
        ) as std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>;

        let log_storage = std::sync::Arc::new(FileDidLogStorage::new(
            temp_dir
                .path()
                .join("didwebvh_logs"),
        )) as std::sync::Arc<dyn crate::storage::DidLogStorage>;
        let secrets_store = std::sync::Arc::new(
            FilesystemSecretsStore::new_async(
                temp_dir
                    .path()
                    .join("secrets")
                    .to_string_lossy()
                    .as_ref(),
            )
            .await
            .expect("Failed to create secrets store"),
        ) as std::sync::Arc<dyn crate::secrets::SecretsStore>;

        let (did, secrets, did_doc) = generate_trust_registry_identity(
            "test-tr-webvh",
            "example.com",
            &storage_path,
            "https://mediator.example.com",
            "did:web:mediator.example.com",
            DidMethod::Webvh,
            Some(identity_store.clone()),
            Some(log_storage.clone()),
        )
        .await
        .expect("Failed to generate webvh identity");

        assert!(did.starts_with("did:webvh:"), "DID must start with did:webvh:, got: {}", did);
        assert!(
            did.contains(":trust-registries:test-tr-webvh"),
            "DID must contain trust-registries path, got: {}",
            did
        );
        assert_eq!(secrets.len(), 2, "Must have 2 DIDComm secrets (Ed25519 + X25519)");

        for secret in &secrets {
            assert!(secret.id.starts_with(&did), "Secret ID must reference the final DID");
        }

        // Verify the DIDComm doc uses did:webvh IDs (not did:web parallel doc)
        let doc_id = did_doc["id"]
            .as_str()
            .expect("DID doc must have id");
        assert!(doc_id.starts_with("did:webvh:"), "DID doc id must use did:webvh, got: {}", doc_id);
        assert_eq!(doc_id, did, "DID doc id must match the returned DID");

        // Verify both verification methods exist with correct did:webvh IDs
        let vms = did_doc["verificationMethod"]
            .as_array()
            .expect("Must have verificationMethod");
        assert_eq!(vms.len(), 2, "Must have 2 verification methods");
        assert_eq!(vms[0]["id"].as_str().unwrap(), format!("{}#key-1", did));
        assert_eq!(vms[1]["id"].as_str().unwrap(), format!("{}#key-2", did));

        // Verify authentication references #key-1 (Ed25519 signing)
        let auth = did_doc["authentication"]
            .as_array()
            .expect("Must have authentication");
        assert_eq!(auth[0].as_str().unwrap(), format!("{}#key-1", did));

        // Verify keyAgreement references #key-2 (X25519 encryption)
        let ka = did_doc["keyAgreement"]
            .as_array()
            .expect("Must have keyAgreement");
        assert_eq!(ka[0].as_str().unwrap(), format!("{}#key-2", did));

        // Verify DIDComm service endpoint
        let service_uri = did_doc["service"][0]["serviceEndpoint"][0]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(service_uri, "did:web:mediator.example.com");

        // Verify identity is in the shared store (not on disk as separate files)
        let loaded = identity_store
            .get_by_did(&did)
            .await
            .expect("Failed to query identity store")
            .expect("Identity must be in the shared store");
        assert_eq!(loaded.did, did);
        assert!(loaded.key_pair.is_some(), "Key pair must be stored in identity record");
        assert!(
            !loaded
                .metadata
                .contains_key("e_key"),
            "Raw DIDComm key must not be persisted in identity metadata"
        );
        assert!(
            !loaded
                .metadata
                .contains_key(E_KEY_SECRET_ID_METADATA_KEY),
            "New did:webvh registries must not reference the operator-facing secrets store"
        );
        assert!(
            secrets_store
                .list_all()
                .await
                .expect("Failed to list secrets")
                .is_empty(),
            "DIDComm key agreement secret must not be stored in the operator-facing secrets store"
        );

        // Verify log is in the shared log storage
        let log_entries = log_storage
            .load_all(&did)
            .await
            .expect("Failed to load log entries");
        assert_eq!(log_entries.len(), 1, "Must have exactly one birth log entry");

        // Verify key material is persisted on disk (parity with did:web/did:peer
        // and connection points) rather than the operator-facing secrets store
        let keys_path = storage_path.join("test-tr-webvh");
        assert!(
            keys_path
                .join("key_0.json")
                .exists(),
            "Ed25519 key file must exist on disk"
        );
        assert!(
            keys_path
                .join("key_1.json")
                .exists(),
            "X25519 key file must exist on disk"
        );

        // Verify did.json IS written to disk (same pattern as departments)
        assert!(
            keys_path
                .join("did.json")
                .exists(),
            "did.json must exist on disk"
        );
        let did_json_content = tokio::fs::read_to_string(keys_path.join("did.json"))
            .await
            .expect("Failed to read did.json");
        let did_json: serde_json::Value = serde_json::from_str(&did_json_content).expect("did.json must be valid JSON");

        // did.json is a parallel did:web document (same as departments) but with
        // keyAgreement and DIDComm service carried from the birth entry state
        assert!(
            did_json["id"]
                .as_str()
                .unwrap()
                .starts_with("did:web:"),
            "Parallel did.json must use did:web scheme"
        );
        let also_known_as = did_json["alsoKnownAs"]
            .as_array()
            .expect("Parallel doc must have alsoKnownAs");
        assert!(
            also_known_as.iter().any(|v| v
                .as_str()
                .is_some_and(|s| s.starts_with("did:webvh:"))),
            "alsoKnownAs must reference the did:webvh DID"
        );
        assert!(
            did_json["keyAgreement"]
                .as_array()
                .is_some_and(|arr| !arr.is_empty()),
            "did.json must include keyAgreement for DIDComm"
        );
        assert!(
            did_json["service"]
                .as_array()
                .is_some_and(|arr| !arr.is_empty()),
            "did.json must include DIDComm service endpoint"
        );
        let vm = did_json["verificationMethod"]
            .as_array()
            .expect("did.json must have verificationMethod");
        assert!(vm.len() >= 2, "did.json must have at least 2 verification methods (Ed25519 + X25519)");

        // Verify did.jsonl IS written to disk (same pattern as departments)
        assert!(
            keys_path
                .join("did.jsonl")
                .exists(),
            "did.jsonl must exist on disk"
        );
        let jsonl_content = tokio::fs::read_to_string(keys_path.join("did.jsonl"))
            .await
            .expect("Failed to read did.jsonl");
        assert!(!jsonl_content.is_empty(), "did.jsonl must not be empty");

        // Verify secrets can be derived from the store
        let derived = derive_didcomm_secrets_from_identity_store(&identity_store, Some(&secrets_store), &did)
            .await
            .expect("Failed to derive DIDComm secrets from store");
        assert_eq!(derived.len(), 2);
        assert_eq!(derived[0].id, format!("{}#key-1", did));
        assert_eq!(derived[1].id, format!("{}#key-2", did));
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn test_migrate_didcomm_secret_to_disk() {
        use crate::identity::didwebvh::FileSystemDidWebVhIdentityStore;
        use crate::secrets::FilesystemSecretsStore;
        use crate::storage::FileDidLogStorage;

        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let storage_path = temp_dir.path().to_path_buf();

        let identity_store = std::sync::Arc::new(
            FileSystemDidWebVhIdentityStore::new(
                temp_dir
                    .path()
                    .join("didwebvh"),
            )
            .await
            .expect("Failed to create identity store"),
        ) as std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>;
        let log_storage = std::sync::Arc::new(FileDidLogStorage::new(
            temp_dir
                .path()
                .join("didwebvh_logs"),
        )) as std::sync::Arc<dyn crate::storage::DidLogStorage>;
        let secrets_store = std::sync::Arc::new(
            FilesystemSecretsStore::new_async(
                temp_dir
                    .path()
                    .join("secrets")
                    .to_string_lossy()
                    .as_ref(),
            )
            .await
            .expect("Failed to create secrets store"),
        ) as std::sync::Arc<dyn crate::secrets::SecretsStore>;

        let (did, secrets, _did_doc) = generate_trust_registry_identity(
            "test-tr-migrate",
            "example.com",
            &storage_path,
            "https://mediator.example.com",
            "did:web:mediator.example.com",
            DidMethod::Webvh,
            Some(identity_store.clone()),
            Some(log_storage.clone()),
        )
        .await
        .expect("Failed to generate webvh identity");

        // Recreate the pre-disk-persistence state: X25519 in the operator-facing
        // store, referenced from identity metadata, and no key files on disk.
        let stored = secrets_store
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "legacy DIDComm key".to_string(),
                secret_id: crate::secrets::generate_secret_id("legacy-e-key"),
                description: None,
                value: serde_json::to_string(&secrets[1]).expect("serialize e_key"),
                secret_type: "General".to_string(),
                tags: vec!["trust-registry".to_string()],
            })
            .await
            .expect("Failed to seed legacy secret");

        let mut identity = identity_store
            .get_by_did(&did)
            .await
            .expect("query identity")
            .expect("identity must exist");
        identity
            .metadata
            .insert(E_KEY_SECRET_ID_METADATA_KEY.to_string(), serde_json::Value::String(stored.secret_id.clone()));
        identity_store
            .update(identity)
            .await
            .expect("update identity");

        let keys_path = storage_path.join("test-tr-migrate");
        tokio::fs::remove_file(keys_path.join("key_0.json"))
            .await
            .expect("remove key_0");
        tokio::fs::remove_file(keys_path.join("key_1.json"))
            .await
            .expect("remove key_1");
        assert!(
            load_trust_registry_secrets("test-tr-migrate", &storage_path)
                .await
                .is_err(),
            "precondition: no key files on disk"
        );

        let migrated =
            migrate_didcomm_secret_to_disk(&identity_store, &secrets_store, &storage_path, "test-tr-migrate", &did)
                .await
                .expect("migration failed");
        assert!(migrated, "migration must report work done");

        // Keys are back on disk with the correct DID-scoped ids.
        let loaded = load_trust_registry_secrets("test-tr-migrate", &storage_path)
            .await
            .expect("keys must load from disk after migration");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, format!("{}#key-1", did));
        assert_eq!(loaded[1].id, format!("{}#key-2", did));

        // Secret removed from the operator-facing store.
        assert!(
            secrets_store
                .list_all()
                .await
                .expect("list secrets")
                .is_empty(),
            "DIDComm secret must be deleted from the operator-facing store"
        );

        // Metadata reference cleared.
        let after = identity_store
            .get_by_did(&did)
            .await
            .expect("query identity")
            .expect("identity must exist");
        assert!(
            !after
                .metadata
                .contains_key(E_KEY_SECRET_ID_METADATA_KEY),
            "e_key_secret_id metadata must be cleared after migration"
        );

        // Idempotent: a second run does nothing.
        let again =
            migrate_didcomm_secret_to_disk(&identity_store, &secrets_store, &storage_path, "test-tr-migrate", &did)
                .await
                .expect("second migration failed");
        assert!(!again, "second migration must be a no-op");
    }
}
