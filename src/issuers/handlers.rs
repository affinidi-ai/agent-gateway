use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{info, warn};

use super::IssuerStore;
use super::types::{Issuer, IssuerResponse};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};
use crate::trust_registries::communication::TrustRegistryListenerManager;
use crate::trust_registries::types::TrAdminRecordRequest;

#[derive(Debug, Deserialize)]
pub struct CreateIssuerRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,

    /// Optional description for the issuer.
    #[serde(default)]
    pub description: Option<String>,

    /// Optional: Trust registry DID to register the issuer with.
    /// Must be provided together with `authority_did`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_registry_did: Option<String>,

    /// Optional: Authority DID (company DID) that asserts ownership of this issuer.
    /// Required if `trust_registry_did` is provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_did: Option<String>,
}

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

fn issuer_allowed(
    issuer: &Issuer,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(issuer.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Issuers, &issuer.id)
}

#[derive(Debug, Deserialize)]
pub struct UpdateIssuerRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// List all issuers (secrets + did_document excluded)
pub async fn list_issuers<S: IssuerStore>(
    Extension(store): Extension<Arc<S>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<IssuerResponse>>, (StatusCode, String)> {
    let mut issuers = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let context = tenant_context(&context);
    let scope = resource_scope(&scope);
    issuers.retain(|issuer| {
        can_access(issuer.tenant_id.as_deref(), context)
            && scope_allows_resource(scope, context, ResourceKind::Issuers, &issuer.id)
    });
    Ok(Json(
        issuers
            .into_iter()
            .map(IssuerResponse::from)
            .collect(),
    ))
}

/// Create an issuer with auto-generated DID.
/// When the `didwebvh` feature is enabled a `did:webvh` identity is created
/// (with birth log, SCID, signed entry, and parallel did:web document).
/// Otherwise falls back to a plain `did:web` identity.
pub async fn create_issuer<S: IssuerStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(vc_issuer): Extension<Arc<crate::identity::VCIssuer>>,
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(tr_manager): Extension<Option<Arc<TrustRegistryListenerManager>>>,
    Extension(log_storage): Extension<Option<Arc<dyn crate::storage::DidLogStorage>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateIssuerRequest>,
) -> Result<(StatusCode, Json<IssuerResponse>), (StatusCode, String)> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Issuer name cannot be empty".to_string()));
    }

    // Validate: trust_registry_did and authority_did must both be present or both absent
    if req
        .trust_registry_did
        .is_some()
        != req.authority_did.is_some()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "trust_registry_did and authority_did must both be provided together".to_string(),
        ));
    }

    let id = uuid::Uuid::new_v4().to_string();
    if !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Issuers, &id) {
        return Err((StatusCode::FORBIDDEN, "Issuer is outside this token's permitted scope".into()));
    }

    // Generate DID identity — did:webvh when feature is enabled, did:web fallback otherwise
    #[cfg(feature = "didwebvh")]
    let mut issuer = {
        let issuer_gateway_did = vc_issuer
            .get_issuer_did()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let domain = extract_domain_from_did(&issuer_gateway_did);
        let storage_path = std::path::Path::new(&config.storage_paths.issuers);

        let (did, key_pair, did_document) =
            generate_issuer_identity_webvh(&id, &domain, storage_path, log_storage.clone())
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        Issuer::new_webvh(id, name.clone(), did, key_pair, did_document)
    };

    #[cfg(not(feature = "didwebvh"))]
    let mut issuer = {
        let (did, secrets_json, did_document) = generate_issuer_did(&vc_issuer, &id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Issuer::new(id, name.clone(), did, secrets_json, did_document)
    };

    // Suppress unused-variable warnings when feature gates exclude one branch
    #[cfg(not(feature = "didwebvh"))]
    let _ = &config;
    issuer.description = req
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    issuer.tenant_id = req.tenant_id;

    store
        .create(&issuer)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!("Issuer created: {} ({})", issuer.name, issuer.did);

    // Optionally register issuer in trust registry (non-fatal on failure)
    if let (Some(tr_did), Some(authority_did)) = (
        req.trust_registry_did
            .as_deref(),
        req.authority_did.as_deref(),
    ) {
        if let Some(ref manager) = tr_manager {
            let q3_resource = crate::trust_registries::q3_resource_config::q3_resource_name();
            let records = vec![
                TrAdminRecordRequest {
                    authority_id: authority_did.to_string(),
                    entity_id: issuer.did.clone(),
                    action: "is".to_string(),
                    resource: q3_resource.to_string(),
                    record_type: "recognition".to_string(),
                    authorized: true,
                    recognized: true,
                    context: None,
                },
                TrAdminRecordRequest {
                    authority_id: authority_did.to_string(),
                    entity_id: issuer.did.clone(),
                    action: "register".to_string(),
                    resource: "agents".to_string(),
                    record_type: "authorization".to_string(),
                    authorized: true,
                    recognized: true,
                    context: None,
                },
            ];

            match manager
                .create_records(tr_did, &records)
                .await
            {
                Ok(_) => {
                    info!(
                        did = %issuer.did,
                        trust_registry_did = %tr_did,
                        authority_did = %authority_did,
                        "Issuer registered in trust registry"
                    );
                    issuer.trust_registry_did = Some(tr_did.to_string());
                    issuer.authority_did = Some(authority_did.to_string());
                    issuer.tr_registered = Some(true);
                    store
                        .update(&issuer)
                        .await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                }
                Err(e) => {
                    warn!(
                        did = %issuer.did,
                        trust_registry_did = %tr_did,
                        error = %e,
                        "Failed to register issuer in trust registry (non-fatal)"
                    );
                    // Persist TR context so retry is possible later
                    issuer.trust_registry_did = Some(tr_did.to_string());
                    issuer.authority_did = Some(authority_did.to_string());
                    issuer.tr_registered = Some(false);
                    let _ = store.update(&issuer).await;
                }
            }
        } else {
            warn!(
                did = %issuer.did,
                trust_registry_did = %tr_did,
                "Trust registry registration requested but listener manager not configured"
            );
        }
    }

    Ok((StatusCode::CREATED, Json(IssuerResponse::from(issuer))))
}

/// Get an issuer by ID (secrets + did_document excluded)
pub async fn get_issuer<S: IssuerStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<IssuerResponse>, (StatusCode, String)> {
    let issuer = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Issuer not found".to_string()))?;
    if !can_access(issuer.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Issuers, &issuer.id)
    {
        return Err((StatusCode::NOT_FOUND, "Issuer not found".to_string()));
    }
    Ok(Json(IssuerResponse::from(issuer)))
}

/// Update an issuer (name only)
pub async fn update_issuer<S: IssuerStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateIssuerRequest>,
) -> Result<Json<IssuerResponse>, (StatusCode, String)> {
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Issuer name cannot be empty".to_string()));
    }

    let mut issuer = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Issuer not found".to_string()))?;
    if !can_access(issuer.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Issuers, &issuer.id)
    {
        return Err((StatusCode::FORBIDDEN, "Issuer is outside this token's permitted scope".into()));
    }

    issuer.name = name;
    if let Some(description) = req.description {
        issuer.description = Some(description)
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
    }
    issuer.updated_at = chrono::Utc::now();

    store
        .update(&issuer)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!("Issuer updated: {} ({})", issuer.name, issuer.id);
    Ok(Json(IssuerResponse::from(issuer)))
}

/// Delete an issuer
pub async fn delete_issuer<S: IssuerStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(tr_manager): Extension<Option<Arc<TrustRegistryListenerManager>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    let issuer = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Issuer not found".to_string()))?;
    if !can_access(issuer.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Issuers, &issuer.id)
    {
        return Err((StatusCode::FORBIDDEN, "Issuer is outside this token's permitted scope".into()));
    }

    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    info!("Issuer deleted: {} ({})", issuer.name, issuer.id);

    // Deregister from trust registry if it was registered there (non-fatal on failure)
    if let (Some(tr_did), Some(authority_did)) = (&issuer.trust_registry_did, &issuer.authority_did)
        && let Some(ref manager) = tr_manager
    {
        let q3_resource = crate::trust_registries::q3_resource_config::q3_resource_name();
        let records = vec![
            TrAdminRecordRequest {
                authority_id: authority_did.clone(),
                entity_id: issuer.did.clone(),
                action: "is".to_string(),
                resource: q3_resource.to_string(),
                record_type: "recognition".to_string(),
                authorized: true,
                recognized: true,
                context: None,
            },
            TrAdminRecordRequest {
                authority_id: authority_did.clone(),
                entity_id: issuer.did.clone(),
                action: "register".to_string(),
                resource: "agents".to_string(),
                record_type: "authorization".to_string(),
                authorized: true,
                recognized: true,
                context: None,
            },
        ];

        match manager
            .delete_records(tr_did, &records)
            .await
        {
            Ok(_) => {
                info!(
                    did = %issuer.did,
                    trust_registry_did = %tr_did,
                    "Issuer deregistered from trust registry"
                );
            }
            Err(e) => {
                warn!(
                    did = %issuer.did,
                    trust_registry_did = %tr_did,
                    error = %e,
                    "Failed to deregister issuer from trust registry (non-fatal)"
                );
            }
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Serve the W3C DID document for an issuer (unauthenticated — did:web resolution)
pub async fn serve_issuer_did_document<S: IssuerStore>(
    Extension(store): Extension<Arc<S>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let issuer = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Issuer not found".to_string()))?;
    Ok(Json(issuer.did_document))
}

/// Response for the issuer TR registration retry endpoint
#[derive(Debug, serde::Serialize)]
pub struct RetryIssuerTrRegistrationResponse {
    pub success: bool,
    pub message: String,
}

/// POST /v1/issuers/{id}/register-trust-registry
///
/// Retry trust registry registration for an issuer.
pub async fn retry_issuer_tr_registration<S: IssuerStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(tr_manager): Extension<Option<Arc<TrustRegistryListenerManager>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<RetryIssuerTrRegistrationResponse>, (StatusCode, String)> {
    info!(issuer_id = %id, "Issuer TR registration retry requested");

    let mut issuer = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "Issuer not found".to_string()))?;
    if !issuer_allowed(&issuer, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Issuer is outside this token's permitted scope".to_string()));
    }

    let tr_did = issuer
        .trust_registry_did
        .as_deref()
        .ok_or_else(|| {
            (StatusCode::BAD_REQUEST, "Issuer has no trust_registry_did — cannot register in TR".to_string())
        })?;

    let authority_did = issuer
        .authority_did
        .as_deref()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Issuer has no authority_did — cannot register in TR".to_string()))?;

    let manager = tr_manager
        .as_ref()
        .ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, "Trust registry listener manager not configured".to_string())
        })?;

    let q3_resource = crate::trust_registries::q3_resource_config::q3_resource_name();
    let records = vec![
        TrAdminRecordRequest {
            authority_id: authority_did.to_string(),
            entity_id: issuer.did.clone(),
            action: "is".to_string(),
            resource: q3_resource.to_string(),
            record_type: "recognition".to_string(),
            authorized: true,
            recognized: true,
            context: None,
        },
        TrAdminRecordRequest {
            authority_id: authority_did.to_string(),
            entity_id: issuer.did.clone(),
            action: "register".to_string(),
            resource: "agents".to_string(),
            record_type: "authorization".to_string(),
            authorized: true,
            recognized: true,
            context: None,
        },
    ];

    let registered = match manager
        .create_records(tr_did, &records)
        .await
    {
        Ok(_) => {
            info!(
                issuer_id = %id,
                trust_registry_did = %tr_did,
                "Issuer TR registration retry succeeded"
            );
            true
        }
        Err(e) => {
            warn!(
                issuer_id = %id,
                trust_registry_did = %tr_did,
                error = %e,
                "Issuer TR registration retry failed"
            );
            false
        }
    };

    issuer.tr_registered = Some(registered);
    let _ = store.update(&issuer).await;

    let (message, status_text) = if registered {
        ("Issuer successfully registered in trust registry".to_string(), "success")
    } else {
        ("TR registration failed — check gateway logs for details".to_string(), "failed")
    };

    info!(issuer_id = %id, status = status_text, "Issuer TR registration retry completed");

    Ok(Json(RetryIssuerTrRegistrationResponse { success: registered, message }))
}

// ─── Domain extraction ──────────────────────────────────────────────────────

/// Extract the domain segment from an issuer DID, decoding encoded localhost ports.
fn extract_domain_from_did(issuer_did: &str) -> String {
    crate::identity::utils::extract_domain_from_did(issuer_did)
}

// ─── did:webvh identity generation ──────────────────────────────────────────

/// Generate a `did:webvh` identity for an issuer.
///
/// Creates a birth log entry (`did.jsonl`), persists it to
/// `{storage_path}/{issuer_id}/did.jsonl`, and returns the canonical
/// `did:webvh:<SCID>:<domain>:issuers:<uuid>` DID, the Ed25519 signing
/// `KeyPair`, and the parallel `did:web` document for backward-compatible
/// resolution.
#[cfg(feature = "didwebvh")]
pub async fn generate_issuer_identity_webvh(
    issuer_id: &str,
    domain: &str,
    storage_path: &std::path::Path,
    log_storage: Option<Arc<dyn crate::storage::DidLogStorage>>,
) -> anyhow::Result<(String, crate::identity::didwebvh::types::KeyPair, serde_json::Value)> {
    use crate::identity::didwebvh::create::{create_webvh_did, strip_jwk_private_key};
    use crate::identity::didwebvh::types::KeyPair;
    use affinidi_tdk_common::secrets_resolver::secrets::{Secret, SecretMaterial};

    let issuer_keys_path = storage_path.join(issuer_id);
    tokio::fs::create_dir_all(&issuer_keys_path).await?;

    let safe_domain = domain.replace(':', "%3A");
    let placeholder_did = format!("did:webvh:{{SCID}}:{}:issuers:{}", safe_domain, issuer_id);

    // --- 1. Generate key material ---
    let mut ed25519_secret = Secret::generate_ed25519(None, None);
    let mut x25519_secret =
        Secret::generate_x25519(None, None).map_err(|e| anyhow::anyhow!("Failed to generate X25519 key: {:?}", e))?;
    let mut p256_secret =
        Secret::generate_p256(None, None).map_err(|e| anyhow::anyhow!("Failed to generate P-256 key: {:?}", e))?;

    ed25519_secret.id = format!("{}#key-1", placeholder_did);
    x25519_secret.id = format!("{}#key-2", placeholder_did);
    p256_secret.id = format!("{}#key-3", placeholder_did);

    // --- 2. Extract Ed25519 JWK for DID document and KeyPair storage ---
    let ed25519_private_jwk = match &ed25519_secret.secret_material {
        SecretMaterial::JWK(jwk) => {
            serde_json::to_value(jwk).map_err(|e| anyhow::anyhow!("Failed to serialize JWK: {}", e))?
        }
        _ => return Err(anyhow::anyhow!("Ed25519 secret is not a JWK")),
    };
    let ed25519_pub_jwk = strip_jwk_private_key(&ed25519_private_jwk);

    // --- 3. Build DID document JSON with {SCID} placeholder (no service — issuers are not agents) ---
    let did_document_json = serde_json::json!({
        "id": placeholder_did,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{}#key-1", placeholder_did),
            "type": "JsonWebKey2020",
            "controller": placeholder_did,
            "publicKeyJwk": ed25519_pub_jwk
        }],
        "authentication": [format!("{}#key-1", placeholder_did)],
        "assertionMethod": [format!("{}#key-1", placeholder_did)]
    });

    // --- 4. Create DID:webvh via shared helper ---
    let base_url = crate::identity::didwebvh::base_url_for_domain(domain);
    let result = create_webvh_did(&ed25519_private_jwk, did_document_json, &base_url).await?;

    let final_did = result.final_did;
    let log_entry_json = result.log_entry_json;
    let signed_entry = result.signed_entry;
    let scid = result.scid;

    // --- 5. Persist birth log to {issuer_id}/did.jsonl (raw JSON preserves signature) ---
    crate::storage::did_artifacts::write_did_log_raw(&issuer_keys_path, &log_entry_json).await?;

    if let Some(storage) = log_storage
        && let Err(e) = storage
            .append_raw(&final_did, &log_entry_json)
            .await
    {
        warn!("Failed to register issuer DID in log storage: {}", e);
    }

    // --- 6. Update secret IDs to reference the final DID ---
    ed25519_secret.id = format!("{}#key-1", final_did);
    x25519_secret.id = format!("{}#key-2", final_did);
    p256_secret.id = format!("{}#key-3", final_did);
    let secrets = [ed25519_secret, x25519_secret, p256_secret];

    for (i, secret) in secrets.iter().enumerate() {
        let secret_json = serde_json::to_string_pretty(secret)?;
        crate::encryption::secret_file::write_secret_file(
            &issuer_keys_path.join(format!("key_{}.json", i)),
            &secret_json,
        )
        .await?;
    }

    // --- 7. Generate parallel did:web document ---
    let state_json = serde_json::to_string(&signed_entry.state)?;
    let parallel_doc =
        crate::identity::didwebvh::generate_parallel_did_web(&serde_json::from_str(&state_json)?, &final_did, &scid);

    let did_doc_json = serde_json::to_string_pretty(&parallel_doc)?;
    crate::storage::did_artifacts::write_did_document(&issuer_keys_path, &did_doc_json).await?;

    info!("Generated issuer did:webvh: {}", final_did);

    let key_pair = KeyPair {
        public_key: ed25519_pub_jwk,
        private_key: ed25519_private_jwk,
        key_type: "Ed25519".to_string(),
    };

    Ok((final_did, key_pair, parallel_doc))
}

// ─── did:web fallback identity generation ───────────────────────────────────

/// Generate a `did:web` DID with keys for an issuer.
/// Used as fallback when the `didwebvh` feature is not enabled.
#[cfg(not(feature = "didwebvh"))]
async fn generate_issuer_did(
    vc_issuer: &crate::identity::VCIssuer,
    identity_id: &str,
) -> anyhow::Result<(String, serde_json::Value, serde_json::Value)> {
    use affinidi_tdk_common::secrets_resolver::secrets::Secret;
    use serde_json::json;

    let issuer_did = vc_issuer
        .get_issuer_did()
        .await?;

    let domain = extract_domain_from_did(&issuer_did);
    let safe_domain = domain.replace(':', "%3A");
    let did = format!("did:web:{}:issuers:{}", safe_domain, identity_id);

    info!("[Issuer DID] Generated DID: {}", did);

    let mut ed25519_secret = Secret::generate_ed25519(None, None);
    let mut x25519_secret = Secret::generate_x25519(None, None)?;
    let mut p256_secret = Secret::generate_p256(None, None)?;

    ed25519_secret.id = format!("{}#key-1", did);
    x25519_secret.id = format!("{}#key-2", did);
    p256_secret.id = format!("{}#key-3", did);

    let secrets = vec![ed25519_secret, x25519_secret, p256_secret];

    let mut public_jwks = Vec::new();
    for secret in &secrets {
        if let affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial::JWK(jwk) = &secret.secret_material {
            let mut jwk_value = serde_json::to_value(jwk)?;
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
        "verificationMethod": public_jwks.iter().enumerate().map(|(i, jwk)| {
            json!({
                "id": format!("{}#key-{}", did, i + 1),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk
            })
        }).collect::<Vec<_>>(),
        "authentication": [format!("{}#key-1", did)],
        "assertionMethod": [format!("{}#key-1", did)],
        "keyAgreement": [format!("{}#key-2", did)]
    });

    let secrets_json = serde_json::to_value(&secrets)?;

    Ok((did, secrets_json, did_document))
}

// ─── did:webvh DID log serving ──────────────────────────────────────────────

fn issuer_artifact_dir(
    base: &std::path::Path,
    id: &str,
) -> anyhow::Result<std::path::PathBuf> {
    crate::storage::validate_storage_id(id)?;
    let issuer_dir = base.join(id);
    crate::storage::assert_within_storage_dir(base, &issuer_dir)?;
    Ok(issuer_dir)
}

/// Handler for `GET /issuers/{id}/did.jsonl`.
///
/// Serves the issuer's verifiable DID log for did:webvh resolution.
/// Returns 404 (RFC 9457 problem-details) when the log has not been created yet.
pub async fn serve_issuer_did_jsonl<S: IssuerStore>(
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(_store): Extension<Arc<S>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;

    let base = std::path::Path::new(&config.storage_paths.issuers);
    let issuer_dir = match issuer_artifact_dir(base, &id) {
        Ok(dir) => dir,
        Err(e) => {
            warn!(error = %e, issuer_id = %id, "Rejected issuer DID log request");
            let problem = serde_json::json!({
                "type": "https://identity.foundation/didwebvh/v1.0/#problem-details",
                "title": "invalidDid",
                "status": 400,
                "detail": "Invalid issuer id"
            });
            return (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/problem+json")],
                problem.to_string(),
            )
                .into_response();
        }
    };

    match crate::storage::did_artifacts::read_did_log_raw(&issuer_dir).await {
        Ok(Some(content)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/jsonl"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
            content,
        )
            .into_response(),
        Ok(None) => {
            let problem = serde_json::json!({
                "type": "https://identity.foundation/didwebvh/v1.0/#problem-details",
                "title": "notFound",
                "status": 404,
                "detail": format!("DID log not found for issuer: {}", id)
            });
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/problem+json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
                problem.to_string(),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, issuer_id = %id, "Failed to read issuer did.jsonl");
            let problem = serde_json::json!({
                "type": "https://identity.foundation/didwebvh/v1.0/#problem-details",
                "title": "internalError",
                "status": 500,
                "detail": "Failed to read DID log"
            });
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/problem+json")],
                problem.to_string(),
            )
                .into_response()
        }
    }
}

// ─── Migration endpoint ─────────────────────────────────────────────────────

/// Response for the issuer did:webvh migration endpoint.
#[derive(Debug, serde::Serialize)]
pub struct MigrateIssuerWebvhResponse {
    pub migrated: usize,
    pub skipped: usize,
    pub errors: Vec<String>,
}

/// POST /v1/admin/issuers/migrate-to-webvh
///
/// Migrates all issuers that still use `did:web` to `did:webvh`.
/// Each migrated issuer receives a new birth log, SCID, and signed entry.
/// The old `did:web` identifier is preserved via `alsoKnownAs` in the parallel
/// did:web document.
#[cfg(feature = "didwebvh")]
pub async fn migrate_issuers_to_webvh<S: IssuerStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(vc_issuer): Extension<Arc<crate::identity::VCIssuer>>,
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(log_storage): Extension<Option<Arc<dyn crate::storage::DidLogStorage>>>,
) -> Result<Json<MigrateIssuerWebvhResponse>, (StatusCode, String)> {
    let issuers = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let issuer_gateway_did = vc_issuer
        .get_issuer_did()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let domain = extract_domain_from_did(&issuer_gateway_did);
    let storage_path = std::path::Path::new(&config.storage_paths.issuers);

    let mut migrated = 0usize;
    let mut skipped = 0usize;
    let mut errors = Vec::new();

    for mut issuer in issuers {
        // Only migrate issuers that still have a did:web DID
        if !issuer
            .did
            .starts_with("did:web:")
        {
            skipped += 1;
            continue;
        }

        match generate_issuer_identity_webvh(&issuer.id, &domain, storage_path, log_storage.clone()).await {
            Ok((new_did, key_pair, did_document)) => {
                info!(
                    issuer_id = %issuer.id,
                    old_did = %issuer.did,
                    new_did = %new_did,
                    "Migrating issuer to did:webvh"
                );
                issuer.did = new_did;
                issuer.key_pair = Some(key_pair);
                issuer.did_document = did_document;
                issuer.updated_at = chrono::Utc::now();

                if let Err(e) = store.update(&issuer).await {
                    errors.push(format!("{}: failed to persist: {}", issuer.id, e));
                } else {
                    migrated += 1;
                }
            }
            Err(e) => {
                errors.push(format!("{}: {}", issuer.id, e));
            }
        }
    }

    info!(migrated = migrated, skipped = skipped, errors = errors.len(), "Issuer did:webvh migration complete");

    Ok(Json(MigrateIssuerWebvhResponse { migrated, skipped, errors }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_manager::pat::PatResourceScope;
    use crate::issuers::filesystem::FileSystemIssuerStore;
    use crate::tenancy::PatTenantContext;
    use regex::Regex;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[test]
    fn issuer_actions_require_tenant_and_scope_access() {
        let mut issuer = Issuer::new(
            "issuer-a".into(),
            "Issuer".into(),
            "did:example:issuer".into(),
            serde_json::json!([]),
            serde_json::json!({}),
        );
        issuer.tenant_id = Some("tenant-a".into());
        let context = PatTenantContext {
            token_id: "token-a".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(Arc::new(Regex::new(r"\ATENANT:tenant-a:issuers:issuer-a\z").unwrap()));

        assert!(issuer_allowed(&issuer, &Some(Extension(context.clone())), &Some(Extension(scope.clone()))));
        issuer.tenant_id = Some("tenant-b".into());
        assert!(!issuer_allowed(&issuer, &Some(Extension(context)), &Some(Extension(scope))));
    }

    async fn test_store() -> (FileSystemIssuerStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let store = FileSystemIssuerStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn test_list_empty() {
        let (store, _dir) = test_store().await;
        let issuers = store
            .list_all()
            .await
            .unwrap();
        assert!(issuers.is_empty());
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let (store, _dir) = test_store().await;
        let issuer = Issuer::new(
            "test-1".to_string(),
            "Engineering".to_string(),
            "did:web:example.com:issuers:test-1".to_string(),
            serde_json::json!([]),
            serde_json::json!({"id": "did:web:example.com:issuers:test-1"}),
        );
        store
            .create(&issuer)
            .await
            .unwrap();

        let fetched = store
            .get(&issuer.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.name, "Engineering");
        assert_eq!(fetched.did, "did:web:example.com:issuers:test-1");
    }

    #[tokio::test]
    async fn test_create_list_delete() {
        let (store, _dir) = test_store().await;
        let issuer = Issuer::new(
            "test-2".to_string(),
            "Marketing".to_string(),
            "did:web:example.com:issuers:test-2".to_string(),
            serde_json::json!([]),
            serde_json::json!({}),
        );
        store
            .create(&issuer)
            .await
            .unwrap();

        let all = store
            .list_all()
            .await
            .unwrap();
        assert_eq!(all.len(), 1);

        store
            .delete(&issuer.id)
            .await
            .unwrap();

        let all = store
            .list_all()
            .await
            .unwrap();
        assert!(all.is_empty());
    }

    #[tokio::test]
    async fn test_update() {
        let (store, _dir) = test_store().await;
        let mut issuer = Issuer::new(
            "test-3".to_string(),
            "Old Name".to_string(),
            "did:web:example.com:issuers:test-3".to_string(),
            serde_json::json!([]),
            serde_json::json!({}),
        );
        store
            .create(&issuer)
            .await
            .unwrap();

        let original_did = issuer.did.clone();
        let original_updated_at = issuer.updated_at;

        issuer.name = "New Name".to_string();
        issuer.updated_at = chrono::Utc::now();
        store
            .update(&issuer)
            .await
            .unwrap();

        let fetched = store
            .get(&issuer.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.name, "New Name");
        assert_eq!(fetched.did, original_did, "DID should not change on update");
        assert!(fetched.updated_at >= original_updated_at);
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let (store, _dir) = test_store().await;
        let result = store
            .get("nonexistent-id")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_issuer_response_excludes_secrets() {
        let issuer = Issuer::new(
            "test-4".to_string(),
            "Test".to_string(),
            "did:web:test".to_string(),
            serde_json::json!(["private_key_data"]),
            serde_json::json!({"id": "did:web:test"}),
        );
        let response = IssuerResponse::from(issuer);
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("secrets").is_none());
        assert!(
            json.get("did_document")
                .is_none()
        );
        assert!(json.get("did").is_some());
        assert!(json.get("name").is_some());
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn test_generate_issuer_identity_webvh() {
        let dir = TempDir::new().unwrap();
        let issuer_id = "test-issuer-webvh";
        let domain = "gateway.example.com";

        let (did, key_pair, did_document) = super::generate_issuer_identity_webvh(issuer_id, domain, dir.path(), None)
            .await
            .expect("generate_issuer_identity_webvh should succeed");

        // DID must be did:webvh format
        assert!(did.starts_with("did:webvh:"), "DID should start with did:webvh:, got: {}", did);
        assert!(did.contains(":issuers:"), "DID should contain :issuers: path segment, got: {}", did);
        assert!(did.ends_with(issuer_id), "DID should end with issuer id, got: {}", did);

        // Key pair must be Ed25519 with both public and private keys
        assert_eq!(key_pair.key_type, "Ed25519");
        assert!(
            key_pair
                .public_key
                .get("d")
                .is_none(),
            "Public key must not contain 'd' field"
        );
        assert!(
            key_pair
                .private_key
                .get("d")
                .is_some(),
            "Private key must contain 'd' field"
        );

        // Parallel did:web document must exist
        assert!(
            did_document
                .get("id")
                .is_some(),
            "DID document must have an id"
        );

        // Birth log must be persisted
        let log_path = dir
            .path()
            .join(issuer_id)
            .join("did.jsonl");
        assert!(log_path.exists(), "did.jsonl birth log must be written to disk");
        let log_content = tokio::fs::read_to_string(&log_path)
            .await
            .unwrap();
        assert!(!log_content.is_empty(), "did.jsonl must not be empty");

        // Parallel did.json must be persisted
        let doc_path = dir
            .path()
            .join(issuer_id)
            .join("did.json");
        assert!(doc_path.exists(), "did.json must be written to disk");

        // Key files must be persisted
        for i in 0..3 {
            let key_path = dir
                .path()
                .join(issuer_id)
                .join(format!("key_{}.json", i));
            assert!(key_path.exists(), "key_{}.json must be written to disk", i);
        }
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn test_generate_issuer_identity_webvh_supports_localhost_port() {
        let dir = TempDir::new().unwrap();
        let issuer_id = "test-issuer-localhost-webvh";

        let (did, _, _) = super::generate_issuer_identity_webvh(issuer_id, "localhost:8443", dir.path(), None)
            .await
            .expect("generate_issuer_identity_webvh should accept localhost domains with ports");

        assert!(did.starts_with("did:webvh:"), "DID should start with did:webvh:, got: {}", did);
        assert!(did.contains(":localhost%3A8443:"), "DID should encode the localhost port, got: {}", did);
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn test_issuer_new_webvh() {
        let key_pair = crate::identity::didwebvh::types::KeyPair {
            public_key: serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "test"}),
            private_key: serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "test", "d": "secret"}),
            key_type: "Ed25519".to_string(),
        };

        let issuer = Issuer::new_webvh(
            "webvh-1".to_string(),
            "WebVH Issuer".to_string(),
            "did:webvh:zScid:example.com:issuers:webvh-1".to_string(),
            key_pair,
            serde_json::json!({"id": "did:web:example.com:issuers:webvh-1"}),
        );

        assert!(
            issuer
                .did
                .starts_with("did:webvh:")
        );
        assert!(issuer.key_pair.is_some());
        assert_eq!(issuer.secrets, serde_json::json!([]));
    }

    #[test]
    fn issuer_artifact_dir_rejects_traversal_and_stays_within_base() {
        let base = TempDir::new().unwrap();
        for id in ["../../etc", "../did.jsonl", "..", ".", "", "/etc/passwd", "a/b", "./x"] {
            assert!(issuer_artifact_dir(base.path(), id).is_err(), "{id:?} must be rejected");
        }

        let id = "123e4567-e89b-12d3-a456-426614174000";
        assert_eq!(issuer_artifact_dir(base.path(), id).unwrap(), base.path().join(id));

        let still_encoded = issuer_artifact_dir(base.path(), "..%2F..%2Fetc").unwrap();
        assert_eq!(still_encoded.parent(), Some(base.path()));
    }
}
