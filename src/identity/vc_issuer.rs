//! Verifiable Credential issuer for agent identities
//!
//! This module handles issuing VCs for agent identities using the Affinidi TDK

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use ssi::jwk::JWK;
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::identity::ssi::vc_issuer::{AgentIdentity, IssueVcPayload, LocalVcIssuer, LocalVcSigner, VcIssuer};
use crate::identity::ssi::verifier::{LocalVerifier, Verifier};
use crate::identity::ssi::vp_issuer::{Credentials, LocalVpIssuer, LocalVpSigner, VpIssuer, VpIssuerPayload};

use super::display_name::{DisplayName, ManagedDisplayName, SurfacesByDidCache, resolve_managed_display_name_in};
use super::filesystem::IdentityOrigin;
use super::{IdentityStore, VpChallengeStore};

const IS_VP_CHALLENGE_REQUIRED_DEFAULT: bool = false;

fn extract_domain_from_proxy_did(proxy_did: &str) -> String {
    crate::identity::utils::extract_domain_from_did(proxy_did)
}

/// Read an issuer key file, transparently decrypting the whole-file `.enc`
/// sibling when encryption at rest is active. Delegates to the shared
/// secret-file helper so issuer keys and every other DID key store share one
/// encryption-at-rest implementation.
async fn read_issuer_file(path: &Path) -> Result<Option<String>> {
    crate::encryption::secret_file::read_secret_file(path).await
}

/// Write an issuer key file. When encryption at rest is active the content is
/// written as a whole-file `.enc` blob and any plaintext sibling is removed, so
/// signing-key material never lingers in plaintext. Delegates to the shared
/// secret-file helper.
async fn write_issuer_file(
    path: &Path,
    contents: &str,
) -> Result<()> {
    crate::encryption::secret_file::write_secret_file(path, contents).await
}

/// Agent Identity Credential Subject Schema
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct AgentIdentityCredentialSubject {
    /// The DID of the agent
    pub id: String,

    /// LLM information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_info: Option<serde_json::Value>,

    /// Software information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_info: Option<serde_json::Value>,

    /// Provisioning information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning_info: Option<serde_json::Value>,

    /// Region
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// VC Issuer configuration
#[derive(Debug, Clone)]
pub struct VCIssuerConfig {
    /// The proxy's DID (did:web)
    pub proxy_did: String,

    /// The proxy's signing key
    pub signing_key: JWK,

    /// Storage path for keys and DIDs
    pub storage_path: PathBuf,

    /// VP challenge is required or no
    pub is_vp_challenge_required: bool,
}

/// Saved issuer configuration
#[derive(Debug, Serialize, Deserialize)]
struct SavedIssuerConfig {
    proxy_did: String,
    signing_key: serde_json::Value,
    #[serde(default)]
    is_vp_challenge_required: bool,
}

/// Response containing agent DID and credential
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentIdentityResponse {
    /// The agent's DID
    pub did: String,

    /// The verifiable credential (JWT format)
    pub credential: String,

    /// Whether this is a newly created DID
    pub is_new: bool,

    /// When the identity was created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// VC Issuer for agent identities
pub struct VCIssuer {
    config: Arc<RwLock<VCIssuerConfig>>,
    identity_store: Arc<dyn IdentityStore>,
    vp_challenge_store: Arc<dyn VpChallengeStore>,
    did_cache: Arc<RwLock<Option<Arc<crate::gateways::did_cache::DIDCache>>>>,
    vc_issuer: Arc<dyn VcIssuer>,
    vp_issuer: Arc<dyn VpIssuer>,
    verifier: Arc<dyn Verifier>,
    issuer_store: Arc<RwLock<Option<Arc<dyn crate::issuers::IssuerStore>>>>,
    tr_listener_manager: Arc<RwLock<Option<Arc<crate::trust_registries::TrustRegistryListenerManager>>>>,
    surface_store: std::sync::OnceLock<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
    surfaces_by_did: SurfacesByDidCache,
    /// The backend that signs the JWT-shaped agent-identity credential
    /// (VTA-11a). Late-bound: the connector is only selected once `[vta]` has
    /// been resolved, which happens after this issuer is constructed. `None`
    /// until then, in which case signing falls back to the local key — which is
    /// also what the local connector does, so the output is identical either
    /// way.
    signing_authority: Arc<RwLock<Option<Arc<dyn crate::identity::authority::CredentialAuthority>>>>,
    /// The backend that issues the **Data-Integrity** agent-identity credential
    /// embedded in the forwarding VP (VTA-11b). Late-bound for the same reason
    /// as `signing_authority`: the VTA connection is resolved after this issuer
    /// is constructed. `None` falls back to `vc_issuer`, the local issuer,
    /// which is the pre-VTA behaviour.
    ///
    /// Separate from `signing_authority` because they sign different artifacts
    /// with different mechanisms — that one mints a JWT, this one a credential
    /// carrying an `eddsa-jcs-2022` proof — and a deployment may move one
    /// without the other.
    di_vc_issuer: Arc<RwLock<Option<Arc<dyn VcIssuer>>>>,

    /// The backend that signs the agent's **presentation** — the holder proof
    /// (VTA-12). Late-bound for the same reason as `di_vc_issuer`.
    ///
    /// Distinct from `di_vc_issuer` because the two proofs are made by
    /// different parties: the credential is signed by the *issuer* (this
    /// gateway's own context), the presentation by the *holder* (the agent's
    /// own context). Collapsing them would mean one key signing as both, which
    /// is the custody problem rather than its fix.
    di_vp_issuer: Arc<RwLock<Option<Arc<dyn VpIssuer>>>>,

    /// Provisions an agent identity whose private key lives in a Verifiable
    /// Trust Agent (VTA-12). When set, a newly onboarded agent gets a
    /// `did:key` backed by a VTA-held key and this process never sees a
    /// private half; when unset, onboarding generates a key as before.
    agent_provisioner: Arc<RwLock<Option<Arc<dyn crate::vta::agent_contexts::AgentKeyProvisioner>>>>,

    /// Signs artifacts whose verifier **resolves the claimed DID** rather than
    /// checking a published JWKS — today the fabric issuer attestation.
    ///
    /// Separate from `signing_authority` because that one claims the trust
    /// agent's DID while signing with a key in the gateway's context. A
    /// verifier that resolves the claimed DID would not find that key there and
    /// would reject the result; one that checks the JWKS is fine with it. So
    /// the two cannot be the same slot.
    attestation_signer: Arc<RwLock<Option<Arc<dyn crate::vta::context_signer::ContextSigner>>>>,

    /// Resolves **which** key signs for a given surface (VTA-19). Late-bound
    /// for the same reason as `signing_authority`.
    ///
    /// Consulted ahead of `signing_authority`, which stays the appliance-wide
    /// answer: a surface that maps nothing resolves the same default and signs
    /// with exactly the key it did before any mapping existed. Without this
    /// the per-surface config parses and validates but never reaches signing,
    /// so a mapping would silently do nothing.
    key_directory: Arc<RwLock<Option<Arc<crate::vta::key_directory::KeyDirectory>>>>,
}

impl VCIssuer {
    pub async fn new(
        storage_path: impl AsRef<std::path::Path>,
        proxy_domain: impl AsRef<str>,
        identity_store: Arc<dyn IdentityStore>,
        vp_challenge_store: Arc<dyn VpChallengeStore>,
        vc_issuer: Option<Arc<dyn VcIssuer>>,
        vp_issuer: Option<Arc<dyn VpIssuer>>,
    ) -> Result<Self> {
        let storage_path = storage_path
            .as_ref()
            .to_path_buf();
        let proxy_domain = proxy_domain
            .as_ref()
            .to_string();

        // Ensure storage directory exists
        tokio::fs::create_dir_all(&storage_path).await?;

        // Load or generate proxy DID and keys
        let config = Self::load_or_create_config(storage_path.clone(), proxy_domain).await?;
        let config = Arc::new(RwLock::new(config));
        let vc_issuer = if let Some(provided_vc_issuer) = vc_issuer {
            provided_vc_issuer
        } else {
            let signer = LocalVcSigner::new(Arc::clone(&config));
            Arc::new(LocalVcIssuer::new(Arc::clone(&config), Arc::new(signer)))
        };

        let vp_issuer = if let Some(provided_vp_issuer) = vp_issuer {
            provided_vp_issuer
        } else {
            Arc::new(LocalVpIssuer::new(Arc::new(LocalVpSigner::new())))
        };

        let resolver_client = crate::gateways::did_cache::shared_resolver().clone();
        let verifier: Arc<dyn Verifier> = Arc::new(LocalVerifier::new(resolver_client));

        Ok(Self {
            config,
            identity_store,
            vp_challenge_store,
            did_cache: Arc::new(RwLock::new(None)),
            vc_issuer,
            vp_issuer,
            verifier,
            issuer_store: Arc::new(RwLock::new(None)),
            tr_listener_manager: Arc::new(RwLock::new(None)),
            surface_store: std::sync::OnceLock::new(),
            surfaces_by_did: SurfacesByDidCache::default(),
            signing_authority: Arc::new(RwLock::new(None)),
            di_vc_issuer: Arc::new(RwLock::new(None)),
            di_vp_issuer: Arc::new(RwLock::new(None)),
            agent_provisioner: Arc::new(RwLock::new(None)),
            attestation_signer: Arc::new(RwLock::new(None)),
            key_directory: Arc::new(RwLock::new(None)),
        })
    }

    /// Use `store` instead of the process-global agent-surface store for VC names.
    #[cfg(test)]
    pub fn set_surface_store(
        &self,
        store: Arc<dyn crate::surfaces::AgentSurfaceStore>,
    ) {
        let _ = self.surface_store.set(store);
    }

    fn surface_store(&self) -> Option<Arc<dyn crate::surfaces::AgentSurfaceStore>> {
        self.surface_store
            .get()
            .cloned()
            .or_else(crate::gateways::connection_points::get_agent_surface_store)
    }

    /// Point agent-identity credential signing at the selected signing
    /// connector (VTA-11a). Called from the identity router once `[vta]` has
    /// been resolved, so the credential returned by `issue_or_get_credential`
    /// is signed by the same backend as STS tokens and payment receipts.
    pub async fn set_signing_authority(
        &self,
        authority: Arc<dyn crate::identity::authority::CredentialAuthority>,
    ) {
        let mut slot = self
            .signing_authority
            .write()
            .await;
        *slot = Some(authority);
    }

    /// Install the directory that decides which key signs for which surface
    /// (VTA-19). Called from the identity router once `[vta]`, the connection
    /// registry and the surface mappings have all been resolved.
    pub async fn set_key_directory(
        &self,
        directory: Arc<crate::vta::key_directory::KeyDirectory>,
    ) {
        let mut slot = self
            .key_directory
            .write()
            .await;
        *slot = Some(directory);
    }

    /// The authority that should sign for `surface_id`.
    ///
    /// Falls back to the appliance-wide `signing_authority` whenever the
    /// directory cannot answer — no directory installed, no surface in scope,
    /// or a resolution failure. A surface that maps nothing therefore keeps
    /// signing with exactly the key it used before, which is what makes
    /// installing the directory a no-op for every existing deployment.
    ///
    /// A resolution **failure** is logged and falls back rather than failing
    /// the request: the mapping was already validated at startup, so a failure
    /// here is a transient backend problem, and refusing to issue an identity
    /// because an optional override is unreachable would take the surface down
    /// over something it worked without yesterday.
    async fn authority_for_surface(
        &self,
        surface_id: Option<&str>,
    ) -> Option<Arc<dyn crate::identity::authority::CredentialAuthority>> {
        let appliance = self
            .signing_authority
            .read()
            .await
            .clone();
        // Consulted whenever a directory is installed, **with or without a
        // surface**. An appliance-wide default is by definition what applies
        // when nothing more specific does, so requiring a surface here skipped
        // it for every caller that has none — `/v1/identity/issue` among them,
        // which then signed locally while the dashboard reported the agent.
        let Some(directory) = self
            .key_directory
            .read()
            .await
            .clone()
        else {
            return appliance;
        };

        let scope = match surface_id {
            Some(surface_id) => crate::vta::key_directory::KeyScope::surface(surface_id),
            None => crate::vta::key_directory::KeyScope::default(),
        };
        let purpose = crate::config::vta::KeyPurpose::Jwt;
        let resolved = match directory
            .resolve_and_provision(purpose, &scope)
            .await
        {
            Ok(key_ref) => {
                directory
                    .authority_for(&key_ref, purpose)
                    .await
            }
            Err(e) => Err(e),
        };
        match resolved {
            Ok(authority) => Some(authority),
            Err(e) => {
                warn!(
                    target: "vta_audit",
                    surface_id = surface_id.unwrap_or("<appliance-wide>"),
                    error = %e.log_detail(),
                    "signing key could not be resolved; falling back to the appliance key",
                );
                appliance
            }
        }
    }

    /// Point the Data-Integrity agent-identity credential at a VTA-backed
    /// issuer (VTA-11b). Called from the identity router once `[vta]` has been
    /// resolved.
    ///
    /// Once set there is no fallback to the local issuer: a credential signed
    /// by a key the operator has moved away from is not an acceptable
    /// substitute for one that failed to issue.
    pub async fn set_di_vc_issuer(
        &self,
        issuer: Arc<dyn VcIssuer>,
    ) {
        let mut slot = self
            .di_vc_issuer
            .write()
            .await;
        *slot = Some(issuer);
    }

    /// The in-process credential issuer, for wrapping in a delegate that
    /// falls back to it.
    ///
    /// Exposed so a dashboard-driven issuer can keep local signing as its
    /// fallback without rebuilding one — a second `LocalVcIssuer` would read
    /// the same config but be a different object, and divergence there would
    /// be invisible until a credential verified against the wrong key.
    pub fn local_vc_issuer(&self) -> Arc<dyn VcIssuer> {
        Arc::clone(&self.vc_issuer)
    }

    /// Point the agent's **holder proof** at a VTA-backed issuer (VTA-12), so
    /// the agent's private key lives in its own trust agent rather than in
    /// this process.
    ///
    /// The VTA issuer decides per agent: one that has a VTA context is signed
    /// there, one onboarded before the migration still has a gateway-held key
    /// and is signed locally. That is what makes the migration gradual rather
    /// than a flag day.
    pub async fn set_di_vp_issuer(
        &self,
        issuer: Arc<dyn VpIssuer>,
    ) {
        let mut slot = self
            .di_vp_issuer
            .write()
            .await;
        *slot = Some(issuer);
    }

    /// Onboard new agents with a key held in their own VTA context (VTA-12)
    /// rather than one generated here.
    ///
    /// Only affects agents onboarded from now on. Existing records keep their
    /// gateway-held key and keep working — rewriting them would change every
    /// agent's DID, invalidating credentials already issued to them and any
    /// trust-registry record that names them.
    pub async fn set_agent_provisioner(
        &self,
        provisioner: Arc<dyn crate::vta::agent_contexts::AgentKeyProvisioner>,
    ) {
        let mut slot = self
            .agent_provisioner
            .write()
            .await;
        *slot = Some(provisioner);
    }

    /// Set the DID cache for this issuer (for caching DID resolution during VP verification)
    pub async fn set_did_cache(
        &self,
        did_cache: Arc<crate::gateways::did_cache::DIDCache>,
    ) {
        let mut cache = self.did_cache.write().await;
        *cache = Some(did_cache);
        info!("DID cache initialized");
    }

    /// Set the issuer store and TR listener manager for agent TR registration
    pub async fn set_trust_registry_deps(
        &self,
        issuer_store: Arc<dyn crate::issuers::IssuerStore>,
        tr_listener_manager: Arc<crate::trust_registries::TrustRegistryListenerManager>,
    ) {
        let mut ds = self
            .issuer_store
            .write()
            .await;
        *ds = Some(issuer_store);
        let mut tr = self
            .tr_listener_manager
            .write()
            .await;
        *tr = Some(tr_listener_manager);
        info!("Trust registry deps initialized for agent DID registration");
    }

    /// Get a reference to the identity store
    pub fn get_identity_store(&self) -> Arc<dyn IdentityStore> {
        Arc::clone(&self.identity_store)
    }

    /// Get a VC signer that can sign arbitrary VC payloads with the gateway's Ed25519 key
    pub fn get_vc_signer(&self) -> Arc<dyn crate::identity::ssi::vc_issuer::VcSigner> {
        Arc::new(LocalVcSigner::new(Arc::clone(&self.config)))
    }

    /// Get the storage path used by the VC issuer (contains `did.json`, `did.jsonl`, keys)
    pub async fn get_storage_path(&self) -> std::path::PathBuf {
        self.config
            .read()
            .await
            .storage_path
            .clone()
    }

    /// Resolve an issuer by its UUID.
    /// Returns `None` if the issuer store is not configured or the issuer is not found.
    #[allow(dead_code)]
    pub async fn resolve_issuer_by_id(
        &self,
        issuer_id: &str,
    ) -> Option<crate::issuers::types::Issuer> {
        let guard = self.issuer_store.read().await;
        let store = guard.as_ref()?;
        match store.get(issuer_id).await {
            Ok(issuer) => issuer,
            Err(e) => {
                tracing::warn!(issuer_id, error = %e, "Failed to look up issuer by ID");
                None
            }
        }
    }

    /// Get the issuer DID
    pub async fn get_issuer_did(&self) -> Result<String> {
        let config = self.config.read().await;
        Ok(config.proxy_did.clone())
    }

    /// The gateway's public JWKS (Ed25519 signing key, private `d` component
    /// stripped). Lets a standard OAuth resource server verify STS-issued tokens
    /// via a `jwks_uri` without resolving the gateway DID document.
    pub async fn signing_public_jwks(&self) -> Result<serde_json::Value> {
        let config = self.config.read().await;
        let mut jwk = serde_json::to_value(&config.signing_key)?;
        if let Some(obj) = jwk.as_object_mut() {
            obj.remove("d");
            obj.entry("use".to_string())
                .or_insert_with(|| json!("sig"));
            obj.entry("alg".to_string())
                .or_insert_with(|| json!("EdDSA"));
            // Ensure a `kid` is present and matches the default the JWS header
            // carries when the signing key has no explicit key id (`sign_jwt`
            // falls back to `"key-1"`), so a resource server can select the key.
            obj.entry("kid".to_string())
                .or_insert_with(|| json!("key-1"));
        }
        Ok(json!({ "keys": [jwk] }))
    }

    /// Get the signing keys as Secrets for DID authentication
    /// Returns Ed25519 (authentication), X25519 (keyAgreement), and P-256 (keyAgreement)
    /// This is used for self gateway OOB invitation creation
    pub async fn get_signing_secrets(&self) -> Result<Vec<affinidi_tdk_common::secrets_resolver::secrets::Secret>> {
        let config = self.config.read().await;

        // Ed25519 secret for authentication/signing
        let ed25519_key_id = format!("{}#key-1", config.proxy_did);
        let ed25519_secret: affinidi_tdk_common::secrets_resolver::secrets::Secret =
            serde_json::from_value(serde_json::json!({
                "id": ed25519_key_id,
                "type": "JsonWebKey2020",
                "privateKeyJwk": config.signing_key
            }))?;

        let mut secrets = vec![ed25519_secret];

        // X25519 secret for keyAgreement (DIDComm encryption)
        let x25519_key_path = config
            .storage_path
            .join("x25519_key.json");
        if let Some(content) = read_issuer_file(&x25519_key_path).await? {
            let x25519_secret = serde_json::from_str(&content)?;
            secrets.push(x25519_secret);
        }

        // P-256 secret for keyAgreement (compatible with Affinidi mediator)
        let p256_key_path = config
            .storage_path
            .join("p256_key.json");
        if let Some(content) = read_issuer_file(&p256_key_path).await? {
            let p256_secret = serde_json::from_str(&content)?;
            secrets.push(p256_secret);
        }

        Ok(secrets)
    }

    /// Get the signing key as a Secret for DID authentication (deprecated, use get_signing_secrets)
    /// This is used for self gateway OOB invitation creation
    #[allow(dead_code)]
    pub async fn get_signing_secret(&self) -> Result<affinidi_tdk_common::secrets_resolver::secrets::Secret> {
        let secrets = self
            .get_signing_secrets()
            .await?;
        Ok(secrets
            .into_iter()
            .next()
            .unwrap())
    }

    /// Get the DID document for the proxy/gateway
    /// This is used to cache the DID document in the resolver
    pub async fn get_did_document(&self) -> Result<serde_json::Value> {
        let config = self.config.read().await;
        if let Some(content) = crate::storage::did_artifacts::read_did_document(&config.storage_path).await? {
            Ok(serde_json::from_str(&content)?)
        } else {
            use crate::identity::ssi::did_utils::jwk_to_multibase_ed25519;

            let domain = extract_domain_from_proxy_did(&config.proxy_did);

            let public_key_multibase = jwk_to_multibase_ed25519(&config.signing_key)?;

            let x25519_key_path = config
                .storage_path
                .join("x25519_key.json");
            let p256_key_path = config
                .storage_path
                .join("p256_key.json");

            let (x25519_key_id, x25519_public_jwk) = if let Some(content) = read_issuer_file(&x25519_key_path).await? {
                let secret: affinidi_tdk_common::secrets_resolver::secrets::Secret = serde_json::from_str(&content)?;
                let key_id = secret.id.clone();
                let public_jwk = if let affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial::JWK(jwk) =
                    &secret.secret_material
                {
                    let mut public_jwk = serde_json::to_value(jwk)?;
                    if let Some(obj) = public_jwk.as_object_mut() {
                        obj.remove("d");
                    }
                    public_jwk
                } else {
                    return Err(anyhow::anyhow!("X25519 secret is not a JWK"));
                };
                (key_id, public_jwk)
            } else {
                let key_id = format!("{}#key-x25519-1", config.proxy_did);
                (key_id, serde_json::json!({}))
            };

            let (p256_key_id, p256_public_jwk) = if let Some(content) = read_issuer_file(&p256_key_path).await? {
                let secret: affinidi_tdk_common::secrets_resolver::secrets::Secret = serde_json::from_str(&content)?;
                let key_id = secret.id.clone();
                let public_jwk = if let affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial::JWK(jwk) =
                    &secret.secret_material
                {
                    let mut public_jwk = serde_json::to_value(jwk)?;
                    if let Some(obj) = public_jwk.as_object_mut() {
                        obj.remove("d");
                    }
                    public_jwk
                } else {
                    return Err(anyhow::anyhow!("P-256 secret is not a JWK"));
                };
                (key_id, public_jwk)
            } else {
                let key_id = format!("{}#key-p256-1", config.proxy_did);
                (key_id, serde_json::json!({}))
            };

            // Include both JsonWebKey2020 (#key-1) and Multikey (#key-2) formats
            // VP signatures use EdDsaRdfc2022 cryptosuite which expects Multikey format
            Ok(serde_json::json!({
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1",
                    "https://w3id.org/security/multikey/v1"
                ],
                "id": config.proxy_did,
                "verificationMethod": [
                    {
                        "id": format!("{}#key-1", config.proxy_did),
                        "type": "JsonWebKey2020",
                        "controller": config.proxy_did,
                        "publicKeyJwk": config.signing_key.to_public()
                    },
                    {
                        "id": format!("{}#key-2", config.proxy_did),
                        "type": "Multikey",
                        "controller": config.proxy_did,
                        "publicKeyMultibase": public_key_multibase
                    },
                    {
                        "id": &x25519_key_id,
                        "type": "JsonWebKey2020",
                        "controller": config.proxy_did,
                        "publicKeyJwk": x25519_public_jwk
                    },
                    {
                        "id": &p256_key_id,
                        "type": "JsonWebKey2020",
                        "controller": config.proxy_did,
                        "publicKeyJwk": p256_public_jwk
                    }
                ],
                "authentication": [format!("{}#key-1", config.proxy_did)],
                "assertionMethod": [
                    format!("{}#key-1", config.proxy_did),
                    format!("{}#key-2", config.proxy_did)
                ],
                "keyAgreement": [&x25519_key_id, &p256_key_id],
                "service": [{
                    "id": format!("{}#didcomm", config.proxy_did),
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{
                        "uri": format!("https://{}/didcomm", domain),
                        "accept": ["didcomm/v2"],
                        "routingKeys": []
                    }]
                }]
            }))
        }
    }

    /// Migrate the gateway `proxy_did` from `did:web:` to `did:webvh:` on first boot after upgrade.
    ///
    /// Delegates to `create_webvh_did` (the same spec-compliant helper used by
    /// channels and trust-registries) and persists the birth log to
    /// `{storage_path}/did.jsonl`.  Returns the new canonical `did:webvh` DID.
    ///
    /// This function is **idempotent**: if `did.jsonl` already exists it reads the
    /// SCID from the first line and returns the corresponding DID without touching
    /// any file.
    ///
    #[cfg(feature = "didwebvh")]
    async fn migrate_proxy_did_to_webvh(
        storage_path: &std::path::Path,
        proxy_did: &str,
        signing_key: &JWK,
    ) -> Result<String> {
        use crate::identity::didwebvh::create::create_webvh_did;
        use crate::identity::didwebvh::types::LogEntry;

        let domain_encoded = proxy_did
            .strip_prefix("did:web:")
            .unwrap_or(proxy_did);

        // Idempotent: already migrated — read SCID from existing log.
        // Only reuse if the SCID is non-empty (guard against the old bug where scid was "").
        if let Some(content) = crate::storage::did_artifacts::read_did_log_raw(storage_path).await?
            && let Some(first_line) = content.lines().next()
        {
            let entry: LogEntry = serde_json::from_str(first_line)?;
            let scid = entry.parameters.scid.clone();
            if !scid.is_empty() {
                return Ok(format!("did:webvh:{}:{}", scid, domain_encoded));
            }
            info!("Gateway did.jsonl has empty SCID (old format), regenerating");
        }

        // Read existing did.json as raw JSON (not via DidDocument/url::Url which
        // would percent-encode placeholders and break SCID substitution).
        let did_json_content = crate::storage::did_artifacts::read_did_document(storage_path)
            .await?
            .context("did.json not found; ensure the gateway has started at least once before upgrading")?;

        // Replace old did:web: prefix with {SCID} placeholder at the raw JSON string level,
        // preserving all fields (including @context which DidDocument/url::Url may mangle).
        let placeholder_did = format!("did:webvh:{{SCID}}:{}", domain_encoded);
        let placeholder_json = did_json_content.replace(proxy_did, &placeholder_did);
        let did_doc_value: serde_json::Value =
            serde_json::from_str(&placeholder_json).context("Failed to parse did.json for webvh migration")?;

        // Extract the Ed25519 private key as a JSON value for the didwebvh_rs helper.
        let private_jwk = serde_json::to_value(signing_key)?;

        // Derive the base URL from the domain-encoded portion of the did:web
        let domain = domain_encoded.replace("%3A", ":");
        let base_url = crate::identity::didwebvh::base_url_for_domain(&domain);

        let result = create_webvh_did(&private_jwk, did_doc_value, &base_url).await?;

        // Persist birth log
        crate::storage::did_artifacts::write_did_log_raw(storage_path, &result.log_entry_json).await?;

        // Update did.json to serve as the parallel did:web document
        let state_json = serde_json::to_string(&result.signed_entry.state)?;
        let state_value: serde_json::Value = serde_json::from_str(&state_json)?;
        let parallel_doc =
            crate::identity::didwebvh::generate_parallel_did_web(&state_value, &result.final_did, &result.scid);
        let parallel_json = serde_json::to_string_pretty(&parallel_doc)?;
        crate::storage::did_artifacts::write_did_document(storage_path, &parallel_json).await?;

        info!("Gateway proxy_did migrated: {} → {}", proxy_did, result.final_did);
        Ok(result.final_did)
    }

    #[cfg(feature = "didwebvh")]
    async fn update_didcomm_key_ids(
        storage_path: &std::path::Path,
        old_did: &str,
        new_did: &str,
    ) {
        for filename in &["x25519_key.json", "p256_key.json"] {
            let path = storage_path.join(filename);
            match read_issuer_file(&path).await {
                Ok(Some(content)) => {
                    let updated = content.replace(old_did, new_did);
                    if updated != content
                        && let Err(e) = write_issuer_file(&path, &updated).await
                    {
                        warn!("Failed to update key ID in {}: {}", filename, e);
                    }
                }
                Ok(None) => {}
                Err(e) => warn!("Failed to read key file {} for key-ID update: {}", filename, e),
            }
        }
    }

    /// Load existing config or create new one
    async fn load_or_create_config(
        storage_path: PathBuf,
        proxy_domain: String,
    ) -> Result<VCIssuerConfig> {
        let config_path = storage_path.join("issuer_config.json");

        let (key, proxy_did, is_vp_challenge_required, is_new_config) =
            if let Some(content) = read_issuer_file(&config_path).await? {
                // Load existing config
                let saved: SavedIssuerConfig = serde_json::from_str(&content)?;

                (serde_json::from_value(saved.signing_key)?, saved.proxy_did, saved.is_vp_challenge_required, false)
            } else {
                // Generate new key pair
                let key = JWK::generate_ed25519().context("Failed to generate Ed25519 key")?;

                // Create did:web DID
                let proxy_did = format!("did:web:{}", proxy_domain.replace(":", "%3A"));

                (key, proxy_did, IS_VP_CHALLENGE_REQUIRED_DEFAULT, true)
            };

        // Save config if it's new
        if is_new_config {
            let saved = SavedIssuerConfig {
                proxy_did: proxy_did.clone(),
                signing_key: serde_json::to_value(&key)?,
                is_vp_challenge_required: IS_VP_CHALLENGE_REQUIRED_DEFAULT,
            };

            let content = serde_json::to_string_pretty(&saved)?;
            write_issuer_file(&config_path, &content).await?;
        }

        // Generate or load X25519 and P-256 keys for DIDComm keyAgreement
        let x25519_key_path = storage_path.join("x25519_key.json");
        let existing_x25519 = read_issuer_file(&x25519_key_path).await?;
        let x25519_existed = existing_x25519.is_some();
        let x25519_secret = if let Some(content) = existing_x25519 {
            // Load existing X25519 key
            serde_json::from_str(&content)?
        } else {
            // Generate new X25519 key using Affinidi SDK
            let x25519_key_id = format!("{}#key-x25519-1", proxy_did);
            let secret =
                affinidi_tdk_common::secrets_resolver::secrets::Secret::generate_x25519(Some(&x25519_key_id), None)?;

            // Save to file
            let x25519_json = serde_json::to_string_pretty(&secret)?;
            write_issuer_file(&x25519_key_path, &x25519_json).await?;

            secret
        };

        let p256_key_path = storage_path.join("p256_key.json");
        let existing_p256 = read_issuer_file(&p256_key_path).await?;
        let p256_existed = existing_p256.is_some();
        let p256_secret = if let Some(content) = existing_p256 {
            // Load existing P-256 key
            serde_json::from_str(&content)?
        } else {
            // Generate new P-256 key using Affinidi SDK
            let p256_key_id = format!("{}#key-p256-1", proxy_did);
            let secret =
                affinidi_tdk_common::secrets_resolver::secrets::Secret::generate_p256(Some(&p256_key_id), None)?;

            // Save to file
            let p256_json = serde_json::to_string_pretty(&secret)?;
            write_issuer_file(&p256_key_path, &p256_json).await?;

            secret
        };

        // Extract public keys from the secrets for the DID document
        let x25519_key_id = x25519_secret.id.clone();
        let x25519_public_jwk = if let affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial::JWK(jwk) =
            &x25519_secret.secret_material
        {
            // Create public-only version (without 'd' parameter)
            let mut public_jwk = serde_json::to_value(jwk)?;
            if let Some(obj) = public_jwk.as_object_mut() {
                obj.remove("d");
            }
            public_jwk
        } else {
            return Err(anyhow::anyhow!("X25519 secret is not a JWK"));
        };

        let p256_key_id = p256_secret.id.clone();
        let p256_public_jwk = if let affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial::JWK(jwk) =
            &p256_secret.secret_material
        {
            // Create public-only version (without 'd' parameter)
            let mut public_jwk = serde_json::to_value(jwk)?;
            if let Some(obj) = public_jwk.as_object_mut() {
                obj.remove("d");
            }
            public_jwk
        } else {
            return Err(anyhow::anyhow!("P-256 secret is not a JWK"));
        };

        // Generate or update the DID document
        let did_doc_path = storage_path.join("did.json");

        // Only regenerate DID document if it doesn't exist or if we created new keys
        let should_update_did_doc = !did_doc_path.exists() || is_new_config || !x25519_existed || !p256_existed;

        if should_update_did_doc {
            use crate::identity::ssi::did_utils::jwk_to_multibase_ed25519;

            let domain = extract_domain_from_proxy_did(&proxy_did);

            let public_key_multibase = jwk_to_multibase_ed25519(&key)?;

            let did_doc = json!({
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/suites/jws-2020/v1",
                    "https://w3id.org/security/multikey/v1"
                ],
                "id": proxy_did,
                "verificationMethod": [
                    {
                        "id": format!("{}#key-1", proxy_did),
                        "type": "JsonWebKey2020",
                        "controller": proxy_did,
                        "publicKeyJwk": key.to_public()
                    },
                    {
                        "id": format!("{}#key-2", proxy_did),
                        "type": "Multikey",
                        "controller": proxy_did,
                        "publicKeyMultibase": public_key_multibase
                    },
                    {
                        "id": &x25519_key_id,
                        "type": "JsonWebKey2020",
                        "controller": proxy_did,
                        "publicKeyJwk": x25519_public_jwk
                    },
                    {
                        "id": &p256_key_id,
                        "type": "JsonWebKey2020",
                        "controller": proxy_did,
                        "publicKeyJwk": p256_public_jwk
                    }
                ],
                "authentication": [format!("{}#key-1", proxy_did)],
                "assertionMethod": [format!("{}#key-1", proxy_did)],
                "keyAgreement": [&x25519_key_id, &p256_key_id],
                "service": [{
                    "id": format!("{}#didcomm", proxy_did),
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": [{
                        "uri": format!("https://{}/didcomm", domain),
                        "accept": ["didcomm/v2"],
                        "routingKeys": []
                    }]
                }]
            });

            let did_doc_json = serde_json::to_string_pretty(&did_doc)?;
            crate::storage::did_artifacts::write_did_document(&storage_path, &did_doc_json).await?;
        }

        // Create or migrate proxy_did to did:webvh.
        // Runs on first boot (new config) and on subsequent boots if still did:web: (legacy upgrade path).
        #[cfg(feature = "didwebvh")]
        let proxy_did = if proxy_did.starts_with("did:web:") {
            match Self::migrate_proxy_did_to_webvh(&storage_path, &proxy_did, &key).await {
                Ok(new_did) => {
                    // Persist the new DID back to issuer_config.json
                    let saved = SavedIssuerConfig {
                        proxy_did: new_did.clone(),
                        signing_key: serde_json::to_value(&key)?,
                        is_vp_challenge_required,
                    };
                    write_issuer_file(&config_path, &serde_json::to_string_pretty(&saved)?).await?;

                    // Update DIDComm key IDs from old did:web to new did:webvh
                    Self::update_didcomm_key_ids(&storage_path, &proxy_did, &new_did).await;

                    new_did
                }
                Err(e) => {
                    warn!("Gateway DID webvh migration skipped: {}", e);
                    proxy_did
                }
            }
        } else {
            proxy_did
        };

        Ok(VCIssuerConfig {
            proxy_did,
            signing_key: key,
            storage_path,
            is_vp_challenge_required,
        })
    }

    /// Issue a VC for an agent identity, or return existing DID if already issued
    ///
    /// If identity_hash is provided, it will be used directly (preferred).
    /// Otherwise, the hash will be computed from the identity_fields.
    pub async fn issue_or_get_credential(
        &self,
        identity_fields: std::collections::HashMap<String, serde_json::Value>,
        identity_hash: Option<String>,
        channel_config_id: Option<String>,
        issuer_id: Option<String>,
    ) -> Result<AgentIdentityResponse> {
        self.issue_or_get_credential_with_origin(identity_fields, identity_hash, channel_config_id, issuer_id, None)
            .await
    }

    /// [`Self::issue_or_get_credential`] for the managed agent of `channel_config_id`:
    /// records the identity as managed and names the VC with its managed display name.
    pub async fn issue_or_get_managed_credential(
        &self,
        identity_fields: std::collections::HashMap<String, serde_json::Value>,
        identity_hash: Option<String>,
        channel_config_id: Option<String>,
        issuer_id: Option<String>,
    ) -> Result<AgentIdentityResponse> {
        self.issue_or_get_credential_with_origin(
            identity_fields,
            identity_hash,
            channel_config_id,
            issuer_id,
            Some(IdentityOrigin::Managed),
        )
        .await
    }

    /// [`Self::issue_or_get_credential`] for a caller reaching the surface: records
    /// the identity as an external caller. The VC carries no name.
    pub async fn issue_or_get_caller_credential(
        &self,
        identity_fields: std::collections::HashMap<String, serde_json::Value>,
        identity_hash: Option<String>,
        channel_config_id: Option<String>,
        issuer_id: Option<String>,
    ) -> Result<AgentIdentityResponse> {
        self.issue_or_get_credential_with_origin(
            identity_fields,
            identity_hash,
            channel_config_id,
            issuer_id,
            Some(IdentityOrigin::ExternalCaller),
        )
        .await
    }

    async fn issue_or_get_credential_with_origin(
        &self,
        identity_fields: std::collections::HashMap<String, serde_json::Value>,
        identity_hash: Option<String>,
        channel_config_id: Option<String>,
        issuer_id: Option<String>,
        origin: Option<IdentityOrigin>,
    ) -> Result<AgentIdentityResponse> {
        info!(
            "[TR-TRACE] issue_or_get_credential called: channel_config_id={:?}, issuer_id={:?}, identity_hash={:?}, field_count={}",
            channel_config_id,
            issuer_id,
            identity_hash,
            identity_fields.len()
        );
        // Use provided hash or calculate from the identity fields
        let identity_hash = identity_hash.unwrap_or_else(|| {
            let fields_json = serde_json::to_value(&identity_fields).unwrap_or_default();
            crate::identity::calculate_identity_hash(&fields_json)
        });

        // Check if we already have a DID for this identity
        if let Some(record) = self
            .identity_store
            .find_by_hash(&identity_hash)
            .await?
        {
            info!("[TR-TRACE] Identity ALREADY EXISTS for hash={}, did={}", identity_hash, record.did);
            // Update usage tracking with the current channel
            self.identity_store
                .update_usage(&identity_hash, channel_config_id.clone())
                .await?;

            let effective_origin = match (record.origin, origin) {
                (None, Some(requested)) => {
                    if let Err(e) = self
                        .identity_store
                        .set_origin(&identity_hash, requested)
                        .await
                    {
                        warn!(identity_hash = %identity_hash, error = %e, "Failed to record identity origin (non-fatal)");
                    }
                    Some(requested)
                }
                (existing, _) => existing,
            };
            let name = self
                .managed_display_name(&record.did, effective_origin, channel_config_id.as_deref())
                .await;

            // Return existing DID and generate a fresh VC
            let vc = self
                .create_credential(&record.did, &identity_fields, name.as_ref(), channel_config_id.as_deref())
                .await?;

            return Ok(AgentIdentityResponse {
                did: record.did,
                credential: vc.to_string(),
                is_new: false,
                created_at: record.created_at,
            });
        }

        // Generate new did:webvh DID for this agent
        let provisioned = match self
            .agent_provisioner
            .read()
            .await
            .as_ref()
        {
            Some(provisioner) if provisioner.available() => match provisioner
                .provision(&identity_hash)
                .await
            {
                Ok(provisioned) => Some(provisioned),
                // An inferred provisioner may simply lack the grant to create
                // contexts, which cannot be known before trying. Falling back
                // to the key this would have minted anyway keeps onboarding
                // working; an explicitly configured one still fails, because
                // the operator asked for the stronger guarantee.
                Err(e) if provisioner.optional() => {
                    warn!(
                        target: "vta_audit",
                        error = %e,
                        "could not mint this agent's key in the trust agent; \
                         falling back to a gateway-held key",
                    );
                    None
                }
                Err(e) => return Err(e),
            },
            // No provisioner, or no trust agent configured for it to use: the
            // gateway mints the key, exactly as it always did.
            _ => None,
        };

        let (agent_did, mut record) = match provisioned {
            // The agent's key is minted inside its own VTA context and the DID
            // follows from it, so no private half ever exists on this host.
            Some(provisioned) => {
                let record = crate::identity::AgentIdentityRecord {
                    did: provisioned.did.clone(),
                    identity_hash: identity_hash.clone(),
                    created_at: chrono::Utc::now(),
                    identity_fields: std::collections::HashMap::new(),
                    usage_count: 0,
                    last_used_at: None,
                    channel_usage: vec![],
                    private_key: None,
                    vta_context_id: Some(provisioned.context_id),
                    vta_connection_id: Some(provisioned.connection_id),
                    channel_config_id: None,
                    is_local: true,
                    verified: true,
                    // Provisioned through onboarding, so this is a managed
                    // agent rather than an external caller.
                    origin: Some(crate::identity::IdentityOrigin::Managed),
                };
                (provisioned.did, record)
            }
            None => {
                crate::vault_identity::handlers::generate_did_webvh_identity(
                    self,
                    "surface",
                    Some(format!(
                        "Surface: {}",
                        channel_config_id
                            .as_deref()
                            .unwrap_or("unknown")
                    )),
                )
                .await?
            }
        };

        let name = self
            .managed_display_name(&agent_did, origin, channel_config_id.as_deref())
            .await;
        let vc = self
            .create_credential(&agent_did, &identity_fields, name.as_ref(), channel_config_id.as_deref())
            .await?;

        // Update the record with the actual identity_hash and fields before storing
        record.identity_hash = identity_hash.clone();
        record.identity_fields = identity_fields;
        record.channel_config_id = channel_config_id.clone();
        record.origin = origin;
        let created_at = record.created_at;
        let channel_config_id_for_usage = channel_config_id;
        let _ = issuer_id; // no-op: agent-in-TR writes are owned by Trust Recorder now

        // Store the record once with the correct identity_hash
        self.identity_store
            .create(record)
            .await?;

        // Treat the very call that triggered creation as the first usage,
        // so the dashboard shows usage_count=1 / last_used_at instead of
        // an unused record. Without this, the first request silently
        // creates the identity but it appears as "Unused" until a second
        // call exercises the existing-record branch above.
        if let Err(e) = self
            .identity_store
            .update_usage(&identity_hash, channel_config_id_for_usage)
            .await
        {
            warn!(
                agent_did = %agent_did,
                identity_hash = %identity_hash,
                error = %e,
                "Failed to record initial usage for newly created identity (non-fatal)"
            );
        }

        Ok(AgentIdentityResponse {
            did: agent_did,
            credential: vc.to_string(),
            is_new: true,
            created_at,
        })
    }

    /// Display name `surface_id` gives its managed agent `agent_did`; `None` when the
    /// surface or the identity list is unavailable.
    pub async fn surface_display_name(
        &self,
        agent_did: &str,
        surface_id: &str,
    ) -> Option<ManagedDisplayName> {
        let surface_store = self.surface_store()?;
        resolve_managed_display_name_in(
            surface_store.as_ref(),
            agent_did,
            surface_id,
            self.identity_store.as_ref(),
            &self.surfaces_by_did,
        )
        .await
    }

    /// Display name for a managed identity (its surface name); `None` for callers, unknown origins, unnamed agents and DIDs shared by
    /// several surfaces.
    async fn managed_display_name(
        &self,
        agent_did: &str,
        origin: Option<IdentityOrigin>,
        surface_id: Option<&str>,
    ) -> Option<DisplayName> {
        if origin != Some(IdentityOrigin::Managed) {
            return None;
        }
        self.surface_display_name(agent_did, surface_id?)
            .await?
            .publishable(agent_did)
            .cloned()
    }

    async fn display_name_for_did(
        &self,
        agent_did: &str,
    ) -> Option<DisplayName> {
        let record = match self
            .identity_store
            .find_by_did(agent_did)
            .await
        {
            Ok(record) => record?,
            Err(e) => {
                warn!(agent_did, error = %e, "Identity lookup for VC name failed (non-fatal)");
                return None;
            }
        };
        self.managed_display_name(
            agent_did,
            record.origin,
            record
                .channel_config_id
                .as_deref(),
        )
        .await
    }

    /// Create a verifiable credential for an agent identity
    async fn create_credential(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
        name: Option<&DisplayName>,
        surface_id: Option<&str>,
    ) -> Result<String> {
        // The backend that will sign, if one has been selected (VTA-11a),
        // narrowed to this surface's own key when one is mapped (VTA-19).
        let authority = self
            .authority_for_surface(surface_id)
            .await;

        // Clone what signing needs and release the config lock before any
        // `.await` on the authority — the local connector re-enters this same
        // `RwLock` to read the signing key, and tokio's write-preferring lock
        // would deadlock on a reentrant read if a writer were queued.
        let (local_signing_key, local_issuer_did) = {
            let config = self.config.read().await;
            (config.signing_key.clone(), config.proxy_did.clone())
        };

        // The `issuer` claim must name whoever actually holds the signing key,
        // otherwise the credential cannot be verified against the published
        // JWKS. Fail closed rather than falling back to the local DID: a
        // credential attributed to the wrong issuer is worse than none.
        let issuer_did = match authority.as_ref() {
            Some(authority) => authority.issuer_did().await?,
            None => local_issuer_did,
        };

        // Convert identity fields to JSON for credential
        let identity_json = serde_json::to_value(identity_fields).context("Failed to serialize identity fields")?;

        // Create credential subject with identity fields
        // The public key can be resolved from the channel's DID document at /channel/{id}/did.json
        let mut credential_subject = serde_json::json!({
            "id": agent_did,
            "identityFields": identity_json,
        });
        if let Some(name) = name {
            credential_subject["name"] = json!(name);
        }

        // Create JWT payload
        let now = chrono::Utc::now().timestamp();
        let payload = json!({
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://affinidi.io/contexts/agent-identity/v1"
            ],
            "type": ["VerifiableCredential", "AgentIdentityCredential"],
            "issuer": issuer_did,
            "issuanceDate": chrono::Utc::now().to_rfc3339(),
            "credentialSubject": credential_subject,
            "iat": now,
            "exp": now + (365 * 24 * 60 * 60), // 1 year
            "jti": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        });

        // Sign as JWT. A down backend propagates its error — the caller gets no
        // credential rather than a locally-signed one the active issuer DID
        // would not account for.
        let jwt = match authority.as_ref() {
            Some(authority) => {
                authority
                    .sign_token(&payload)
                    .await?
            }
            None => Self::sign_jwt(&payload, &local_signing_key)?,
        };

        Ok(jwt)
    }

    /// Sign a payload as JWT (JOSE `typ` = `JWT`).
    fn sign_jwt(
        payload: &serde_json::Value,
        key: &JWK,
    ) -> Result<String> {
        Self::sign_jwt_with_typ(payload, key, "JWT")
    }

    /// Sign a payload as a JWS with an explicit JOSE `typ` header. Explicit
    /// typing (RFC 8725) lets a verifier reject a token presented in the wrong
    /// context — e.g. requiring `oauth-id-jag+jwt` when redeeming an ID-JAG.
    pub(crate) fn sign_jwt_with_typ(
        payload: &serde_json::Value,
        key: &JWK,
        typ: &str,
    ) -> Result<String> {
        use base64::Engine;

        // Create JWT header
        let header = json!({
            "alg": "EdDSA",
            "typ": typ,
            "kid": key.key_id.as_ref().unwrap_or(&"key-1".to_string())
        });

        // Encode header and payload
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&header)?.as_bytes());
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload)?.as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);

        // Sign using the JWK
        let signature = Self::sign_with_jwk(signing_input.as_bytes(), key)?;
        let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

        Ok(format!("{}.{}", signing_input, signature_b64))
    }

    /// Sign data with JWK (Ed25519)
    fn sign_with_jwk(
        data: &[u8],
        key: &JWK,
    ) -> Result<Vec<u8>> {
        use base64::Engine;

        use ed25519_dalek::{Signer, SigningKey};

        // Serialize JWK to JSON to extract the d parameter
        let key_json = serde_json::to_value(key)?;
        let d_str = key_json
            .get("d")
            .and_then(|v| v.as_str())
            .context("Missing private key component 'd'")?;

        // Decode the private key
        let secret_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(d_str)
            .context("Failed to decode private key")?;

        let signing_key = SigningKey::from_bytes(
            &secret_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
        );

        let signature = signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    pub async fn get_agent_key_by_did(
        &self,
        did: &str,
    ) -> Result<JWK> {
        let record = self
            .identity_store
            .find_by_did(did)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Agent DID not found: {}", did))?;

        let key_json = record
            .private_key
            .ok_or_else(|| anyhow::anyhow!("No private key found for agent: {}", did))?;

        let key: JWK = serde_json::from_value(key_json).context("Failed to deserialize agent private key")?;

        Ok(key)
    }

    /// Sign data with an agent's private key (by DID)
    #[allow(dead_code)]
    pub async fn sign_with_agent_key(
        &self,
        did: &str,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self
            .get_agent_key_by_did(did)
            .await?;
        Self::sign_with_jwk(data, &key)
    }

    /// Sign a JWT payload with an agent's private key
    pub async fn sign_jwt_with_agent_key(
        &self,
        did: &str,
        payload: &serde_json::Value,
    ) -> Result<String> {
        let key = self
            .get_agent_key_by_did(did)
            .await?;
        let jwt = Self::sign_jwt(payload, &key)?;
        info!(did = did, "✍️ Signed JWT with agent key");
        Ok(jwt)
    }

    /// Point the fabric issuer attestation at a VTA context, so the DID it
    /// claims and the key that signs it are the same party.
    ///
    /// Without this the attestation claims the gateway's own DID and signs
    /// with the local key — which still verifies, but pins peers to a DID that
    /// no longer issues the credentials they will receive.
    pub async fn set_attestation_signer(
        &self,
        signer: Arc<dyn crate::vta::context_signer::ContextSigner>,
    ) {
        let mut slot = self
            .attestation_signer
            .write()
            .await;
        *slot = Some(signer);
    }

    /// The DID the fabric issuer attestation should claim, and which must
    /// therefore also be the issuer of the credentials peers will receive.
    pub async fn attestation_issuer_did(&self) -> Result<String> {
        match self
            .attestation_signer
            .read()
            .await
            .as_ref()
        {
            Some(signer) => signer.issuer_did().await,
            None => self.get_issuer_did().await,
        }
    }

    /// Sign an attestation as [`attestation_issuer_did`](Self::attestation_issuer_did).
    pub async fn sign_attestation_typ(
        &self,
        claims: &serde_json::Value,
        typ: &str,
    ) -> Result<String> {
        match self
            .attestation_signer
            .read()
            .await
            .as_ref()
        {
            Some(signer) => {
                signer
                    .sign_typ(claims, typ)
                    .await
            }
            None => {
                self.sign_jwt_with_gateway_key_typ(claims, typ)
                    .await
            }
        }
    }

    /// Sign a JWT payload with the gateway's private key
    pub async fn sign_jwt_with_gateway_key(
        &self,
        payload: &serde_json::Value,
    ) -> Result<String> {
        let config = self.config.read().await;
        let gateway_did = config.proxy_did.clone();
        let jwt = Self::sign_jwt(payload, &config.signing_key)?;
        drop(config);
        info!(did = %gateway_did, "✍️ Signed JWT with gateway key");
        Ok(jwt)
    }

    /// Sign a JWT payload with the gateway's private key under an explicit JOSE
    /// `typ` header (e.g. `oauth-id-jag+jwt` for an ID-JAG), so a verifier can
    /// reject a token presented in the wrong context.
    pub async fn sign_jwt_with_gateway_key_typ(
        &self,
        payload: &serde_json::Value,
        typ: &str,
    ) -> Result<String> {
        let config = self.config.read().await;
        let gateway_did = config.proxy_did.clone();
        let jwt = Self::sign_jwt_with_typ(payload, &config.signing_key, typ)?;
        drop(config);
        info!(did = %gateway_did, typ = typ, "✍️ Signed typed JWT with gateway key");
        Ok(jwt)
    }

    /// Create a Verifiable Presentation containing a Verifiable Credential for an agent
    /// This is used when GW1 forwards identity to GW2 with proof of identity
    pub async fn create_agent_identity_presentation(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
        challenge: Option<&str>,
        domain: Option<&str>,
    ) -> Result<String> {
        self.create_agent_identity_presentation_with_binding(agent_did, identity_fields, None, challenge, domain, None)
            .await
    }

    /// Create a VP with optional workload binding attestation.
    /// When `workload_binding` is provided, the VC uses structured `workloadBinding`
    /// instead of flat `identityFields`.
    ///
    /// `surface_id` scopes which key issues the embedded credential. `None`
    /// means appliance-wide, which is what every caller outside the injection
    /// path wants — and what the injection path itself did before surfaces
    /// could carry their own key.
    pub async fn create_agent_identity_presentation_with_binding(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
        workload_binding: Option<serde_json::Value>,
        challenge: Option<&str>,
        domain: Option<&str>,
        surface_id: Option<&str>,
    ) -> Result<String> {
        self.create_agent_identity_presentation_chained(
            agent_did,
            identity_fields,
            workload_binding,
            challenge,
            domain,
            Vec::new(),
            surface_id,
        )
        .await
    }

    /// Same as `create_agent_identity_presentation_with_binding`, but appends
    /// pre-existing verifiable credentials (typically the raw VCs from a
    /// verified inbound binding VP) to the issued VP so the receiver sees the
    /// full provenance chain.
    pub async fn create_agent_identity_presentation_chained(
        &self,
        agent_did: &str,
        identity_fields: &std::collections::HashMap<String, serde_json::Value>,
        workload_binding: Option<serde_json::Value>,
        challenge: Option<&str>,
        domain: Option<&str>,
        chained_credentials: Vec<serde_json::Value>,
        surface_id: Option<&str>,
    ) -> Result<String> {
        let display_name = self
            .display_name_for_did(agent_did)
            .await;
        // A VTA-backed holder issuer signs with the agent's own key, held in
        // the agent's VTA context. Only reach for a gateway-held key when
        // there is no such issuer — fetching it unconditionally would keep the
        // custody alive in the one place that still reads it.
        let vp_issuer = match self
            .di_vp_issuer
            .read()
            .await
            .as_ref()
        {
            Some(vta) => Arc::clone(vta),
            None => Arc::clone(&self.vp_issuer),
        };
        // ...but a VTA holder issuer only signs for agents that *have* a VTA
        // context, and falls back to the local one for the rest. Deciding on
        // the issuer alone stranded every pre-migration agent: the fallback
        // got no key and refused with "no holder key". So the key is fetched
        // whenever this agent would be signed locally, which keeps custody out
        // of the path for migrated agents and keeps the others working — the
        // gradual migration this is supposed to support.
        let signs_in_its_own_agent = self
            .di_vp_issuer
            .read()
            .await
            .is_some()
            && self
                .identity_store
                .find_by_did(agent_did)
                .await
                .ok()
                .flatten()
                .is_some_and(|record| {
                    record
                        .vta_context_id
                        .is_some()
                });
        let agent_key = match signs_in_its_own_agent {
            true => None,
            false => Some(
                self.get_agent_key_by_did(agent_did)
                    .await?,
            ),
        };

        let agent_identity = AgentIdentity {
            did: Cow::Borrowed(agent_did),
            identity_fields: Cow::Borrowed(identity_fields),
            workload_binding,
            display_name: display_name
                .as_ref()
                .map(|name| Cow::Borrowed(name.as_str())),
        };
        // A VTA-backed issuer, once selected, is the only issuer: there is no
        // fallback to the local key, because a credential signed by a key the
        // operator has moved away from is not an acceptable substitute for one
        // that failed to issue.
        //
        // Resolved per surface when the directory is wired, so a surface's own
        // `signing` block governs the credential inside an injected
        // presentation exactly as it governs that surface's tokens. A surface
        // that configures nothing resolves the appliance default, and an
        // appliance with no agent resolves the local key — which is why a
        // gateway that never adopted one is on an unchanged path.
        let scoped = match self
            .key_directory
            .read()
            .await
            .as_ref()
        {
            Some(directory) => {
                let scope = crate::vta::key_directory::KeyScope {
                    surface_id: surface_id.map(str::to_string),
                    ..Default::default()
                };
                directory
                    .di_vc_issuer_for(&scope)
                    .await
            }
            None => crate::vta::key_directory::ScopedDiIssuer::Inherit,
        };
        let issuer = match scoped {
            crate::vta::key_directory::ScopedDiIssuer::Agent(vta) => vta,
            // An explicit `local` is honoured as written, rather than falling
            // through to whatever the appliance signs with.
            crate::vta::key_directory::ScopedDiIssuer::Local => Arc::clone(&self.vc_issuer),
            crate::vta::key_directory::ScopedDiIssuer::Inherit => match self
                .di_vc_issuer
                .read()
                .await
                .as_ref()
            {
                Some(vta) => Arc::clone(vta),
                None => Arc::clone(&self.vc_issuer),
            },
        };
        let vc = issuer
            .issue(IssueVcPayload::AgentIdentity(agent_identity))
            .await?;

        let mut credentials_list: Vec<serde_json::Value> = Vec::with_capacity(1 + chained_credentials.len());
        credentials_list.push(vc);
        credentials_list.extend(chained_credentials);

        let presentation_creds = Credentials {
            holder_key: agent_key.map(Cow::Owned),
            holder_did: Cow::Borrowed(agent_did),
            verifiable_credentials: Cow::Owned(credentials_list),
            challenge: challenge.map(Cow::Borrowed),
            domain: domain.map(Cow::Borrowed),
        };

        let vp = vp_issuer
            .issue(VpIssuerPayload::Credentials(presentation_creds))
            .await?;

        info!(agent_did = agent_did, "Created VP for agent identity presentation");

        Ok(vp.to_string())
    }

    async fn validate_vp_challenge(
        &self,
        challenge: Option<&String>,
    ) -> Result<()> {
        let config = self.config.read().await;
        let is_challenge_required = config.is_vp_challenge_required;
        drop(config);

        match (challenge, is_challenge_required) {
            (None, true) => {
                anyhow::bail!("VP challenge is required but not presented");
            }
            (Some(challenge), _) => {
                let stored = self
                    .vp_challenge_store
                    .find_by_challenge(challenge)
                    .await
                    .context("Failed to lookup VP challenge")?;

                if stored.is_none() {
                    anyhow::bail!("VP challenge '{}' not found in store", challenge);
                }

                self.vp_challenge_store
                    .delete(challenge)
                    .await
                    .context("Failed to delete used VP challenge")?;
            }
            (None, false) => {}
        }

        Ok(())
    }

    pub async fn verify_agent_presentation(
        &self,
        vp_input: &str,
    ) -> Result<(String, std::collections::HashMap<String, serde_json::Value>)> {
        let (did, fields, _) = self
            .verify_agent_presentation_with_credentials(vp_input)
            .await?;
        Ok((did, fields))
    }

    /// Same as `verify_agent_presentation` but additionally returns the raw
    /// `verifiableCredential` entries from the inbound VP, so a downstream
    /// gateway can flatten them into a re-issued chained VP.
    pub async fn verify_agent_presentation_with_credentials(
        &self,
        vp_input: &str,
    ) -> Result<(String, std::collections::HashMap<String, serde_json::Value>, Vec<serde_json::Value>)> {
        let vp: serde_json::Value = serde_json::from_str(vp_input).context("Failed to parse VP as JSON")?;

        let result = self
            .verifier
            .verify_vp(&vp)
            .await
            .context("VP verification failed");

        if let Err(e) = &result {
            // `{:#}` prints the full anyhow cause chain inline on one line so
            // the tracing formatter surfaces the real reason (the `{:?}` form
            // spills the `Caused by:` chain onto lines the log viewer drops).
            warn!("VP verification error: {:#}", e);
        }

        let result = result?;

        self.validate_vp_challenge(result.challenge.as_ref())
            .await?;

        let identity_fields = result
            .credentials
            .first()
            .map(|vc| vc.identity_fields.clone())
            .unwrap_or_default();

        Ok((result.holder_did, identity_fields, result.raw_credentials))
    }

    /// Verify an agent presentation and return the full set of parts the
    /// Workload Binding verifier needs: the VP holder DID, the primary VC
    /// subject id (`credentialSubject.id`), the primary VC issuer DID, the
    /// credential subject fields, and the raw credentials for re-chaining.
    /// Lifetime (`validUntil` / `expirationDate`) is already enforced by
    /// `verify_vp`, so an expired credential fails here.
    pub async fn verify_agent_presentation_full(
        &self,
        vp_input: &str,
    ) -> Result<VerifiedAgentPresentation> {
        let vp: serde_json::Value = serde_json::from_str(vp_input).context("Failed to parse VP as JSON")?;

        let result = self
            .verifier
            .verify_vp(&vp)
            .await
            .context("VP verification failed")?;

        self.validate_vp_challenge(result.challenge.as_ref())
            .await?;

        let primary = result.credentials.first();
        let issuer_did = primary.map(|vc| vc.issuer_did.clone());
        let identity_fields = primary
            .map(|vc| vc.identity_fields.clone())
            .unwrap_or_default();
        let subject_id = result
            .raw_credentials
            .first()
            .and_then(|vc| vc.get("credentialSubject"))
            .and_then(|subj| subj.get("id"))
            .and_then(|id| id.as_str())
            .map(str::to_string);

        Ok(VerifiedAgentPresentation {
            holder_did: result.holder_did,
            subject_id,
            issuer_did,
            identity_fields,
            raw_credentials: result.raw_credentials,
        })
    }

    #[allow(dead_code)]
    pub async fn create_vp_challenge(
        &self,
        requested_from_did: &str,
    ) -> Result<(String, String)> {
        let config = self.config.read().await;
        let domain = config.proxy_did.clone();
        drop(config);

        let challenge = uuid::Uuid::new_v4().to_string();

        let record = super::VpChallengeRecord {
            challenge: challenge.clone(),
            created_at: chrono::Utc::now(),
            domain: domain.clone(),
            requested_from_did: requested_from_did.to_string(),
        };

        self.vp_challenge_store
            .store(record)
            .await
            .context("Failed to store VP challenge")?;
        Ok((challenge, domain))
    }

    #[allow(dead_code)]
    pub fn get_vp_challenge_store(&self) -> Arc<dyn VpChallengeStore> {
        Arc::clone(&self.vp_challenge_store)
    }
}

/// Full result of [`VCIssuer::verify_agent_presentation_full`], carrying the
/// parts the Workload Binding verifier needs to enforce issuer trust and
/// holder/subject binding.
#[derive(Debug, Clone)]
pub struct VerifiedAgentPresentation {
    /// The VP holder DID (who signed the presentation).
    pub holder_did: String,
    /// The primary VC `credentialSubject.id`, when present.
    pub subject_id: Option<String>,
    /// The primary VC issuer DID, when present.
    pub issuer_did: Option<String>,
    /// The primary VC credential-subject fields.
    pub identity_fields: std::collections::HashMap<String, serde_json::Value>,
    /// Raw `verifiableCredential` entries for re-chaining.
    pub raw_credentials: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_helpers::{MockIdentityStore, MockVpChallengeStore};
    use crate::identity::{IdentityStore, VpChallengeStore};
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn extract_domain_from_proxy_did_supports_didwebvh() {
        assert_eq!(extract_domain_from_proxy_did("did:web:localhost%3A8080"), "localhost:8080");
        assert_eq!(extract_domain_from_proxy_did("did:webvh:z6MkScid123:localhost%3A8080"), "localhost:8080");
    }

    /// Enable whole-file encryption on the current test thread and return the service.
    fn enable_test_encryption() -> crate::encryption::EncryptionService {
        let service =
            crate::encryption::EncryptionService::new(crate::encryption::KeySource::Raw { key: [7u8; 32] }).unwrap();
        crate::encryption::global::set_test_encryption(
            crate::config::EncryptionConfig {
                enabled: true,
                ..Default::default()
            },
            service.clone(),
        );
        service
    }

    #[tokio::test]
    async fn write_issuer_file_encrypts_and_removes_plaintext() {
        enable_test_encryption();
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("issuer_config.json");
        let enc = crate::encryption::secret_file::secret_enc_path(&path);

        write_issuer_file(&path, r#"{"k":"v"}"#)
            .await
            .unwrap();

        assert!(!path.exists(), "plaintext issuer key material must not remain when encryption is active");
        assert!(enc.exists(), "encrypted sibling must be written");
        let on_disk = std::fs::read_to_string(&enc).unwrap();
        assert!(on_disk.starts_with("ENC["), "on-disk blob must be an ENC[...] envelope, got: {on_disk}");

        let read_back = read_issuer_file(&path)
            .await
            .unwrap();
        assert_eq!(read_back.as_deref(), Some(r#"{"k":"v"}"#), "round-trip must return the original plaintext");
    }

    #[tokio::test]
    async fn write_issuer_file_plaintext_when_encryption_disabled() {
        crate::encryption::global::set_test_encryption(
            crate::config::EncryptionConfig::default(),
            crate::encryption::EncryptionService::disabled(),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("p256_key.json");
        let enc = crate::encryption::secret_file::secret_enc_path(&path);

        write_issuer_file(&path, "plain")
            .await
            .unwrap();

        assert!(path.exists(), "plaintext file must be written when encryption is disabled");
        assert!(!enc.exists(), "no encrypted sibling when encryption is disabled");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "plain");
    }

    #[tokio::test]
    async fn read_issuer_file_migrates_plaintext_only_to_encrypted() {
        enable_test_encryption();
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("x25519_key.json");
        // A plaintext-only key left from before encryption was enabled.
        std::fs::write(&path, "secret-key-material").unwrap();
        let enc = crate::encryption::secret_file::secret_enc_path(&path);
        assert!(!enc.exists());

        let content = read_issuer_file(&path)
            .await
            .unwrap();

        assert_eq!(content.as_deref(), Some("secret-key-material"), "read must return the plaintext content");
        assert!(!path.exists(), "plaintext must be removed after migrate-on-read");
        assert!(enc.exists(), "encrypted sibling must be created on read");
    }

    #[tokio::test]
    async fn read_issuer_file_prefers_ciphertext_and_drops_stale_plaintext() {
        enable_test_encryption();
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("issuer_config.json");

        write_issuer_file(&path, "authoritative")
            .await
            .unwrap();
        // A stale plaintext sibling lingering beside the authoritative ciphertext.
        std::fs::write(&path, "stale-plaintext").unwrap();

        let content = read_issuer_file(&path)
            .await
            .unwrap();

        assert_eq!(content.as_deref(), Some("authoritative"), "ciphertext is authoritative");
        assert!(!path.exists(), "stale plaintext sibling must be removed on read");
    }

    #[tokio::test]
    #[ignore] // FIXME: failing test
    async fn test_create_agent_identity_presentation() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let orchestrator =
            VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
                .await
                .unwrap();

        let mut identity_fields = HashMap::new();
        identity_fields.insert(
            "agentIdentity".to_string(),
            json!({
                "llmInfo": {
                    "model": "gpt-4",
                    "provider": "openai"
                },
                "softwareInfo": {
                    "name": "test-agent",
                    "version": "1.0.0"
                }
            }),
        );

        let response = orchestrator
            .issue_or_get_credential(identity_fields.clone(), None, None, None)
            .await
            .unwrap();

        let agent_did = response.did;

        let vp_json_str = orchestrator
            .create_agent_identity_presentation(&agent_did, &identity_fields, None, None)
            .await
            .unwrap();

        assert!(!vp_json_str.is_empty(), "VP should not be empty");

        let vp: serde_json::Value = serde_json::from_str(&vp_json_str).unwrap();

        assert!(vp.get("proof").is_some(), "VP should have a proof");
        assert_eq!(vp["type"], json!(["VerifiablePresentation"]));

        let holder = vp["holder"].as_str().unwrap();
        assert!(holder.starts_with("did:peer:"), "Holder should be a did:peer");

        let vc = &vp["verifiableCredential"];
        assert!(vc.is_object() || vc.is_array(), "VP should contain verifiableCredential");
    }

    // === Baseline did:webvh Tests ===
    /// The proxy DID is created as did:webvh on the first boot and is
    /// stable on all subsequent boots.
    #[tokio::test]
    async fn proxy_did_persists_across_restarts() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        // Boot 1 — new config, creates did:webvh directly
        let issuer1 = VCIssuer::new(
            temp_dir.path(),
            "example.com",
            Arc::clone(&identity_store),
            Arc::clone(&vp_challenge_store),
            None,
            None,
        )
        .await
        .unwrap();
        let did1 = issuer1
            .get_issuer_did()
            .await
            .unwrap();
        assert!(did1.starts_with("did:webvh:"), "Boot 1 must create did:webvh, got: {}", did1);

        // Boot 2 — DID is stable
        let issuer2 = VCIssuer::new(
            temp_dir.path(),
            "example.com",
            Arc::clone(&identity_store),
            Arc::clone(&vp_challenge_store),
            None,
            None,
        )
        .await
        .unwrap();
        let did2 = issuer2
            .get_issuer_did()
            .await
            .unwrap();
        assert_eq!(did1, did2, "Boot 2 DID must be identical to boot 1 (stable)");

        // Boot 3 — DID is still stable
        let issuer3 = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();
        let did3 = issuer3
            .get_issuer_did()
            .await
            .unwrap();
        assert_eq!(did1, did3, "Proxy DID must be identical on third boot (stable)");
    }

    /// The proxy DID must use the did:webvh method on first boot.
    #[tokio::test]
    async fn proxy_did_format_is_did_webvh() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let did = issuer
            .get_issuer_did()
            .await
            .unwrap();
        assert!(did.starts_with("did:webvh:"), "Proxy DID must use the did:webvh method, got: {}", did);
    }

    /// Three key types (Ed25519, X25519, P-256) must be generated.
    #[tokio::test]
    async fn generates_three_key_types_ed25519_x25519_p256() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let secrets = issuer
            .get_signing_secrets()
            .await
            .unwrap();
        assert_eq!(secrets.len(), 3, "Must generate exactly 3 key types (Ed25519 + X25519 + P-256)");
    }

    /// Secret IDs must follow the expected naming convention.
    #[tokio::test]
    async fn key_ids_follow_hash_key_n_convention() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let secrets = issuer
            .get_signing_secrets()
            .await
            .unwrap();
        assert_eq!(secrets.len(), 3, "Expected 3 secrets");

        // Ed25519 key has #key-1 fragment
        assert!(
            secrets[0]
                .id
                .contains("#key-1"),
            "Ed25519 secret ID must contain '#key-1', got: {}",
            secrets[0].id
        );
        // X25519 key has #key-x25519-1 fragment
        assert!(
            secrets[1]
                .id
                .contains("#key-x25519-1"),
            "X25519 secret ID must contain '#key-x25519-1', got: {}",
            secrets[1].id
        );
        // P-256 key has #key-p256-1 fragment
        assert!(
            secrets[2]
                .id
                .contains("#key-p256-1"),
            "P-256 secret ID must contain '#key-p256-1', got: {}",
            secrets[2].id
        );
    }

    /// Ed25519 signing key must be identical after reload.
    #[tokio::test]
    async fn signing_key_unchanged_after_reload() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store1 = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp1 = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;
        let store2 = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp2 = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", store1, vp1, None, None)
            .await
            .unwrap();
        let secrets1 = issuer1
            .get_signing_secrets()
            .await
            .unwrap();
        let _ed25519_id_1 = secrets1[0].id.clone();
        // Serialize so we can compare after reload
        let material1 = serde_json::to_string(&secrets1[0].secret_material).unwrap();

        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store2, vp2, None, None)
            .await
            .unwrap();
        let secrets2 = issuer2
            .get_signing_secrets()
            .await
            .unwrap();
        let ed25519_id_2 = secrets2[0].id.clone();
        let material2 = serde_json::to_string(&secrets2[0].secret_material).unwrap();

        // The DID (and thus the key reference ID) changes on the 2nd boot migration.
        // Only the cryptographic material must be preserved.
        assert_eq!(material1, material2, "Ed25519 key material must be identical after migration");
        // Verify the ID now references the webvh DID
        assert!(
            ed25519_id_2.starts_with("did:webvh:"),
            "After migration, Ed25519 key ID must reference the webvh DID, got: {}",
            ed25519_id_2
        );
    }

    /// The DID document must contain all required sections.
    #[tokio::test]
    async fn did_document_has_required_sections() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let doc = issuer
            .get_did_document()
            .await
            .unwrap();

        assert!(
            doc.get("verificationMethod")
                .is_some(),
            "DID document missing 'verificationMethod'"
        );
        assert!(
            doc.get("authentication")
                .is_some(),
            "DID document missing 'authentication'"
        );
        assert!(
            doc.get("assertionMethod")
                .is_some(),
            "DID document missing 'assertionMethod'"
        );
        assert!(
            doc.get("keyAgreement")
                .is_some(),
            "DID document missing 'keyAgreement'"
        );
        assert!(doc.get("id").is_some(), "DID document missing 'id'");
    }

    /// The issued VC's issuer field must match the proxy_did.
    #[tokio::test]
    async fn issued_vc_issuer_matches_proxy_did() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let proxy_did = issuer
            .get_issuer_did()
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"llmInfo": {"model": "gpt-4", "provider": "openai"}}));

        let response = issuer
            .issue_or_get_credential(fields, None, None, None)
            .await
            .unwrap();

        // Decode the JWT payload (second segment between dots)
        use base64::Engine;
        let parts: Vec<&str> = response
            .credential
            .split('.')
            .collect();
        assert!(parts.len() >= 2, "JWT must have at least 2 segments");
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let vc_issuer = payload["issuer"]
            .as_str()
            .unwrap_or("");
        assert_eq!(vc_issuer, proxy_did, "VC issuer must match proxy DID");
    }

    // === Per-Agent Credential DID Tests ===
    /// Same metadata → same DID (second call retrieves from store).
    #[tokio::test]
    async fn agent_did_deterministic_from_metadata() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "gpt-4", "provider": "openai"}));

        let r1 = issuer
            .issue_or_get_credential(fields.clone(), None, None, None)
            .await
            .unwrap();
        let r2 = issuer
            .issue_or_get_credential(fields.clone(), None, None, None)
            .await
            .unwrap();

        assert_eq!(r1.did, r2.did, "Same metadata must yield same DID on repeated calls");
    }

    /// Agent DID format must be did:webvh:<SCID>:<domain>:surface:<UUID>.
    #[tokio::test]
    async fn agent_did_format_includes_surface_segment() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "claude-3"}));

        let response = issuer
            .issue_or_get_credential(fields, None, None, None)
            .await
            .unwrap();

        // Format: did:webvh:<SCID>:<domain>:surface:<UUID>
        let parts: Vec<&str> = response
            .did
            .split(':')
            .collect();
        assert!(parts.len() >= 6, "Agent DID must have at least 6 colon-delimited parts, got: {}", response.did);
        assert_eq!(parts[0], "did");
        assert_eq!(parts[1], "webvh");
        // The "surface" segment is second-to-last
        let surface_idx = parts.len() - 2;
        assert_eq!(parts[surface_idx], "surface", "Agent DID must contain 'surface' segment, got: {}", response.did);
    }

    /// Different metadata → different DIDs.
    #[tokio::test]
    async fn different_metadata_different_dids() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields_a = HashMap::new();
        fields_a.insert("agentIdentity".to_string(), json!({"model": "gpt-4"}));

        let mut fields_b = HashMap::new();
        fields_b.insert("agentIdentity".to_string(), json!({"model": "claude-3"}));

        let r_a = issuer
            .issue_or_get_credential(fields_a, None, None, None)
            .await
            .unwrap();
        let r_b = issuer
            .issue_or_get_credential(fields_b, None, None, None)
            .await
            .unwrap();

        assert_ne!(r_a.did, r_b.did, "Different metadata must yield different DIDs");
    }

    /// First issuance for new metadata must set is_new = true.
    #[tokio::test]
    async fn first_issuance_returns_is_new_true() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "new-agent"}));

        let response = issuer
            .issue_or_get_credential(fields, None, None, None)
            .await
            .unwrap();
        assert!(response.is_new, "First issuance must return is_new = true");
    }

    /// Second issuance for the same metadata must set is_new = false.
    #[tokio::test]
    async fn second_issuance_returns_is_new_false() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "reused-agent"}));

        let _first = issuer
            .issue_or_get_credential(fields.clone(), None, None, None)
            .await
            .unwrap();
        let second = issuer
            .issue_or_get_credential(fields, None, None, None)
            .await
            .unwrap();

        assert!(!second.is_new, "Second issuance for same metadata must return is_new = false");
    }

    // === Key Material Preservation Tests ===
    /// Ed25519 key must be unchanged after migration to did:webvh.
    #[tokio::test]
    async fn key_material_unchanged_after_migration_to_didwebvh() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        // Boot 1 — new config, did:web
        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let secrets_before = issuer1
            .get_signing_secrets()
            .await
            .unwrap();
        let ed25519_before = serde_json::to_string(&secrets_before[0].secret_material).unwrap();

        // Boot 2 — migration fires, switches to did:webvh
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();
        let secrets_after = issuer2
            .get_signing_secrets()
            .await
            .unwrap();
        let ed25519_after = serde_json::to_string(&secrets_after[0].secret_material).unwrap();

        assert_eq!(ed25519_before, ed25519_after, "Ed25519 key must be unchanged after migration");

        let did = issuer2
            .get_issuer_did()
            .await
            .unwrap();
        assert!(did.starts_with("did:webvh:"), "Post-migration DID must use did:webvh method, got: {}", did);
    }

    /// X25519 key must be unchanged after migration.
    #[tokio::test]
    async fn x25519_key_unchanged_after_migration() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        // Boot 1 — new config
        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let secrets_before = issuer1
            .get_signing_secrets()
            .await
            .unwrap();
        let x25519_before = serde_json::to_string(&secrets_before[1].secret_material).unwrap();

        // Boot 2 — migration fires
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();
        let secrets_after = issuer2
            .get_signing_secrets()
            .await
            .unwrap();
        let x25519_after = serde_json::to_string(&secrets_after[1].secret_material).unwrap();

        assert_eq!(x25519_before, x25519_after, "X25519 key must be unchanged after migration");
    }

    /// P-256 key must be unchanged after migration.
    #[tokio::test]
    async fn p256_key_unchanged_after_migration() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        // Boot 1 — new config
        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let secrets_before = issuer1
            .get_signing_secrets()
            .await
            .unwrap();
        let p256_before = serde_json::to_string(&secrets_before[2].secret_material).unwrap();

        // Boot 2 — migration fires
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();
        let secrets_after = issuer2
            .get_signing_secrets()
            .await
            .unwrap();
        let p256_after = serde_json::to_string(&secrets_after[2].secret_material).unwrap();

        assert_eq!(p256_before, p256_after, "P-256 key must be unchanged after migration");
    }

    // === VC Issuer Migration Tests ===
    /// After migration, issued VCs must use did:webvh as issuer.
    #[tokio::test]
    async fn post_migration_vcs_use_didwebvh_issuer() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        // Boot 1 — new config
        VCIssuer::new(
            temp_dir.path(),
            "example.com",
            Arc::clone(&identity_store),
            Arc::clone(&vp_challenge_store),
            None,
            None,
        )
        .await
        .unwrap();

        // Boot 2 — migration fires, proxy_did is now did:webvh
        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let mut fields = HashMap::new();
        fields.insert("agentIdentity".to_string(), json!({"model": "post-migration-agent"}));
        let response = issuer
            .issue_or_get_credential(fields, None, None, None)
            .await
            .unwrap();

        use base64::Engine;
        let parts: Vec<&str> = response
            .credential
            .split('.')
            .collect();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let vc_issuer = payload["issuer"]
            .as_str()
            .unwrap_or("");
        assert!(vc_issuer.starts_with("did:webvh:"), "Post-migration VC issuer must use did:webvh, got: {}", vc_issuer);
    }

    /// VCIssuerConfig.proxy_did must hold the did:webvh string after migration.
    #[tokio::test]
    async fn vc_issuer_config_stores_didwebvh_string() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        // Boot 1 — new config
        VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();

        // Boot 2 — migration fires
        let issuer = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();
        let did = issuer
            .get_issuer_did()
            .await
            .unwrap();
        assert!(
            did.starts_with("did:webvh:"),
            "VCIssuerConfig.proxy_did must be did:webvh after migration, got: {}",
            did
        );
    }

    // === Helpers shared by 8.5 / 8.6 / 11.4 ===

    /// Extract the Ed25519 `VerifyingKey` from the first `JsonWebKey2020` OKP entry in a DID document.
    fn extract_ed25519_verifying_key(did_doc: &serde_json::Value) -> ed25519_dalek::VerifyingKey {
        use base64::Engine;
        let vms = did_doc["verificationMethod"]
            .as_array()
            .expect("no verificationMethod array");
        for vm in vms {
            if let Some(jwk) = vm.get("publicKeyJwk")
                && jwk
                    .get("kty")
                    .and_then(|v| v.as_str())
                    == Some("OKP")
            {
                let x = jwk["x"]
                    .as_str()
                    .expect("OKP key missing 'x'");
                let x_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(x)
                    .expect("bad base64 in x");
                let arr: [u8; 32] = x_bytes
                    .try_into()
                    .expect("wrong key length");
                return ed25519_dalek::VerifyingKey::from_bytes(&arr).expect("invalid Ed25519 key");
            }
        }
        panic!("No Ed25519 OKP JWK found in DID document");
    }

    /// Verify the signature portion of a compact JWS (JWT) using an Ed25519 key.
    fn verify_jwt_ed25519(
        jwt: &str,
        key: &ed25519_dalek::VerifyingKey,
    ) -> bool {
        use base64::Engine;
        use ed25519_dalek::Verifier;
        let parts: Vec<&str> = jwt.splitn(3, '.').collect();
        if parts.len() != 3 {
            return false;
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[2]) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let signature = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };
        key.verify(signing_input.as_bytes(), &signature)
            .is_ok()
    }

    #[tokio::test]
    async fn signing_public_jwks_verifies_gateway_signature() {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp_challenge_store = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;
        let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
            .await
            .unwrap();

        let jwt = issuer
            .sign_jwt_with_gateway_key(&json!({
                "sub": "test-subject",
                "exp": chrono::Utc::now().timestamp() + 60,
            }))
            .await
            .unwrap();
        let jwks = issuer
            .signing_public_jwks()
            .await
            .unwrap();
        let keys = jwks["keys"]
            .as_array()
            .expect("JWKS must contain a keys array");
        assert_eq!(keys.len(), 1);

        let public_jwk = &keys[0];
        assert_eq!(public_jwk["kty"], "OKP");
        assert_eq!(public_jwk["crv"], "Ed25519");
        assert_eq!(public_jwk["use"], "sig");
        assert_eq!(public_jwk["alg"], "EdDSA");
        assert_eq!(public_jwk["kid"], "key-1");
        assert!(public_jwk.get("d").is_none(), "public JWKS must not expose private key material");

        let decoding_key = DecodingKey::from_ed_components(
            public_jwk["x"]
                .as_str()
                .expect("public JWK must contain x"),
        )
        .expect("public JWK must contain a valid Ed25519 key");
        let token = decode::<serde_json::Value>(&jwt, &decoding_key, &Validation::new(Algorithm::EdDSA))
            .expect("public JWKS key must verify a JWT signed by the corresponding gateway private key");
        assert_eq!(token.claims["sub"], "test-subject");
    }

    /// A JWT signed with the gateway's did:web key before migration still verifies
    /// after migration, because `did.json` continues to serve the identical public key.
    #[tokio::test]
    async fn old_vc_signature_still_verifies_after_migration() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        // Boot 1 — new config, proxy_did = did:web:example.com
        let issuer1 = VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();

        // Sign a JWT payload with the gateway key (did:web era)
        let old_jwt = issuer1
            .sign_jwt_with_gateway_key(&json!({"test": "before-migration"}))
            .await
            .unwrap();

        // Boot 2 — migration fires, proxy_did becomes did:webvh
        drop(issuer1);
        let _issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();

        // did.json after migration still has the same Ed25519 public key
        let did_json_content = tokio::fs::read_to_string(
            temp_dir
                .path()
                .join("did.json"),
        )
        .await
        .unwrap();
        let did_json: serde_json::Value = serde_json::from_str(&did_json_content).unwrap();
        let verifying_key = extract_ed25519_verifying_key(&did_json);

        assert!(
            verify_jwt_ed25519(&old_jwt, &verifying_key),
            "Old JWT signed before migration must still verify with did.json public key after migration"
        );
    }

    /// A JWT signed with the gateway's did:webvh key after migration verifies
    /// using the public key from the did:webvh log (did.jsonl).
    #[tokio::test]
    async fn new_vc_verifies_via_didwebvh_resolver() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        // Boot 1 then Boot 2 (migration fires)
        VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();

        // Issue a new JWT post-migration (issuer is now did:webvh)
        let new_jwt = issuer2
            .sign_jwt_with_gateway_key(&json!({"test": "after-migration"}))
            .await
            .unwrap();

        let did = issuer2
            .get_issuer_did()
            .await
            .unwrap();
        assert!(did.starts_with("did:webvh:"), "issuer must be did:webvh after migration, got: {}", did);

        // Get the public key from the latest did:webvh log entry state (simulates did:webvh resolver)
        let jsonl_content = tokio::fs::read_to_string(
            temp_dir
                .path()
                .join("did.jsonl"),
        )
        .await
        .unwrap();
        let latest_line = jsonl_content
            .lines()
            .last()
            .expect("did.jsonl must have at least one entry");
        let entry_json: serde_json::Value = serde_json::from_str(latest_line).unwrap();
        let state_doc = &entry_json["state"];
        let verifying_key = extract_ed25519_verifying_key(state_doc);

        assert!(
            verify_jwt_ed25519(&new_jwt, &verifying_key),
            "New JWT with did:webvh issuer must verify with public key from did.jsonl log state"
        );
    }

    /// A JWT with a did:webvh issuer can be verified by an external verifier that only
    /// knows about did:web — it reads the parallel `did.json` to obtain the public key.
    #[tokio::test]
    async fn vc_with_didwebvh_issuer_resolves_via_did_json_fallback() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
        let vp = Arc::new(MockVpChallengeStore::new()) as Arc<dyn VpChallengeStore>;

        // Boot 1 then Boot 2 (migration fires)
        VCIssuer::new(temp_dir.path(), "example.com", Arc::clone(&store), Arc::clone(&vp), None, None)
            .await
            .unwrap();
        let issuer2 = VCIssuer::new(temp_dir.path(), "example.com", store, vp, None, None)
            .await
            .unwrap();

        // Issue a JWT post-migration (issuer is did:webvh)
        let jwt = issuer2
            .sign_jwt_with_gateway_key(&json!({"test": "didweb-fallback"}))
            .await
            .unwrap();

        // Simulate external verifier: resolve did.json at the equivalent did:web URL (no did:webvh support)
        let did_json_content = tokio::fs::read_to_string(
            temp_dir
                .path()
                .join("did.json"),
        )
        .await
        .unwrap();
        let did_json: serde_json::Value = serde_json::from_str(&did_json_content).unwrap();

        // did.json must have alsoKnownAs pointing to the did:webvh DID
        let did = issuer2
            .get_issuer_did()
            .await
            .unwrap();
        let also_known_as = did_json["alsoKnownAs"]
            .as_array()
            .expect("did.json must have alsoKnownAs");
        assert!(
            also_known_as
                .iter()
                .any(|v| v.as_str() == Some(&did)),
            "did.json alsoKnownAs must reference the did:webvh DID for cross-resolution"
        );

        // The public key from did.json must verify the JWT signed by the post-migration gateway
        let verifying_key = extract_ed25519_verifying_key(&did_json);
        assert!(
            verify_jwt_ed25519(&jwt, &verifying_key),
            "JWT with did:webvh issuer must verify with public key from the parallel did.json fallback"
        );
    }

    /// Run `future` with `AG_TEST_MODE=true` in the process environment,
    /// serialized against the `test_auth` tests that mutate the same variable.
    /// The guard must span the await so no other test mutates the variable
    /// while `future` runs.
    #[allow(clippy::await_holding_lock)]
    async fn with_ag_test_mode_env<F: std::future::Future<Output = T>, T>(future: F) -> T {
        let _guard = crate::auth::test_auth::tests::TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var("AG_TEST_MODE").ok();
        unsafe { std::env::set_var("AG_TEST_MODE", "true") };
        let out = future.await;
        unsafe {
            match previous {
                Some(value) => std::env::set_var("AG_TEST_MODE", value),
                None => std::env::remove_var("AG_TEST_MODE"),
            }
        }
        out
    }

    #[tokio::test]
    async fn test_mode_does_not_accept_unverifiable_presentation() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let vp = json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": "did:example:claimed-holder",
            "verifiableCredential": [{
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential", "AgentIdentity"],
                "issuer": "did:example:claimed-issuer",
                "credentialSubject": { "id": "did:example:claimed-holder", "name": "agent" }
            }]
        })
        .to_string();

        let result = with_ag_test_mode_env(issuer.verify_agent_presentation_full(&vp)).await;

        let err = result.expect_err("an unsigned presentation must never verify, whatever the environment says");
        assert!(format!("{err:#}").contains("VP verification failed"), "unexpected error: {err:#}");
    }

    #[tokio::test]
    async fn test_mode_does_not_mint_for_unknown_agent_did() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let identity_fields = HashMap::from([("name".to_string(), json!("agent"))]);

        let result = with_ag_test_mode_env(issuer.create_agent_identity_presentation(
            "did:example:no-key",
            &identity_fields,
            None,
            None,
        ))
        .await;

        let err = result.expect_err("minting without a provisioned agent key must fail, whatever the environment says");
        assert!(
            err.to_string()
                .contains("Agent DID not found"),
            "unexpected error: {err}"
        );
    }

    mod display_names {
        use super::*;
        use crate::identity::test_helpers::test_vc_issuer;
        use crate::surfaces::AgentSurfaceStore;

        struct Fixture {
            issuer: VCIssuer,
            surfaces: Arc<crate::surfaces::FileSystemAgentSurfaceStore>,
            _issuer_dir: tempfile::TempDir,
            _surface_dir: tempfile::TempDir,
        }

        impl Fixture {
            async fn save_surface(
                &self,
                surface_id: &str,
                name: &str,
            ) {
                self.surfaces
                    .save(&crate::config::agent_surface::AgentSurface {
                        surface_id: surface_id.to_string(),
                        name: name.to_string(),
                        ..Default::default()
                    })
                    .await
                    .expect("save surface");
            }
        }

        async fn fixture() -> Fixture {
            let (issuer, issuer_dir) = test_vc_issuer().await;
            let surface_dir = tempfile::tempdir().unwrap();
            let surfaces = Arc::new(
                crate::surfaces::FileSystemAgentSurfaceStore::new(
                    surface_dir
                        .path()
                        .to_path_buf(),
                )
                .await
                .unwrap(),
            );
            issuer.set_surface_store(surfaces.clone());
            Fixture {
                issuer,
                surfaces,
                _issuer_dir: issuer_dir,
                _surface_dir: surface_dir,
            }
        }

        fn jwt_subject(jwt: &str) -> serde_json::Value {
            use base64::Engine;
            let payload = jwt
                .split('.')
                .nth(1)
                .expect("JWT payload segment");
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .expect("base64url payload");
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("JSON payload")["credentialSubject"].clone()
        }

        fn fields(value: &str) -> HashMap<String, serde_json::Value> {
            HashMap::from([("agent".to_string(), json!(value))])
        }

        async fn origin_of(
            issuer: &VCIssuer,
            did: &str,
        ) -> Option<IdentityOrigin> {
            issuer
                .get_identity_store()
                .find_by_did(did)
                .await
                .unwrap()
                .unwrap()
                .origin
        }

        #[tokio::test]
        async fn managed_credential_carries_surface_name_and_origin() {
            let f = fixture().await;
            f.save_surface("vc-name-managed", "OXYGEN")
                .await;
            let issuer = &f.issuer;

            let response = issuer
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-managed".into()), None)
                .await
                .unwrap();

            assert_eq!(jwt_subject(&response.credential)["name"], json!("OXYGEN"));
            assert_eq!(origin_of(issuer, &response.did).await, Some(IdentityOrigin::Managed));
        }

        #[tokio::test]
        async fn caller_credential_has_no_name() {
            let f = fixture().await;
            f.save_surface("vc-name-caller", "OXYGEN")
                .await;
            let issuer = &f.issuer;

            let response = issuer
                .issue_or_get_caller_credential(fields("a"), None, Some("vc-name-caller".into()), None)
                .await
                .unwrap();

            assert!(
                jwt_subject(&response.credential)
                    .get("name")
                    .is_none()
            );
            assert_eq!(origin_of(issuer, &response.did).await, Some(IdentityOrigin::ExternalCaller));
        }

        #[tokio::test]
        async fn plain_credential_has_no_name_or_origin() {
            let f = fixture().await;
            f.save_surface("vc-name-plain", "OXYGEN")
                .await;
            let issuer = &f.issuer;

            let response = issuer
                .issue_or_get_credential(fields("a"), None, Some("vc-name-plain".into()), None)
                .await
                .unwrap();

            assert!(
                jwt_subject(&response.credential)
                    .get("name")
                    .is_none()
            );
            assert_eq!(origin_of(issuer, &response.did).await, None);
        }

        #[tokio::test]
        async fn rename_reissues_with_new_name_and_same_did() {
            let f = fixture().await;
            f.save_surface("vc-name-rename", "OXYGEN")
                .await;
            let issuer = &f.issuer;
            let first = issuer
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-rename".into()), None)
                .await
                .unwrap();

            f.save_surface("vc-name-rename", "HELIUM")
                .await;
            let second = issuer
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-rename".into()), None)
                .await
                .unwrap();

            assert_eq!(second.did, first.did);
            assert!(!second.is_new);
            assert_eq!(jwt_subject(&second.credential)["name"], json!("HELIUM"));
        }

        #[tokio::test]
        async fn did_on_two_surfaces_gets_no_name() {
            let f = fixture().await;
            f.save_surface("vc-name-conflict-a", "OXYGEN")
                .await;
            f.save_surface("vc-name-conflict-b", "HELIUM")
                .await;
            let issuer = &f.issuer;
            let first = issuer
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-conflict-a".into()), None)
                .await
                .unwrap();

            let mut sibling =
                crate::identity::test_helpers::test_surface_identity_record(&first.did, "vc-name-conflict-b");
            sibling.identity_hash = "sibling".to_string();
            sibling.origin = Some(IdentityOrigin::Managed);
            issuer
                .get_identity_store()
                .create(sibling)
                .await
                .unwrap();

            let second = issuer
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-conflict-a".into()), None)
                .await
                .unwrap();

            assert_eq!(second.did, first.did);
            assert!(
                jwt_subject(&second.credential)
                    .get("name")
                    .is_none()
            );
        }

        #[tokio::test]
        async fn managed_wrapper_backfills_legacy_origin_without_overwriting() {
            let f = fixture().await;
            f.save_surface("vc-name-backfill", "OXYGEN")
                .await;
            let issuer = &f.issuer;
            let legacy = issuer
                .issue_or_get_credential(fields("legacy"), None, Some("vc-name-backfill".into()), None)
                .await
                .unwrap();
            let caller = issuer
                .issue_or_get_caller_credential(fields("caller"), None, Some("vc-name-backfill".into()), None)
                .await
                .unwrap();

            let backfilled = issuer
                .issue_or_get_managed_credential(fields("legacy"), None, Some("vc-name-backfill".into()), None)
                .await
                .unwrap();
            let still_caller = issuer
                .issue_or_get_managed_credential(fields("caller"), None, Some("vc-name-backfill".into()), None)
                .await
                .unwrap();

            assert_eq!(backfilled.did, legacy.did);
            assert_eq!(origin_of(issuer, &legacy.did).await, Some(IdentityOrigin::Managed));
            assert_eq!(jwt_subject(&backfilled.credential)["name"], json!("OXYGEN"));
            assert_eq!(origin_of(issuer, &caller.did).await, Some(IdentityOrigin::ExternalCaller));
            assert!(
                jwt_subject(&still_caller.credential)
                    .get("name")
                    .is_none()
            );
        }

        #[tokio::test]
        async fn display_name_for_did_follows_record_origin() {
            let f = fixture().await;
            f.save_surface("vc-name-vp", "OXYGEN")
                .await;
            let issuer = &f.issuer;
            let managed = issuer
                .issue_or_get_managed_credential(fields("m"), None, Some("vc-name-vp".into()), None)
                .await
                .unwrap();
            let caller = issuer
                .issue_or_get_caller_credential(fields("c"), None, Some("vc-name-vp".into()), None)
                .await
                .unwrap();

            assert_eq!(
                issuer
                    .display_name_for_did(&managed.did)
                    .await,
                Some(DisplayName::parse("OXYGEN").unwrap())
            );
            assert_eq!(
                issuer
                    .display_name_for_did(&caller.did)
                    .await,
                None
            );
            assert_eq!(
                issuer
                    .display_name_for_did("did:web:unknown")
                    .await,
                None
            );
        }

        #[tokio::test]
        async fn unknown_surface_issues_without_name() {
            let f = fixture().await;
            let issuer = &f.issuer;

            let response = issuer
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-missing-surface".into()), None)
                .await
                .unwrap();

            assert!(
                jwt_subject(&response.credential)
                    .get("name")
                    .is_none()
            );
            assert_eq!(origin_of(issuer, &response.did).await, Some(IdentityOrigin::Managed));
        }
    }

    /// Stands in for whichever backend `[vta]` selected (VTA-11a): records what
    /// it was asked to sign, and can report itself unreachable.
    struct RecordingAuthority {
        did: &'static str,
        reachable: bool,
        signed: std::sync::Mutex<Vec<serde_json::Value>>,
    }

    impl RecordingAuthority {
        fn new(
            did: &'static str,
            reachable: bool,
        ) -> Arc<Self> {
            Arc::new(Self {
                did,
                reachable,
                signed: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn claims(&self) -> Vec<serde_json::Value> {
            self.signed
                .lock()
                .unwrap()
                .clone()
        }
    }

    #[async_trait::async_trait]
    impl crate::identity::authority::CredentialAuthority for RecordingAuthority {
        async fn issuer_did(&self) -> Result<String> {
            Ok(self.did.to_string())
        }

        async fn issuer_jwks(&self) -> Result<serde_json::Value> {
            Ok(json!({ "keys": [] }))
        }

        async fn sign_token(
            &self,
            claims: &serde_json::Value,
        ) -> Result<String> {
            self.signed
                .lock()
                .unwrap()
                .push(claims.clone());
            if !self.reachable {
                anyhow::bail!("backend unreachable");
            }
            Ok("header.payload.signature".to_string())
        }

        async fn sign_token_typ(
            &self,
            claims: &serde_json::Value,
            _typ: &str,
        ) -> Result<String> {
            self.sign_token(claims).await
        }
    }

    fn decode_jwt_payload(jwt: &str) -> serde_json::Value {
        use base64::Engine as _;
        let payload = jwt
            .split('.')
            .nth(1)
            .expect("a compact JWS has three parts");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url payload");
        serde_json::from_slice(&bytes).expect("JSON payload")
    }

    /// With no connector selected the credential is signed by the local key and
    /// attributed to the local issuer DID — today's behaviour, unchanged.
    #[tokio::test]
    async fn agent_credential_signs_locally_when_no_connector_is_selected() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let identity_fields = HashMap::from([("name".to_string(), json!("agent-a"))]);

        let jwt = issuer
            .create_credential("did:example:agent-a", &identity_fields, None, None)
            .await
            .expect("local signing succeeds");

        let claims = decode_jwt_payload(&jwt);
        let local_did = issuer
            .get_issuer_did()
            .await
            .unwrap();
        assert_eq!(claims["issuer"], local_did);
        assert_eq!(claims["type"][1], "AgentIdentityCredential");
        assert_eq!(claims["credentialSubject"]["id"], "did:example:agent-a");
        assert_eq!(claims["credentialSubject"]["identityFields"]["name"], "agent-a");
    }

    /// Registering the local connector must not change the output: it signs
    /// with the same key and reports the same issuer DID.
    #[tokio::test]
    async fn the_local_connector_produces_the_same_issuer_as_no_connector() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let identity_fields = HashMap::from([("name".to_string(), json!("agent-b"))]);
        let local_did = issuer
            .get_issuer_did()
            .await
            .unwrap();

        issuer
            .set_signing_authority(Arc::new(crate::identity::authority::LocalCredentialAuthority::new(Arc::clone(
                &issuer,
            ))))
            .await;

        let jwt = issuer
            .create_credential("did:example:agent-b", &identity_fields, None, None)
            .await
            .expect("the local connector signs without deadlocking on the config lock");

        let claims = decode_jwt_payload(&jwt);
        assert_eq!(claims["issuer"], local_did);
    }

    /// With a connector selected, the credential is signed by it and the
    /// `issuer` claim names the connector's DID, not the local one.
    #[tokio::test]
    async fn agent_credential_signs_through_the_selected_connector() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let authority = RecordingAuthority::new("did:webvh:vta-under-test", true);
        issuer
            .set_signing_authority(authority.clone())
            .await;
        let identity_fields = HashMap::from([("name".to_string(), json!("agent-c"))]);

        let jwt = issuer
            .create_credential("did:example:agent-c", &identity_fields, None, None)
            .await
            .expect("the connector signs the credential");

        assert_eq!(jwt, "header.payload.signature");
        let claims = authority.claims();
        assert_eq!(claims.len(), 1, "exactly one signing call is made");
        assert_eq!(claims[0]["issuer"], "did:webvh:vta-under-test");
        assert_eq!(claims[0]["type"][1], "AgentIdentityCredential");
        assert_eq!(claims[0]["credentialSubject"]["id"], "did:example:agent-c");
        assert!(
            claims[0]["exp"]
                .as_i64()
                .unwrap()
                > claims[0]["iat"]
                    .as_i64()
                    .unwrap()
        );
    }

    /// A down connector fails closed: the error propagates, and no credential
    /// signed by a different (local) key is substituted.
    #[tokio::test]
    async fn an_unreachable_connector_fails_closed_without_a_local_fallback() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let authority = RecordingAuthority::new("did:webvh:vta-under-test", false);
        issuer
            .set_signing_authority(authority.clone())
            .await;
        let identity_fields = HashMap::from([("name".to_string(), json!("agent-d"))]);

        let err = issuer
            .create_credential("did:example:agent-d", &identity_fields, None, None)
            .await
            .expect_err("a down connector must not yield a credential");

        assert!(
            format!("{err:#}").contains("backend unreachable"),
            "the connector's failure must surface, got: {err:#}"
        );
        assert_eq!(authority.claims().len(), 1, "the failure came from the connector, not from a local fallback");
    }

    /// Installing the directory must change nothing for a surface that maps
    /// no signing of its own, or every existing deployment would start signing
    /// with a different key the moment this was wired up.
    #[tokio::test]
    async fn a_surface_that_maps_nothing_still_signs_with_the_appliance_key() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let appliance = RecordingAuthority::new("did:webvh:appliance", true);
        issuer
            .set_signing_authority(appliance.clone())
            .await;
        issuer
            .set_key_directory(
                empty_directory(Arc::clone(&appliance) as Arc<dyn crate::identity::authority::CredentialAuthority>)
                    .await,
            )
            .await;
        let identity_fields = HashMap::from([("name".to_string(), json!("agent-e"))]);

        issuer
            .create_credential("did:example:agent-e", &identity_fields, None, Some("surface-with-no-mapping"))
            .await
            .expect("an unmapped surface signs with the appliance key");

        let claims = appliance.claims();
        assert_eq!(claims.len(), 1, "the appliance connector still did the signing");
        assert_eq!(claims[0]["issuer"], "did:webvh:appliance", "an unmapped surface must keep the appliance issuer");
    }

    /// The point of the directory: a surface mapped to a different backend
    /// signs with that one instead of the appliance key. Mapped to `local`
    /// here because it is reachable in a unit test and still proves the
    /// override — the appliance connector must not be called at all.
    #[tokio::test]
    async fn a_surface_mapped_to_another_backend_does_not_use_the_appliance_key() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let appliance = RecordingAuthority::new("did:webvh:appliance", true);
        issuer
            .set_signing_authority(appliance.clone())
            .await;

        let local: Arc<dyn crate::identity::authority::CredentialAuthority> =
            Arc::new(crate::identity::authority::LocalCredentialAuthority::new(Arc::clone(&issuer)));
        let mut directory = crate::vta::key_directory::KeyDirectory::build(
            &crate::config::vta::VtaConfig::default(),
            Arc::clone(&local),
        )
        .await
        .expect("a disabled [vta] block builds a local-only directory");
        let surface = crate::config::agent_surface::AgentSurface {
            surface_id: "surface-mapped-local".to_string(),
            signing: Some(crate::config::agent_surface::SurfaceSigningConfig {
                backend: Some(crate::config::agent_surface::SigningBackendKind::Local),
                ..Default::default()
            }),
            ..Default::default()
        };
        directory
            .with_surface(&surface)
            .expect("a local mapping installs");
        issuer
            .set_key_directory(Arc::new(directory))
            .await;

        let identity_fields = HashMap::from([("name".to_string(), json!("agent-f"))]);
        let jwt = issuer
            .create_credential("did:example:agent-f", &identity_fields, None, Some("surface-mapped-local"))
            .await
            .expect("the mapped backend signs");

        assert!(appliance.claims().is_empty(), "the appliance connector must not sign for a surface mapped elsewhere");
        let claims = decode_jwt_payload(&jwt);
        assert_eq!(
            claims["issuer"],
            issuer
                .get_issuer_did()
                .await
                .unwrap(),
            "the issuer claim must name whoever actually signed"
        );
    }

    /// The appliance-wide default must apply when **no surface is in scope**
    /// — that is what "appliance-wide" means. Requiring a surface skipped the
    /// directory entirely for `/v1/identity/issue`, which passes none, so a
    /// gateway configured to sign through its trust agent silently kept
    /// signing locally while the dashboard reported the agent.
    #[tokio::test]
    async fn the_appliance_default_applies_when_no_surface_is_in_scope() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let appliance = RecordingAuthority::new("did:webvh:appliance", true);
        issuer
            .set_signing_authority(appliance.clone())
            .await;

        // A directory whose appliance-wide override points somewhere else.
        let local: Arc<dyn crate::identity::authority::CredentialAuthority> =
            Arc::new(crate::identity::authority::LocalCredentialAuthority::new(Arc::clone(&issuer)));
        let directory = crate::vta::key_directory::KeyDirectory::build(
            &crate::config::vta::VtaConfig::default(),
            Arc::clone(&local),
        )
        .await
        .expect("a disabled [vta] block builds a local-only directory");
        issuer
            .set_key_directory(Arc::new(directory))
            .await;

        let fields = HashMap::from([("name".to_string(), json!("no-surface"))]);
        let jwt = issuer
            .create_credential("did:example:no-surface", &fields, None, None)
            .await
            .expect("issuing without a surface succeeds");

        // The directory resolved it (to local, here), so the appliance
        // connector was never reached. Before the fix the directory was
        // skipped outright and this signed via `appliance`.
        assert!(appliance.claims().is_empty(), "the directory must be consulted even with no surface in scope");
        assert_eq!(
            decode_jwt_payload(&jwt)["issuer"],
            issuer
                .get_issuer_did()
                .await
                .unwrap()
        );
    }

    /// Backward compatibility for every deployment that has never configured
    /// a trust agent, in the shape production actually has: the directory is
    /// installed unconditionally, `[vta]` is disabled, no appliance override
    /// is set and no surface is in scope. The issued credential must be
    /// byte-for-byte the same as one issued with no directory at all.
    #[tokio::test]
    async fn a_gateway_that_never_configured_a_trust_agent_signs_exactly_as_before() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let fields = HashMap::from([("name".to_string(), json!("legacy"))]);

        // Before: no directory, no connector — the pre-VTA gateway.
        let before = issuer
            .create_credential("did:example:legacy", &fields, None, None)
            .await
            .expect("pre-VTA issuance");

        // After: the directory is installed exactly as the router installs it
        // for a gateway with no `[vta]` block, and nothing is overridden.
        let local: Arc<dyn crate::identity::authority::CredentialAuthority> =
            Arc::new(crate::identity::authority::LocalCredentialAuthority::new(Arc::clone(&issuer)));
        let directory = crate::vta::key_directory::KeyDirectory::build(
            &crate::config::vta::VtaConfig::default(),
            Arc::clone(&local),
        )
        .await
        .expect("a disabled [vta] block always builds");
        issuer
            .set_key_directory(Arc::new(directory))
            .await;

        let after = issuer
            .create_credential("did:example:legacy", &fields, None, None)
            .await
            .expect("issuance after the directory is installed");

        assert_eq!(
            decode_jwt_payload(&before)["issuer"],
            decode_jwt_payload(&after)["issuer"],
            "installing the directory must not change which key signs for a gateway with no trust agent"
        );
        assert_eq!(
            decode_jwt_payload(&after)["issuer"],
            issuer
                .get_issuer_did()
                .await
                .unwrap(),
            "and that key is still the gateway's own"
        );
    }

    /// A local-only directory, for asserting the no-op case.
    async fn empty_directory(
        local: Arc<dyn crate::identity::authority::CredentialAuthority>
    ) -> Arc<crate::vta::key_directory::KeyDirectory> {
        Arc::new(
            crate::vta::key_directory::KeyDirectory::build(&crate::config::vta::VtaConfig::default(), local)
                .await
                .expect("a disabled [vta] block builds a local-only directory"),
        )
    }

    // ─── Data-Integrity agent-identity credential (VTA-11b) ───────────────

    /// A `VcIssuer` that records what it was asked for and returns a fixed
    /// credential, standing in for the VTA's context-scoped issue task.
    struct RecordingVcIssuer {
        issued: Arc<std::sync::Mutex<Vec<String>>>,
        credential: serde_json::Value,
    }

    #[async_trait::async_trait]
    impl crate::identity::ssi::vc_issuer::VcIssuer for RecordingVcIssuer {
        async fn issue<'a>(
            &self,
            payload: crate::identity::ssi::vc_issuer::IssueVcPayload<'a>,
        ) -> anyhow::Result<serde_json::Value> {
            let crate::identity::ssi::vc_issuer::IssueVcPayload::AgentIdentity(agent) = payload;
            self.issued
                .lock()
                .expect("lock")
                .push(agent.did.to_string());
            Ok(self.credential.clone())
        }
    }

    /// Once a VTA-backed issuer is bound, the Data-Integrity credential comes
    /// from it rather than from the local issuer — which is the whole point of
    /// moving the key off this process.
    #[tokio::test]
    async fn the_di_credential_is_issued_by_the_bound_vta_issuer() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let identity_fields = HashMap::from([("name".to_string(), json!("agent-di"))]);
        let agent_did = issuer
            .issue_or_get_credential(identity_fields.clone(), None, None, None)
            .await
            .expect("agent identity")
            .did;

        // Start from a real locally-issued credential and only change its
        // issuer, so the stand-in is JSON-LD valid and the presentation signs
        // exactly as it would over a real VTA credential.
        let local_vp = issuer
            .create_agent_identity_presentation_with_binding(&agent_did, &identity_fields, None, None, None, None)
            .await
            .expect("a locally issued presentation to borrow a credential from");
        let local_vp: serde_json::Value = serde_json::from_str(&local_vp).expect("the VP is JSON");
        let mut vta_credential = first_credential(&local_vp);
        vta_credential["issuer"] = json!("did:webvh:vta-context");

        let recorder = Arc::new(RecordingVcIssuer {
            issued: Arc::new(std::sync::Mutex::new(Vec::new())),
            credential: vta_credential.clone(),
        });
        issuer
            .set_di_vc_issuer(recorder.clone())
            .await;

        let vp = issuer
            .create_agent_identity_presentation_with_binding(&agent_did, &identity_fields, None, None, None, None)
            .await
            .expect("the presentation is issued over the VTA-issued credential");

        assert_eq!(
            recorder
                .issued
                .lock()
                .expect("lock")
                .as_slice(),
            std::slice::from_ref(&agent_did),
            "the VTA issuer must be asked for exactly this agent"
        );

        let vp: serde_json::Value = serde_json::from_str(&vp).expect("the VP is JSON");
        assert_eq!(
            first_credential(&vp)["issuer"],
            json!("did:webvh:vta-context"),
            "the embedded credential must be the VTA's, not a locally signed one"
        );
    }

    /// `verifiableCredential` is an object for a single credential and an array
    /// for several; both shapes are legal, so tests read through this.
    fn first_credential(vp: &serde_json::Value) -> serde_json::Value {
        let field = &vp["verifiableCredential"];
        match field {
            serde_json::Value::Array(items) => items
                .first()
                .cloned()
                .expect("the VP carries at least one credential"),
            other => other.clone(),
        }
    }

    /// With no VTA issuer bound, issuance stays exactly where it was.
    #[tokio::test]
    async fn the_di_credential_falls_back_to_the_local_issuer() {
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let identity_fields = HashMap::from([("name".to_string(), json!("agent-local-di"))]);
        let agent_did = issuer
            .issue_or_get_credential(identity_fields.clone(), None, None, None)
            .await
            .expect("agent identity")
            .did;

        let vp = issuer
            .create_agent_identity_presentation_with_binding(&agent_did, &identity_fields, None, None, None, None)
            .await
            .expect("the local issuer still issues when no VTA is bound");

        let vp: serde_json::Value = serde_json::from_str(&vp).expect("the VP is JSON");
        let credential = first_credential(&vp);
        assert_eq!(credential["proof"]["cryptosuite"], "eddsa-rdfc-2022", "the local issuer's suite is unchanged");
        assert_eq!(
            credential["credentialSubject"]["id"], agent_did,
            "the local credential is still bound to the agent"
        );
    }
}

/// End-to-end proof that a per-surface mapping reaches a **real** VTA.
///
/// Unit tests can only show the directory is consulted; they cannot show the
/// resolved key is actually held by a trust agent. This signs through a live
/// VTA and asserts the issuer is not this gateway's local key.
///
/// Requires a running VTA whose granted context the gateway can reach:
///
/// ```sh
/// VTA_LIVE_URL=http://127.0.0.1:3000 \
/// VTA_LIVE_DID=did:webvh:<scid>:localhost%3A3000 \
/// VTA_LIVE_PARENT_CONTEXT=<the granted context> \
///   cargo test --bin agent-trust-gateway \
///     identity::vc_issuer::live_tests \
///     -- --ignored --nocapture --test-threads=1
/// ```
///
/// `--test-threads=1` for the same reason as the other live suites: a second
/// session for the same control DID supersedes the first.
#[cfg(test)]
mod live_tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    const LIVE_SEED_VAR: &str = "VTA_LIVE_CONTROL_SEED";

    /// Mint a signing key in the granted context and return the config that
    /// names it. Self-contained on purpose: the key is what `keys/sign-jws`
    /// addresses, so a test that required one to be created by hand could not
    /// be run from a clean VTA.
    async fn live_config() -> crate::config::vta::VtaConfig {
        use crate::vta::client::VtaRestClient;
        use crate::vta::control_key::ControlKey;

        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID to the VTA did:webvh");
        let context =
            std::env::var("VTA_LIVE_PARENT_CONTEXT").expect("set VTA_LIVE_PARENT_CONTEXT to the granted context");
        if std::env::var(LIVE_SEED_VAR).is_err() {
            // The seed the other live suites use, so one grant covers them all.
            unsafe { std::env::set_var(LIVE_SEED_VAR, "2a".repeat(32)) };
        }

        // The same seed the hex above encodes, and the one the other live
        // suites authenticate with, so a single ACL grant covers them all.
        let control = Arc::new(ControlKey::from_seed([0x2a; 32]));
        let client = VtaRestClient::new(&url, &vta_did, control, std::time::Duration::from_secs(15), 8, None)
            .expect("build a live client");
        let idx: u32 = rand::random::<u32>() % 2_000_000;
        let key_id = format!("gateway-surface-e2e-{idx}");
        let _created: serde_json::Value = client
            .dispatch_signed(
                "https://trusttasks.org/spec/keys/create/0.1",
                json!({
                    "keyType": "ed25519",
                    "keyId": key_id,
                    "label": "gateway-surface-e2e",
                    "internal": true,
                }),
            )
            .await
            .expect("the granted control DID can mint a key in its context");

        crate::config::vta::VtaConfig {
            enabled: true,
            base_url: Some(url),
            vta_did: Some(vta_did),
            context_id: Some(context),
            signing_key_id: Some(key_id),
            auth_key_source: Some(format!("env://{LIVE_SEED_VAR}")),
            ..Default::default()
        }
    }

    fn payload(jwt: &str) -> serde_json::Value {
        use base64::Engine;
        let part = jwt
            .split('.')
            .nth(1)
            .expect("a JWT has three parts");
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .expect("base64url payload");
        serde_json::from_slice(&raw).expect("JSON payload")
    }

    /// A surface mapped to the VTA signs with a key the VTA holds, while the
    /// appliance default stays local — so the two are demonstrably different
    /// keys, which is the entire point of per-surface mapping.
    #[tokio::test]
    #[ignore = "requires a running VTA; see the module docs"]
    async fn a_surface_mapped_to_a_live_vta_signs_with_the_agents_key() {
        let config = live_config().await;
        let context = config
            .context_id
            .clone()
            .expect("set above");
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let local_did = issuer
            .get_issuer_did()
            .await
            .expect("the gateway has a local issuer DID");

        let local: Arc<dyn crate::identity::authority::CredentialAuthority> =
            Arc::new(crate::identity::authority::LocalCredentialAuthority::new(Arc::clone(&issuer)));
        let mut directory = crate::vta::key_directory::KeyDirectory::build(&config, Arc::clone(&local))
            .await
            .expect("the live VTA is reachable and the control DID is granted");

        let surface = crate::config::agent_surface::AgentSurface {
            surface_id: "live-mapped-surface".to_string(),
            signing: Some(crate::config::agent_surface::SurfaceSigningConfig {
                backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
                context_id: Some(context.clone()),
                // `jwt` keys are named explicitly (D-11): `keys/sign-jws`
                // addresses the key, so the mapping has to say which one.
                key_id: config.signing_key_id.clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        directory
            .with_surface(&surface)
            .expect("a VTA mapping naming an existing context installs");
        issuer
            .set_key_directory(Arc::new(directory))
            .await;

        let fields = HashMap::from([("name".to_string(), json!("live-agent"))]);
        let jwt = issuer
            .create_credential("did:example:live-agent", &fields, None, Some("live-mapped-surface"))
            .await
            .expect("the live VTA signs the credential");

        let claims = payload(&jwt);
        eprintln!("LIVE_ISSUER={} LOCAL_ISSUER={local_did}", claims["issuer"]);
        assert_ne!(claims["issuer"], local_did, "a VTA-mapped surface must not be signed by the gateway's own key");
        assert_eq!(claims["credentialSubject"]["id"], "did:example:live-agent");

        // A second surface on the same gateway, mapped back to the local
        // key, must sign with that one. This is the property per-surface
        // mapping exists for: two surfaces, one appliance, different keys at
        // the same time. Asserting the *unmapped* case here would prove
        // nothing — with `[vta]` enabled the appliance default is the VTA, so
        // an unmapped surface correctly resolves to it as well.
        let local_surface = crate::config::agent_surface::AgentSurface {
            surface_id: "live-local-surface".to_string(),
            signing: Some(crate::config::agent_surface::SurfaceSigningConfig {
                backend: Some(crate::config::agent_surface::SigningBackendKind::Local),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut directory = crate::vta::key_directory::KeyDirectory::build(&config, Arc::clone(&local))
            .await
            .expect("rebuild with both mappings");
        directory
            .with_surface(&surface)
            .expect("the VTA mapping installs");
        directory
            .with_surface(&local_surface)
            .expect("the local mapping installs");
        issuer
            .set_key_directory(Arc::new(directory))
            .await;

        let via_local = issuer
            .create_credential("did:example:local-agent", &fields, None, Some("live-local-surface"))
            .await
            .expect("the locally-mapped surface signs");
        assert_eq!(
            payload(&via_local)["issuer"],
            local_did,
            "a surface mapped to the local backend must sign with the gateway key"
        );

        let via_vta = issuer
            .create_credential("did:example:live-agent", &fields, None, Some("live-mapped-surface"))
            .await
            .expect("the VTA-mapped surface still signs");
        assert_ne!(
            payload(&via_vta)["issuer"],
            payload(&via_local)["issuer"],
            "two surfaces on one gateway must be able to sign with different keys"
        );

        // The appliance-wide dashboard setting, end to end: with the local key
        // as the `[vta]`-derived default, an override pointing at the live VTA
        // must move an *unmapped* surface onto it. This is the path an
        // operator takes in Settings, so it is worth proving against a real
        // agent rather than a stub.
        struct Override(crate::config::agent_surface::SurfaceSigningConfig);
        impl crate::vta::key_directory::ApplianceSigningDefault for Override {
            fn signing(&self) -> Option<crate::config::agent_surface::SurfaceSigningConfig> {
                Some(self.0.clone())
            }
        }

        let appliance_override = crate::config::agent_surface::SurfaceSigningConfig {
            backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
            connection_id: None,
            context_id: Some(context.clone()),
            key_id: config.signing_key_id.clone(),
        };
        let directory = crate::vta::key_directory::KeyDirectory::build(&config, Arc::clone(&local))
            .await
            .expect("rebuild for the appliance override")
            .with_appliance_default(Arc::new(Override(appliance_override)));
        issuer
            .set_key_directory(Arc::new(directory))
            .await;

        let unmapped = issuer
            .create_credential("did:example:appliance-agent", &fields, None, Some("a-surface-that-maps-nothing"))
            .await
            .expect("the appliance override signs for an unmapped surface");
        assert_ne!(
            payload(&unmapped)["issuer"],
            local_did,
            "the dashboard override must move the whole appliance onto the trust agent"
        );
    }
}

/// The **connection-record** signing path, end to end against a live VTA.
///
/// Distinct from `live_tests`, which builds the directory from the `[vta]`
/// block and therefore exercises the *bootstrap* connector. Production
/// signing for a dashboard-created agent goes through the **registry**, and
/// that path carried two bugs this module exists to stop recurring: the
/// connector was built with the connection's context as its key id, and a
/// surface's `key_id` was discarded. Both produced a working-looking gateway
/// that signed with the wrong key or refused entirely.
///
/// ```sh
/// VTA_LIVE_URL=http://127.0.0.1:3000 \
/// VTA_LIVE_DID=did:webvh:<scid>:localhost%3A3000 \
/// VTA_LIVE_PARENT_CONTEXT=<the granted context> \
///   cargo test --bin agent-trust-gateway \
///     identity::vc_issuer::live_connection_tests \
///     -- --ignored --nocapture --test-threads=1
/// ```
#[cfg(test)]
mod live_connection_tests {
    use super::*;
    use crate::vta::connections::{
        FileSystemVtaConnectionStore, SigningKey, SigningKeys, VtaConnection, VtaConnectionStatus,
        VtaConnectionStorage, VtaConnectionTransport,
    };
    use serde_json::json;
    use std::collections::HashMap;

    /// The seed the other live suites authenticate with, so one ACL grant
    /// covers them all.
    const LIVE_SEED: [u8; 32] = [0x2a; 32];
    const CONTROL_SECRET_ID: &str = "vta-control-key-live";

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("set {name}; see the module docs"))
    }

    fn payload(jwt: &str) -> serde_json::Value {
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                jwt.split('.')
                    .nth(1)
                    .expect("a JWT has three parts"),
            )
            .expect("base64url payload");
        serde_json::from_slice(&raw).expect("JSON payload")
    }

    fn header(jwt: &str) -> serde_json::Value {
        use base64::Engine;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                jwt.split('.')
                    .next()
                    .expect("a JWT has three parts"),
            )
            .expect("base64url header");
        serde_json::from_slice(&raw).expect("JSON header")
    }

    /// Mint a key in the granted context, returning its id.
    async fn mint_key(client: &Arc<crate::vta::client::VtaRestClient>) -> String {
        let key_id = format!("live-conn-{}", uuid::Uuid::new_v4());
        let _: serde_json::Value = client
            .dispatch_signed(
                "https://trusttasks.org/spec/keys/create/0.1",
                json!({
                    "keyType": "ed25519",
                    "keyId": key_id,
                    "label": "live connection test",
                    "internal": true,
                }),
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "could not mint a key as {}.\n\
                     Grant it first (stop the VTA, it holds a file lock):\n  \
                     vta --config <cfg> acl create --did {} --role initiator \
                     --contexts <context> --capabilities context-create,key-mint,sign\n\
                     underlying error: {e}",
                    control_did(),
                    control_did(),
                )
            });
        key_id
    }

    /// The DID the fixed test seed resolves to — the one that must be granted.
    fn control_did() -> String {
        use crate::vta::control_key::SignerKeyProvider;
        crate::vta::control_key::ControlKey::from_seed(LIVE_SEED)
            .did()
            .to_string()
    }

    /// A surface mapped to a **stored connection** signs with the key that
    /// connection holds, and the credential names the agent as issuer.
    ///
    /// This is the path a dashboard-created agent actually uses. It failed in
    /// production while the `[vta]`-block test passed, because the connector
    /// was built with `default_context_id` as its key id — the agent refused
    /// with "key `<context>` is not within the caller's scope".
    #[tokio::test]
    #[ignore = "requires a running VTA; see the module docs"]
    async fn a_surface_mapped_to_a_stored_connection_signs_with_its_key() {
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = env("VTA_LIVE_DID");
        let context = env("VTA_LIVE_PARENT_CONTEXT");
        let tmp = tempfile::tempdir().expect("tempdir");

        // A client on the granted control key, used to mint the keys the
        // connection will then be recorded as holding.
        let control = Arc::new(crate::vta::control_key::ControlKey::from_seed(LIVE_SEED));
        let client = Arc::new(
            crate::vta::client::VtaRestClient::new(
                &url,
                &vta_did,
                control,
                std::time::Duration::from_secs(15),
                8,
                None,
            )
            .expect("build a live client"),
        );
        let active_key = mint_key(&client).await;
        let other_key = mint_key(&client).await;

        // The control key as the connection's secret, exactly as the pairing
        // wizard stores it.
        let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                tmp.path()
                    .join("secrets")
                    .to_str()
                    .unwrap(),
            )
            .await
            .expect("secrets store"),
        );
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "live control key".to_string(),
                secret_id: CONTROL_SECRET_ID.to_string(),
                description: None,
                value: LIVE_SEED
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                secret_type: "General".to_string(),
                tags: vec!["vta".to_string()],
            })
            .await
            .expect("store the control key");

        let store = Arc::new(
            FileSystemVtaConnectionStore::new(tmp.path().join("connections"))
                .await
                .expect("connection store"),
        );
        let now = chrono::Utc::now();
        store
            .create(VtaConnection {
                id: "live-conn".to_string(),
                tenant_id: None,
                name: "Live agent".to_string(),
                description: None,
                enabled: true,
                transport: VtaConnectionTransport::Https,
                endpoint: url.clone(),
                vta_did: vta_did.clone(),
                default_context_id: Some(context.clone()),
                control_key_ref: Some(CONTROL_SECRET_ID.to_string()),
                status: VtaConnectionStatus::Connected,
                keys: SigningKeys {
                    active: Some(SigningKey {
                        key_id: active_key.clone(),
                        public_key: None,
                        label: None,
                        added_at: now,
                        retired_at: None,
                    }),
                    retiring: Vec::new(),
                },
                pairing: crate::vta::pairing::PairingRecord {
                    state: crate::vta::pairing::PairingState::Connected,
                    pinned_vta_did: Some(vta_did.clone()),
                    ..Default::default()
                },
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("store the connection");

        let registry = Arc::new(crate::vta::registry::VtaConnectionRegistry::new(
            store,
            Some(Arc::clone(&secrets)),
            None,
            None,
            std::time::Duration::from_secs(15),
            8,
        ));

        let (issuer, _issuer_tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let local_did = issuer
            .get_issuer_did()
            .await
            .expect("local issuer DID");
        let local: Arc<dyn crate::identity::authority::CredentialAuthority> =
            Arc::new(crate::identity::authority::LocalCredentialAuthority::new(Arc::clone(&issuer)));

        // `[vta]` disabled: everything must come from the connection record,
        // which is the shape a dashboard-only deployment has.
        let mut directory =
            crate::vta::key_directory::KeyDirectory::build(&crate::config::vta::VtaConfig::default(), local)
                .await
                .expect("a disabled [vta] block builds")
                .with_connections(Arc::clone(&registry));

        let surface = |id: &str, key: Option<&str>| crate::config::agent_surface::AgentSurface {
            surface_id: id.to_string(),
            signing: Some(crate::config::agent_surface::SurfaceSigningConfig {
                backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
                connection_id: Some("live-conn".to_string()),
                context_id: Some(context.clone()),
                key_id: key.map(str::to_string),
            }),
            ..Default::default()
        };
        directory
            .with_surface(&surface("s-default", Some(&active_key)))
            .expect("the default mapping installs");
        directory
            .with_surface(&surface("s-other", Some(&other_key)))
            .expect("the second mapping installs");
        issuer
            .set_key_directory(Arc::new(directory))
            .await;

        let fields = HashMap::from([("name".to_string(), json!("live-conn"))]);

        let first = issuer
            .create_credential("did:example:live-a", &fields, None, Some("s-default"))
            .await
            .expect("the stored connection signs");
        assert_eq!(
            payload(&first)["issuer"],
            vta_did,
            "a connection-backed surface must be issued by the agent, not the gateway"
        );
        assert_ne!(payload(&first)["issuer"], local_did);
        assert_eq!(header(&first)["kid"], active_key, "it must sign with the connection's key, never its context");

        // The property the `key_id` fix exists for: a second surface on the
        // *same* connection signs with a different key, so rotating or
        // revoking one cannot affect the other.
        let second = issuer
            .create_credential("did:example:live-b", &fields, None, Some("s-other"))
            .await
            .expect("the second surface signs");
        assert_eq!(
            header(&second)["kid"],
            other_key,
            "a surface's key_id must be honoured, not replaced by the connection's active key"
        );
        assert_ne!(
            header(&first)["kid"],
            header(&second)["kid"],
            "two surfaces on one connection must be able to use different keys"
        );
    }
}

/// Does a surface mapped to a trust agent actually reach it when the gateway
/// injects a presentation?
///
/// Every layer of this was unit-tested and the answer was still no, three
/// times over: the choice was not saved, the backend was believed unable to
/// issue credentials, and the mapping was only read at startup. None of them
/// failed — each quietly signed locally — so the only way to see it is to
/// assert that the agent was *contacted*.
#[cfg(test)]
mod surface_injection_tests {
    use super::*;
    use axum::{Json as AxumJson, Router, extract::State, routing::post};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct Recorder {
        issue_calls: Arc<AtomicUsize>,
        last_context: Arc<std::sync::Mutex<Option<String>>>,
    }

    /// Minimal agent: authenticates anything, records credential issuance and
    /// returns a credential shaped like the real `issue-in-context` reply.
    async fn trust_tasks(
        State(rec): State<Recorder>,
        AxumJson(body): AxumJson<serde_json::Value>,
    ) -> AxumJson<serde_json::Value> {
        let type_uri = body
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if type_uri.contains("auth/challenge") {
            return AxumJson(json!({ "challenge": "c", "sessionId": "s" }));
        }
        if type_uri.contains("auth/authenticate") {
            return AxumJson(json!({
                "session": { "id": "s", "subject": body["issuer"] },
                "tokens": { "accessToken": "tok", "tokenType": "Bearer", "expiresIn": 3600 }
            }));
        }
        if type_uri.contains("contexts/get") {
            // Already identified, so the issuer does not try to give it one.
            return AxumJson(json!({
                "context": { "id": "ctx-a", "did": "did:key:zCtx", "issuerKeyId": "ctx-a-issuer",
                             "designatedPurposes": ["assertionMethod"] }
            }));
        }
        if type_uri.contains("credentials/issue-in-context") {
            rec.issue_calls
                .fetch_add(1, Ordering::SeqCst);
            *rec.last_context
                .lock()
                .unwrap() = body["payload"]["contextId"]
                .as_str()
                .map(str::to_owned);
            return AxumJson(json!({
                "credentialId": "urn:uuid:1",
                "credential": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential"],
                    "issuer": "did:key:zCtx",
                    "credentialSubject": { "id": body["payload"]["holder"] },
                    "proof": { "type": "DataIntegrityProof", "verificationMethod": "did:key:zCtx#zCtx" }
                },
                "verificationMethod": "did:key:zCtx#zCtx"
            }));
        }
        AxumJson(json!({ "ok": true }))
    }

    async fn spawn_agent() -> (String, Recorder) {
        let rec = Recorder {
            issue_calls: Arc::new(AtomicUsize::new(0)),
            last_context: Arc::new(std::sync::Mutex::new(None)),
        };
        let app = Router::new()
            .route("/trust-tasks", post(trust_tasks))
            .with_state(rec.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        (format!("http://{addr}"), rec)
    }

    /// The whole chain, as the proxy drives it: a surface that names an agent
    /// must have that agent issue the credential embedded in the presentation
    /// it forwards.
    #[tokio::test]
    async fn a_surface_mapped_to_an_agent_has_it_issue_the_embedded_credential() {
        let (agent_url, recorder) = spawn_agent().await;
        let tmp = tempfile::tempdir().expect("tempdir");

        // The control key the connection authenticates with.
        let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                tmp.path()
                    .join("secrets")
                    .to_str()
                    .unwrap(),
            )
            .await
            .expect("secrets store"),
        );
        secrets
            .create(crate::secrets::CreateSecretRequest {
                tenant_id: None,
                name: "control".to_string(),
                secret_id: "ctl".to_string(),
                description: None,
                value: [0x2a_u8; 32]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                secret_type: "General".to_string(),
                tags: vec!["vta".to_string()],
            })
            .await
            .expect("store the control key");

        let connections = Arc::new(
            crate::vta::connections::FileSystemVtaConnectionStore::new(tmp.path().join("conns"))
                .await
                .expect("connection store"),
        );
        let now = chrono::Utc::now();
        crate::vta::connections::VtaConnectionStorage::create(
            connections.as_ref(),
            crate::vta::connections::VtaConnection {
                id: "vta-a".to_string(),
                tenant_id: None,
                name: "Agent".to_string(),
                description: None,
                enabled: true,
                transport: crate::vta::connections::VtaConnectionTransport::Https,
                endpoint: agent_url.clone(),
                vta_did: "did:webvh:agent.example".to_string(),
                default_context_id: Some("ctx-a".to_string()),
                control_key_ref: Some("ctl".to_string()),
                status: crate::vta::connections::VtaConnectionStatus::Connected,
                keys: Default::default(),
                pairing: crate::vta::pairing::PairingRecord {
                    state: crate::vta::pairing::PairingState::Connected,
                    pinned_vta_did: Some("did:webvh:agent.example".to_string()),
                    ..Default::default()
                },
                created_at: now,
                updated_at: now,
            },
        )
        .await
        .expect("store the connection");

        // The surface, saved **after** the directory is built — the shape an
        // operator creates one in.
        let surfaces = Arc::new(
            crate::surfaces::FileSystemAgentSurfaceStore::new(tmp.path().join("surfaces"))
                .await
                .expect("surface store"),
        ) as Arc<dyn crate::surfaces::AgentSurfaceStore>;

        let (issuer, _issuer_tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let local: Arc<dyn crate::identity::authority::CredentialAuthority> =
            Arc::new(crate::identity::authority::LocalCredentialAuthority::new(Arc::clone(&issuer)));
        let registry = Arc::new(crate::vta::registry::VtaConnectionRegistry::new(
            connections,
            Some(Arc::clone(&secrets)),
            None,
            None,
            std::time::Duration::from_secs(5),
            4,
        ));
        let directory =
            crate::vta::key_directory::KeyDirectory::build(&crate::config::vta::VtaConfig::default(), local)
                .await
                .expect("a disabled [vta] block builds")
                .with_connections(registry)
                .with_surface_store(Arc::clone(&surfaces));
        issuer
            .set_key_directory(Arc::new(directory))
            .await;

        crate::surfaces::AgentSurfaceStore::save(
            surfaces.as_ref(),
            &crate::config::agent_surface::AgentSurface {
                surface_id: "surface-1".to_string(),
                signing: Some(crate::config::agent_surface::SurfaceSigningConfig {
                    backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
                    connection_id: Some("vta-a".to_string()),
                    context_id: Some("ctx-a".to_string()),
                    key_id: Some("gateway-jwt-1".to_string()),
                }),
                ..Default::default()
            },
        )
        .await
        .expect("save the surface");

        // Onboard an agent, so the presentation has a holder whose key
        // the gateway can find. Counted separately: this step issues a
        // credential too, and the assertion below is about the injection.
        let mut fields = std::collections::HashMap::new();
        fields.insert("sub".to_string(), serde_json::json!("alice"));
        let onboarded = issuer
            .issue_or_get_credential(fields.clone(), None, None, None)
            .await
            .expect("onboard an agent");
        let agent_did = onboarded.did;
        recorder
            .issue_calls
            .store(0, Ordering::SeqCst);
        let outcome = issuer
            .create_agent_identity_presentation_with_binding(&agent_did, &fields, None, None, None, Some("surface-1"))
            .await;
        // The outcome is deliberately not asserted: this mock returns a
        // skeleton credential, not one rich enough to assemble a presentation
        // from. What is being proved is that the surface's agent was *asked* —
        // every bug behind this symptom silently signed locally instead, and
        // produced a perfectly valid presentation while doing so.
        let _ = outcome;

        assert_eq!(
            recorder
                .issue_calls
                .load(Ordering::SeqCst),
            1,
            "the surface's agent must issue the embedded credential; 0 means the \
             gateway signed locally and the agent never saw the request"
        );
        assert_eq!(
            recorder
                .last_context
                .lock()
                .unwrap()
                .as_deref(),
            Some("ctx-a"),
            "issued in the surface's own context"
        );
    }
}
