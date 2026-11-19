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

use crate::identity::ssi::vc_issuer::{
    AgentIdentity, DEFAULT_SIGNING_KEY_ID, IssueVcPayload, LocalVcIssuer, LocalVcSigner, VcIssuer,
};
use crate::identity::ssi::verifier::{LocalVerifier, Verifier};
use crate::identity::ssi::vp_issuer::{Credentials, LocalVpIssuer, LocalVpSigner, VpIssuer, VpIssuerPayload};

use super::display_name::{DisplayName, ManagedDisplayName, SurfacesByDidCache, resolve_managed_display_name_in};
use super::filesystem::{AgentIdentityRecord, IdentityOrigin, ManagedIdentitySource};
use super::{IdentityStore, VpChallengeStore};

const IS_VP_CHALLENGE_REQUIRED_DEFAULT: bool = false;

/// Longest wait for a gateway DID log version's `versionTime` to pass before a new version is
/// appended after it.
#[cfg(feature = "didwebvh")]
const MAX_VERSION_TIME_WAIT_SECS: i64 = 2;

/// Lock file in the issuer storage directory that serializes creating, upgrading and repairing
/// the gateway DID between gateways sharing the directory.
const GATEWAY_DID_LOCK_FILE: &str = ".gateway_did.lock";

const GATEWAY_DID_CREATE_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn lock_gateway_did(
    storage_path: &Path,
    timeout: std::time::Duration,
) -> crate::storage::file_lock::LockOutcome {
    crate::storage::file_lock::lock_exclusive(&storage_path.join(GATEWAY_DID_LOCK_FILE), timeout).await
}

fn extract_domain_from_proxy_did(proxy_did: &str) -> String {
    crate::identity::utils::extract_domain_from_did(proxy_did)
}

/// The public JWK of a DIDComm key-agreement secret, without its private `d` parameter.
pub(crate) fn public_key_agreement_jwk(
    secret: &affinidi_tdk_common::secrets_resolver::secrets::Secret,
    label: &str,
) -> Result<serde_json::Value> {
    let affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial::JWK(jwk) = &secret.secret_material else {
        return Err(anyhow::anyhow!("{} secret is not a JWK", label));
    };
    let mut public_jwk = serde_json::to_value(jwk)?;
    if let Some(obj) = public_jwk.as_object_mut() {
        obj.remove("d");
    }
    Ok(public_jwk)
}

/// How long to wait before appending a log version after one dated `previous_time`: a
/// version's `versionTime`, in whole seconds, must be later than the previous one's, which a
/// log published earlier in the same startup can share. A `versionTime` further ahead comes
/// from a clock that is off and is refused rather than waited out.
#[cfg(feature = "didwebvh")]
fn wait_before_next_version(
    previous_time: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<std::time::Duration>> {
    let wait = (previous_time + chrono::Duration::seconds(1)).signed_duration_since(now);
    if wait > chrono::Duration::seconds(MAX_VERSION_TIME_WAIT_SECS) {
        anyhow::bail!(
            "the latest gateway DID log version is dated {previous_time}, ahead of this node's clock; \
             the repair runs again on the next start"
        );
    }
    Ok(wait.to_std().ok())
}

/// Verification relationships the gateway signing key is listed under: credentials and
/// presentations it signs claim one of them as their proof purpose.
#[cfg(feature = "didwebvh")]
const SIGNING_KEY_RELATIONSHIPS: [&str; 2] = ["assertionMethod", "authentication"];

/// Adds `multikey_id` to each of [`SIGNING_KEY_RELATIONSHIPS`] that does not list it yet;
/// returns false when all of them already do. Refuses, changing nothing, a document that does
/// not publish `multikey_id` as the Multikey of `signing_key`, so only the gateway's own signing
/// key is ever authorized, or that lacks one of those relationships.
#[cfg(feature = "didwebvh")]
fn add_signing_key_to_relationships(
    document: &mut serde_json::Value,
    multikey_id: &str,
    signing_key: &JWK,
) -> Result<bool> {
    let expected_key = crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(signing_key)?;
    let mut matching = document["verificationMethod"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|method| method["id"] == multikey_id);
    let published = matching
        .next()
        .with_context(|| format!("DID document does not publish {multikey_id}"))?;
    anyhow::ensure!(matching.next().is_none(), "DID document publishes {multikey_id} more than once");
    anyhow::ensure!(
        published["type"] == "Multikey" && published["publicKeyMultibase"] == expected_key.as_str(),
        "DID document publishes a key other than the gateway signing key as {multikey_id}"
    );
    for relationship in SIGNING_KEY_RELATIONSHIPS {
        anyhow::ensure!(document[relationship].is_array(), "DID document has no {relationship}");
    }

    let mut changed = false;
    for relationship in SIGNING_KEY_RELATIONSHIPS {
        let ids = document
            .get_mut(relationship)
            .and_then(serde_json::Value::as_array_mut)
            .with_context(|| format!("DID document has no {relationship}"))?;
        if !ids
            .iter()
            .any(|id| *id == multikey_id)
        {
            ids.push(json!(multikey_id));
            changed = true;
        }
    }
    Ok(changed)
}

/// The parallel `did:web` document of a `did:webvh` log state, encoded as the gateway serves it
/// at `/.well-known/did.json`, which reads the state as a typed DID document.
#[cfg(feature = "didwebvh")]
fn parallel_did_document(
    state: &serde_json::Value,
    proxy_did: &str,
    scid: &str,
) -> Result<serde_json::Value> {
    let typed: crate::identity::didwebvh::types::DidDocument = serde_json::from_value(state.clone())?;
    Ok(crate::identity::didwebvh::generate_parallel_did_web(&serde_json::to_value(&typed)?, proxy_did, scid))
}

/// The gateway's DID document. The Ed25519 signing key is published twice: as `#key-1`
/// (JsonWebKey2020) and as the Multikey the `eddsa-rdfc-2022` signer references. Both are
/// listed under `assertionMethod` and `authentication`, so verifiers accept the credentials and
/// presentations the gateway signs.
pub(crate) fn gateway_did_document(
    proxy_did: &str,
    signing_key: &JWK,
    x25519_key_id: &str,
    x25519_public_jwk: serde_json::Value,
    p256_key_id: &str,
    p256_public_jwk: serde_json::Value,
) -> Result<serde_json::Value> {
    let public_key_multibase = crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(signing_key)?;
    let jwk_key_id = format!("{}#key-1", proxy_did);
    let multikey_id = format!("{}#{}", proxy_did, DEFAULT_SIGNING_KEY_ID);
    let domain = extract_domain_from_proxy_did(proxy_did);

    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": proxy_did,
        "verificationMethod": [
            {
                "id": &jwk_key_id,
                "type": "JsonWebKey2020",
                "controller": proxy_did,
                "publicKeyJwk": signing_key.to_public()
            },
            {
                "id": &multikey_id,
                "type": "Multikey",
                "controller": proxy_did,
                "publicKeyMultibase": public_key_multibase
            },
            {
                "id": x25519_key_id,
                "type": "JsonWebKey2020",
                "controller": proxy_did,
                "publicKeyJwk": x25519_public_jwk
            },
            {
                "id": p256_key_id,
                "type": "JsonWebKey2020",
                "controller": proxy_did,
                "publicKeyJwk": p256_public_jwk
            }
        ],
        "authentication": [&jwk_key_id, &multikey_id],
        "assertionMethod": [&jwk_key_id, &multikey_id],
        "keyAgreement": [x25519_key_id, p256_key_id],
        "service": [{
            "id": format!("{}#didcomm", proxy_did),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "uri": format!("https://{}/didcomm", domain),
                "accept": ["didcomm/v2"],
                "routingKeys": []
            }]
        }]
    }))
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

/// The surface a request uses its identity on as the managed agent; `None` for a caller.
fn managed_request_surface(
    role: Option<IdentityOrigin>,
    surface_id: Option<&str>,
) -> Option<&str> {
    surface_id.filter(|_| role == Some(IdentityOrigin::Managed))
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
    /// Signs JWTs for agents whose key is in a trust agent, set beside
    /// `di_vp_issuer` because both find the agent's context the same way.
    agent_jwt_signer: Arc<RwLock<Option<Arc<dyn crate::vta::vp_issuer::AgentJwtSigner>>>>,

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
            agent_jwt_signer: Arc::new(RwLock::new(None)),
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

    pub(crate) fn surface_store(&self) -> Option<Arc<dyn crate::surfaces::AgentSurfaceStore>> {
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
    /// A resolution **failure** falls back only for a surface that **maps
    /// nothing of its own**: it signs with the appliance key either way, so the
    /// fallback is the same key it always used. A surface with an explicit
    /// mapping (its own `signing` block, a variant's, or its issuer's) fails
    /// closed instead. Someone chose whose key signs there, and when that key
    /// cannot be reached, signing with another would change the issuer under
    /// callers' feet, or hand a tenant's tokens to the operator's key.
    async fn authority_for_surface(
        &self,
        surface_id: Option<&str>,
    ) -> Result<Option<Arc<dyn crate::identity::authority::CredentialAuthority>>> {
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
            return Ok(appliance);
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
            Ok(authority) => Ok(Some(authority)),
            Err(e) => {
                if directory
                    .has_explicit_mapping(purpose, &scope)
                    .await
                {
                    warn!(
                        target: "vta_audit",
                        surface_id = surface_id.unwrap_or("<appliance-wide>"),
                        error = %e.log_detail(),
                        "the signing key this surface maps could not be resolved; refusing to sign with another",
                    );
                    return Err(anyhow::anyhow!(
                        "the trust agent key this surface signs with is not available ({e}); \
                         it is not replaced by the appliance key"
                    ));
                }
                warn!(
                    target: "vta_audit",
                    surface_id = surface_id.unwrap_or("<appliance-wide>"),
                    error = %e.log_detail(),
                    "signing key could not be resolved; falling back to the appliance key",
                );
                Ok(appliance)
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

    /// Sign agents' JWTs in their own trust agent context when they have one.
    pub async fn set_agent_jwt_signer(
        &self,
        signer: Arc<dyn crate::vta::vp_issuer::AgentJwtSigner>,
    ) {
        *self
            .agent_jwt_signer
            .write()
            .await = Some(signer);
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
    /// The public JWKS of the authority that signs this gateway's tokens (STS
    /// tokens, ID-JAGs, MCP access tokens), so a verifier inside the gateway
    /// checks them against the key that signed them: the local key's until a
    /// signing authority is installed.
    pub async fn token_signing_jwks(&self) -> Result<serde_json::Value> {
        let authority = self
            .signing_authority
            .read()
            .await
            .clone();
        match authority {
            Some(authority) => authority.issuer_jwks().await,
            None => {
                self.signing_public_jwks()
                    .await
            }
        }
    }

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
            let x25519_key_path = config
                .storage_path
                .join("x25519_key.json");
            let p256_key_path = config
                .storage_path
                .join("p256_key.json");

            let (x25519_key_id, x25519_public_jwk) = if let Some(content) = read_issuer_file(&x25519_key_path).await? {
                let secret: affinidi_tdk_common::secrets_resolver::secrets::Secret = serde_json::from_str(&content)?;
                (secret.id.clone(), public_key_agreement_jwk(&secret, "X25519")?)
            } else {
                (format!("{}#key-x25519-1", config.proxy_did), serde_json::json!({}))
            };

            let (p256_key_id, p256_public_jwk) = if let Some(content) = read_issuer_file(&p256_key_path).await? {
                let secret: affinidi_tdk_common::secrets_resolver::secrets::Secret = serde_json::from_str(&content)?;
                (secret.id.clone(), public_key_agreement_jwk(&secret, "P-256")?)
            } else {
                (format!("{}#key-p256-1", config.proxy_did), serde_json::json!({}))
            };

            gateway_did_document(
                &config.proxy_did,
                &config.signing_key,
                &x25519_key_id,
                x25519_public_jwk,
                &p256_key_id,
                p256_public_jwk,
            )
        }
    }

    #[cfg(all(test, feature = "didwebvh"))]
    pub async fn authorize_signing_key(&self) -> Result<bool> {
        self.authorize_signing_key_while(|| true)
            .await
    }

    /// Lists the signing Multikey under `assertionMethod` and `authentication` in the gateway's
    /// published DID document where it is missing, as in documents written before it was. A
    /// `did:webvh` DID gets a new log version signed with the gateway key, so the DID does not
    /// change; the stored `did.json` gets the same addition, also when only it still lacks the
    /// key. The version is appended only while `still_active` holds once it is ready, so a node
    /// that stepped down meanwhile writes nothing. No key is created or replaced, and nothing
    /// else in either document changes. Returns whether a document changed.
    #[cfg(feature = "didwebvh")]
    pub async fn authorize_signing_key_while(
        &self,
        still_active: impl Fn() -> bool + Sync,
    ) -> Result<bool> {
        let config = self
            .config
            .read()
            .await
            .clone();

        if config
            .proxy_did
            .starts_with("did:webvh:")
        {
            let multikey_id = format!("{}#{}", config.proxy_did, DEFAULT_SIGNING_KEY_ID);
            return Self::append_signing_key_version(&config, &multikey_id, &still_active).await;
        }

        let changed = Self::authorize_signing_key_in_did_document(&config, None).await?;
        if changed {
            info!(
                "Gateway DID {} now lists its signing key under assertionMethod and authentication",
                config.proxy_did
            );
        }
        Ok(changed)
    }

    /// Whether the latest gateway DID log version, for a `did:webvh` DID, and the stored
    /// `did.json` both list the signing key under `assertionMethod` and `authentication`. Only
    /// reads, without the gateway DID lock; anything missing or unreadable counts as not listed.
    #[cfg(feature = "didwebvh")]
    pub async fn signing_key_is_listed(&self) -> bool {
        let config = self
            .config
            .read()
            .await
            .clone();
        Self::signing_key_is_listed_in(&config)
            .await
            .unwrap_or(false)
    }

    #[cfg(feature = "didwebvh")]
    async fn signing_key_is_listed_in(config: &VCIssuerConfig) -> Result<bool> {
        use crate::storage::did_artifacts::{read_did_document, read_did_log_raw};

        let lists = |document: &serde_json::Value, document_id: &str| -> Result<bool> {
            let mut document = document.clone();
            let multikey_id = format!("{document_id}#{DEFAULT_SIGNING_KEY_ID}");
            Ok(!add_signing_key_to_relationships(&mut document, &multikey_id, &config.signing_key)?)
        };
        if config
            .proxy_did
            .starts_with("did:webvh:")
        {
            let Some(log) = read_did_log_raw(&config.storage_path).await? else {
                return Ok(false);
            };
            let latest: serde_json::Value = serde_json::from_str(
                log.lines()
                    .map(str::trim)
                    .rfind(|line| !line.is_empty())
                    .context("Gateway DID log has no entries")?,
            )?;
            if !lists(&latest["state"], &config.proxy_did)? {
                return Ok(false);
            }
        }
        let Some(content) = read_did_document(&config.storage_path).await? else {
            return Ok(false);
        };
        let document: serde_json::Value = serde_json::from_str(&content)?;
        let document_id = Self::did_document_id(config)?;
        Ok(document["id"] == document_id.as_str() && lists(&document, &document_id)?)
    }

    /// Takes the lock that serializes creating, upgrading and repairing the gateway DID between
    /// gateways sharing its storage, waiting up to `timeout` for another holder.
    #[cfg(feature = "didwebvh")]
    pub async fn lock_gateway_did(
        &self,
        timeout: std::time::Duration,
    ) -> crate::storage::file_lock::LockOutcome {
        let storage_path = self.get_storage_path().await;
        lock_gateway_did(&storage_path, timeout).await
    }

    #[cfg(feature = "didwebvh")]
    async fn append_signing_key_version(
        config: &VCIssuerConfig,
        multikey_id: &str,
        still_active: &(dyn Fn() -> bool + Sync),
    ) -> Result<bool> {
        use crate::identity::didwebvh::handlers::{build_signing_secret, build_webvh_state};
        use crate::storage::did_artifacts::{append_did_log_raw, read_did_log_raw};

        let Some(log) = read_did_log_raw(&config.storage_path).await? else {
            warn!("Gateway DID {} has no did.jsonl; repairing its did.json only", config.proxy_did);
            return Self::authorize_signing_key_in_did_document(config, None).await;
        };
        let entries: Vec<String> = log
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        let state = build_webvh_state(&config.proxy_did, &entries)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let latest: serde_json::Value = serde_json::from_str(
            entries
                .last()
                .context("Gateway DID log has no entries")?,
        )?;
        let mut document = latest
            .get("state")
            .cloned()
            .context("Gateway DID log entry has no state")?;
        if !add_signing_key_to_relationships(&mut document, multikey_id, &config.signing_key)? {
            let caught_up = Self::authorize_signing_key_in_did_document(config, Some(&latest["state"])).await?;
            if caught_up {
                info!("Gateway DID document {} now lists its signing key like its DID log", config.proxy_did);
            }
            return Ok(caught_up);
        }

        let previous_time = chrono::DateTime::parse_from_rfc3339(
            latest["versionTime"]
                .as_str()
                .context("Gateway DID log entry has no versionTime")?,
        )?;
        if let Some(wait) = wait_before_next_version(previous_time.to_utc(), chrono::Utc::now())? {
            tokio::time::sleep(wait).await;
        }

        let signing_key =
            build_signing_secret(&serde_json::to_value(&config.signing_key)?).map_err(|e| anyhow::anyhow!(e))?;
        let update = didwebvh_rs::prelude::update_did(
            didwebvh_rs::prelude::UpdateDIDConfig::<crate::vta::local::VtaDiSigner, crate::vta::local::VtaDiSigner>::builder_generic()
                .state(state)
                .signing_key(signing_key)
                .document(document)
                .build()?,
        )
        .await?;
        let entry_json = serde_json::to_string(update.log_entry())?;
        if !still_active() {
            info!("Gateway DID repair left to the Active node: this node stepped down to Standby");
            return Ok(false);
        }
        append_did_log_raw(&config.storage_path, &log, &entry_json).await?;
        let entry: serde_json::Value = serde_json::from_str(&entry_json)?;
        if let Err(e) = Self::authorize_signing_key_in_did_document(config, Some(&entry["state"])).await {
            warn!("Gateway DID log repaired, but its did.json was left as it is: {e:#}");
        }

        info!("Gateway DID {} now lists its signing key under assertionMethod and authentication", config.proxy_did);
        Ok(true)
    }

    /// The DID the stored `did.json` describes: the gateway DID, or for a `did:webvh` DID its
    /// parallel `did:web` DID.
    #[cfg(feature = "didwebvh")]
    fn did_document_id(config: &VCIssuerConfig) -> Result<String> {
        if !config
            .proxy_did
            .starts_with("did:webvh:")
        {
            return Ok(config.proxy_did.clone());
        }
        let scid = crate::identity::didwebvh::identifier::parse_did_webvh(&config.proxy_did)?
            .scid
            .context("Gateway DID has no SCID")?;
        config
            .proxy_did
            .strip_prefix(&format!("did:webvh:{scid}:"))
            .map(|rest| format!("did:web:{rest}"))
            .context("Gateway DID does not start with its SCID")
    }

    /// Adds the signing Multikey the stored `did.json` publishes to its `assertionMethod` and
    /// `authentication`, and changes nothing else in it, so a `did.json` that differs from the DID
    /// log keeps its other content. Refuses a `did.json` that publishes another key as the
    /// Multikey. A `did.json` that is missing or does not parse holds nothing to keep, so it is
    /// written from `log_state`, the latest `did:webvh` log version, when there is one. Returns
    /// whether `did.json` changed.
    #[cfg(feature = "didwebvh")]
    async fn authorize_signing_key_in_did_document(
        config: &VCIssuerConfig,
        log_state: Option<&serde_json::Value>,
    ) -> Result<bool> {
        use crate::storage::did_artifacts::{read_did_document, write_did_document};

        let stored = read_did_document(&config.storage_path)
            .await?
            .map(|content| serde_json::from_str::<serde_json::Value>(&content));
        let mut document = match (stored, log_state) {
            (Some(Ok(document)), _) => document,
            (None, None) => return Ok(false),
            (Some(Err(e)), None) => return Err(e).context("Gateway did.json does not parse"),
            (_, Some(state)) => {
                let scid = crate::identity::didwebvh::identifier::parse_did_webvh(&config.proxy_did)?
                    .scid
                    .context("Gateway DID has no SCID")?;
                let parallel = parallel_did_document(state, &config.proxy_did, &scid)?;
                write_did_document(&config.storage_path, &serde_json::to_string_pretty(&parallel)?).await?;
                return Ok(true);
            }
        };
        let document_id = Self::did_document_id(config)?;
        anyhow::ensure!(
            document["id"] == document_id.as_str(),
            "Gateway did.json describes {} rather than {document_id}",
            document["id"]
        );
        let multikey_id = format!("{document_id}#{DEFAULT_SIGNING_KEY_ID}");
        if !add_signing_key_to_relationships(&mut document, &multikey_id, &config.signing_key)? {
            return Ok(false);
        }
        write_did_document(&config.storage_path, &serde_json::to_string_pretty(&document)?).await?;
        Ok(true)
    }

    /// Writes `did.json` of a published `did:webvh` gateway again from the latest version of its
    /// verified DID log, as the parallel `did:web` document the log describes. Returns whether
    /// there was a log to write it from.
    #[cfg(feature = "didwebvh")]
    async fn restore_did_document_from_log(
        storage_path: &Path,
        proxy_did: &str,
    ) -> Result<bool> {
        use crate::identity::didwebvh::handlers::build_webvh_state;
        use crate::storage::did_artifacts::{read_did_log_raw, write_did_document};

        let Some(log) = read_did_log_raw(storage_path).await? else {
            return Ok(false);
        };
        let entries: Vec<String> = log
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        build_webvh_state(proxy_did, &entries)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let latest: serde_json::Value = serde_json::from_str(
            entries
                .last()
                .context("Gateway DID log has no entries")?,
        )?;
        let state = latest
            .get("state")
            .filter(|state| state.is_object())
            .context("Gateway DID log entry has no state")?;
        let scid = crate::identity::didwebvh::identifier::parse_did_webvh(proxy_did)?
            .scid
            .context("Gateway DID has no SCID")?;
        let parallel = parallel_did_document(state, proxy_did, &scid)?;
        write_did_document(storage_path, &serde_json::to_string_pretty(&parallel)?).await?;
        info!("Gateway did.json was missing; written again from the gateway DID log");
        Ok(true)
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

    /// Loads the gateway's keys and DID, creating or upgrading them first when they are not all
    /// published yet.
    async fn load_or_create_config(
        storage_path: PathBuf,
        proxy_domain: String,
    ) -> Result<VCIssuerConfig> {
        Self::load_or_create_config_within(storage_path, proxy_domain, GATEWAY_DID_CREATE_LOCK_TIMEOUT).await
    }

    /// A gateway whose keys and DID are all in place only reads them. Any other start creates
    /// or upgrades them under the gateway DID lock, so gateways sharing the directory end up
    /// with the one set the first of them wrote. A volume without the lock starts unlocked,
    /// except that a node booting Standby, as every node of a multi-node gateway does, refuses
    /// to create a gateway DID that does not exist yet. A start that waited out `lock_timeout`
    /// loads what another gateway finished publishing meanwhile, and otherwise fails, so it is
    /// restarted rather than creating a second identity.
    async fn load_or_create_config_within(
        storage_path: PathBuf,
        proxy_domain: String,
        lock_timeout: std::time::Duration,
    ) -> Result<VCIssuerConfig> {
        use crate::storage::file_lock::LockOutcome;

        if let Some(config) = Self::load_published_config(&storage_path).await? {
            return Ok(config);
        }
        let _lock = match lock_gateway_did(&storage_path, lock_timeout).await {
            LockOutcome::Acquired(file) => Some(file),
            LockOutcome::Unavailable(error) => {
                if crate::server::mode::is_standby() && !Self::has_existing_identity(&storage_path).await {
                    return Err(error.context(
                        "Gateway DID lock unavailable; a Standby node does not create the gateway DID without it, \
                         as other nodes sharing this volume may create their own",
                    ));
                }
                warn!(
                    "Gateway DID lock unavailable ({error:#}); creating the gateway DID without it, so gateways \
                     starting together on this volume may not share one DID"
                );
                None
            }
            LockOutcome::TimedOut => {
                return Self::load_published_config(&storage_path)
                    .await?
                    .context(
                        "Timed out waiting for the gateway DID lock held by another gateway creating the gateway DID",
                    );
            }
        };
        Self::create_or_complete_config(storage_path, proxy_domain).await
    }

    /// Whether a gateway identity is already in place: its config, both key agreement keys,
    /// stored plain or encrypted at rest, and its DID document. A gateway creating its identity
    /// writes the DID document after the others, so a partly created identity is not one.
    async fn has_existing_identity(storage_path: &Path) -> bool {
        let exists = |path: PathBuf| async move {
            tokio::fs::try_exists(&path)
                .await
                .unwrap_or(false)
        };
        for file in ["issuer_config.json", "x25519_key.json", "p256_key.json"] {
            let path = storage_path.join(file);
            if !exists(path.clone()).await && !exists(crate::encryption::secret_file::secret_enc_path(&path)).await {
                return false;
            }
        }
        exists(storage_path.join("did.json")).await
    }

    /// The saved config of a gateway whose keys, DID document and, with `didwebvh`, `did:webvh`
    /// DID are all in place, read without creating anything; `None` when any is missing. A key
    /// file that does not parse is an error, as it is when the keys are created.
    async fn load_published_config(storage_path: &Path) -> Result<Option<VCIssuerConfig>> {
        if !tokio::fs::try_exists(storage_path.join("did.json")).await? {
            return Ok(None);
        }
        for file in ["x25519_key.json", "p256_key.json"] {
            let Some(content) = read_issuer_file(&storage_path.join(file)).await? else {
                return Ok(None);
            };
            serde_json::from_str::<affinidi_tdk_common::secrets_resolver::secrets::Secret>(&content)
                .with_context(|| format!("Failed to parse {file}"))?;
        }
        let Some(content) = read_issuer_file(&storage_path.join("issuer_config.json")).await? else {
            return Ok(None);
        };
        let saved: SavedIssuerConfig = serde_json::from_str(&content)?;
        if cfg!(feature = "didwebvh")
            && !saved
                .proxy_did
                .starts_with("did:webvh:")
        {
            return Ok(None);
        }
        Ok(Some(VCIssuerConfig {
            proxy_did: saved.proxy_did,
            signing_key: serde_json::from_value(saved.signing_key)?,
            storage_path: storage_path.to_path_buf(),
            is_vp_challenge_required: saved.is_vp_challenge_required,
        }))
    }

    /// Load existing config or create new one
    async fn create_or_complete_config(
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

        // Generate or update the DID document
        let did_doc_path = storage_path.join("did.json");

        // Only regenerate DID document if it doesn't exist or if we created new keys
        let did_doc_missing = !tokio::fs::try_exists(&did_doc_path).await?;
        let should_update_did_doc = did_doc_missing || is_new_config || !x25519_existed || !p256_existed;

        #[cfg(feature = "didwebvh")]
        let restored = did_doc_missing
            && !is_new_config
            && x25519_existed
            && p256_existed
            && proxy_did.starts_with("did:webvh:")
            && match Self::restore_did_document_from_log(&storage_path, &proxy_did).await {
                Ok(restored) => restored,
                Err(e) => {
                    warn!("Gateway did.json could not be written again from the gateway DID log: {e:#}");
                    false
                }
            };
        #[cfg(not(feature = "didwebvh"))]
        let restored = false;

        if should_update_did_doc && !restored {
            let did_doc = gateway_did_document(
                &proxy_did,
                &key,
                &x25519_secret.id,
                public_key_agreement_jwk(&x25519_secret, "X25519")?,
                &p256_secret.id,
                public_key_agreement_jwk(&p256_secret, "P-256")?,
            )?;

            let did_doc_json = serde_json::to_string_pretty(&did_doc)?;
            crate::storage::did_artifacts::write_did_document(&storage_path, &did_doc_json).await?;
        }

        // Create or migrate proxy_did to did:webvh.
        // Runs on first boot (new config) and on subsequent boots if still did:web: (legacy upgrade path).
        #[cfg(feature = "didwebvh")]
        let proxy_did = if proxy_did.starts_with("did:web:") {
            match Self::migrate_proxy_did_to_webvh(&storage_path, &proxy_did, &key).await {
                Ok(new_did) => {
                    // Key IDs first: a did:webvh issuer_config.json marks the upgrade complete.
                    Self::update_didcomm_key_ids(&storage_path, &proxy_did, &new_did).await;

                    let saved = SavedIssuerConfig {
                        proxy_did: new_did.clone(),
                        signing_key: serde_json::to_value(&key)?,
                        is_vp_challenge_required,
                    };
                    write_issuer_file(&config_path, &serde_json::to_string_pretty(&saved)?).await?;

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
        self.issue_or_get_credential_with_origin(
            identity_fields,
            identity_hash,
            channel_config_id,
            issuer_id,
            None,
            None,
        )
        .await
    }

    /// [`Self::issue_or_get_credential`] for the managed agent of `channel_config_id`:
    /// records the identity as managed unless the record already has an origin, and a managed
    /// record takes the slot and credential state in `source`. The VC follows the record's
    /// origin: a managed one is named with its managed display name.
    pub async fn issue_or_get_managed_credential(
        &self,
        identity_fields: std::collections::HashMap<String, serde_json::Value>,
        identity_hash: Option<String>,
        channel_config_id: Option<String>,
        issuer_id: Option<String>,
        source: ManagedIdentitySource,
    ) -> Result<AgentIdentityResponse> {
        self.issue_or_get_credential_with_origin(
            identity_fields,
            identity_hash,
            channel_config_id,
            issuer_id,
            Some(IdentityOrigin::Managed),
            Some(&source),
        )
        .await
    }

    /// [`Self::issue_or_get_credential`] for a caller reaching the surface: records the
    /// identity as an external caller unless the record already has an origin. The VC
    /// follows the record's origin, so it carries no name unless the record is managed.
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
            None,
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
        managed_source: Option<&ManagedIdentitySource>,
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

        if let Some(record) = self
            .identity_store
            .find_by_hash(&identity_hash)
            .await?
        {
            return self
                .existing_identity_response(record, identity_fields, channel_config_id, origin, managed_source)
                .await;
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
                    slot: None,
                    credential_updated_at: None,
                    rotations: Vec::new(),
                    rotation_count: 0,
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
            .managed_display_name(&agent_did, origin, managed_request_surface(origin, channel_config_id.as_deref()))
            .await;
        let vc = self
            .create_credential(&agent_did, &identity_fields, name.as_ref(), channel_config_id.as_deref())
            .await?;

        let birth_log_dir = std::mem::replace(&mut record.identity_hash, identity_hash.clone());
        record.identity_fields = identity_fields.clone();
        record.channel_config_id = channel_config_id.clone();
        record.origin = origin;
        if let Some(source) = managed_source {
            record.apply_managed_source(source, &identity_fields);
        }
        let created_at = record.created_at;
        let _ = issuer_id; // no-op: agent-in-TR writes are owned by Trust Recorder now

        if let Some(winner) = self
            .identity_store
            .create_if_absent(record)
            .await?
        {
            info!(identity_hash = %identity_hash, did = %winner.did, discarded_did = %agent_did, "Identity created by a concurrent request — its DID is used");
            self.discard_birth_log(&birth_log_dir)
                .await;
            return self
                .existing_identity_response(winner, identity_fields, channel_config_id, origin, managed_source)
                .await;
        }

        // Treat the very call that triggered creation as the first usage,
        // so the dashboard shows usage_count=1 / last_used_at instead of
        // an unused record. Without this, the first request silently
        // creates the identity but it appears as "Unused" until a second
        // call exercises the existing-record branch above.
        if let Err(e) = self
            .identity_store
            .update_usage(&identity_hash, channel_config_id, origin)
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

    async fn existing_identity_response(
        &self,
        record: AgentIdentityRecord,
        identity_fields: std::collections::HashMap<String, serde_json::Value>,
        channel_config_id: Option<String>,
        origin: Option<IdentityOrigin>,
        managed_source: Option<&ManagedIdentitySource>,
    ) -> Result<AgentIdentityResponse> {
        let identity_hash = &record.identity_hash;
        info!("[TR-TRACE] Identity ALREADY EXISTS for hash={}, did={}", identity_hash, record.did);
        let effective_origin = match (record.origin, origin) {
            (None, Some(requested)) => match self
                .identity_store
                .set_origin(identity_hash, requested)
                .await
            {
                Ok(stored) => stored.or(Some(requested)),
                Err(e) => {
                    warn!(identity_hash = %identity_hash, error = %e, "Failed to record identity origin (non-fatal)");
                    Some(requested)
                }
            },
            (existing, _) => existing,
        };
        if let Some(source) = managed_source
            && effective_origin == Some(IdentityOrigin::Managed)
            && record.would_change(source)
            && let Err(e) = self
                .identity_store
                .apply_managed_source(identity_hash, source, &identity_fields)
                .await
        {
            warn!(identity_hash = %identity_hash, error = %e, "Failed to record managed identity source (non-fatal)");
        }
        self.identity_store
            .update_usage(identity_hash, channel_config_id.clone(), origin)
            .await?;

        let name = self
            .managed_display_name(
                &record.did,
                effective_origin,
                managed_request_surface(origin, channel_config_id.as_deref()),
            )
            .await;

        let vc = self
            .create_credential(&record.did, &identity_fields, name.as_ref(), channel_config_id.as_deref())
            .await?;

        Ok(AgentIdentityResponse {
            did: record.did,
            credential: vc.to_string(),
            is_new: false,
            created_at: record.created_at,
        })
    }

    /// Remove the birth log of a generated DID that was never stored.
    async fn discard_birth_log(
        &self,
        birth_log_dir: &str,
    ) {
        let Some(base_path) = self
            .identity_store
            .base_path()
        else {
            return;
        };
        if let Err(e) = tokio::fs::remove_dir_all(base_path.join(birth_log_dir)).await
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(birth_log_dir, error = %e, "Failed to remove the birth log of a discarded DID (non-fatal)");
        }
    }

    /// Display name of the managed agent `agent_did` of `surface_id`; `None` when the
    /// surface or the identity list is unavailable.
    pub async fn surface_display_name(
        &self,
        agent_did: &str,
        surface_id: &str,
    ) -> Option<ManagedDisplayName> {
        self.resolve_display_name(agent_did, Some(surface_id))
            .await
    }

    async fn resolve_display_name(
        &self,
        agent_did: &str,
        managed_on: Option<&str>,
    ) -> Option<ManagedDisplayName> {
        let surface_store = self.surface_store()?;
        resolve_managed_display_name_in(
            surface_store.as_ref(),
            agent_did,
            managed_on,
            self.identity_store.as_ref(),
            &self.surfaces_by_did,
        )
        .await
    }

    /// Display name for a managed identity (the name of its one managed surface); `None` for
    /// callers, unknown origins, unnamed agents and shared managed DIDs.
    async fn managed_display_name(
        &self,
        agent_did: &str,
        origin: Option<IdentityOrigin>,
        managed_on: Option<&str>,
    ) -> Option<DisplayName> {
        if origin != Some(IdentityOrigin::Managed) {
            return None;
        }
        self.resolve_display_name(agent_did, managed_on)
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
        self.managed_display_name(agent_did, record.origin, None)
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
            .await?;

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
        Ok(crate::vta::local::sign_jwt(key, typ, payload)?)
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
            .ok_or_else(|| anyhow::anyhow!("agent {did} has no key on this gateway and no trust agent signs for it"))?;

        let key: JWK = serde_json::from_value(key_json).context("Failed to deserialize agent private key")?;

        Ok(key)
    }

    /// Sign a JWT payload as an agent: in the agent's own trust agent context
    /// when its key lives there, otherwise with the key the gateway holds.
    pub async fn sign_jwt_with_agent_key(
        &self,
        did: &str,
        payload: &serde_json::Value,
    ) -> Result<String> {
        let signer = self
            .agent_jwt_signer
            .read()
            .await
            .clone();
        if let Some(signer) = signer
            && let Some(jwt) = signer
                .sign_agent_jwt(did, payload)
                .await?
        {
            info!(did = did, "✍️ Signed JWT in the agent's trust agent context");
            return Ok(jwt);
        }
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

    /// Who signs the fabric issuer attestation right now: the context the
    /// key directory resolves for the appliance's agent-identity credential,
    /// so the two cannot diverge; the signer installed for `[vta]` when the
    /// directory has no opinion; otherwise the gateway's own key (`None`).
    async fn current_attestation_signer(&self) -> Result<Option<Arc<dyn crate::vta::context_signer::ContextSigner>>> {
        let directory = self
            .key_directory
            .read()
            .await
            .clone();
        if let Some(directory) = directory {
            match directory
                .attestation_signer()
                .await
            {
                crate::vta::key_directory::ScopedContextSigner::Agent(signer) => return Ok(Some(signer)),
                crate::vta::key_directory::ScopedContextSigner::Local => return Ok(None),
                crate::vta::key_directory::ScopedContextSigner::Inherit => {}
                crate::vta::key_directory::ScopedContextSigner::Unavailable(reason) => {
                    anyhow::bail!(
                        "the trust agent that issues this gateway's credentials is not available ({reason}); \
                         the attestation is not signed by another issuer"
                    )
                }
            }
        }
        Ok(self
            .attestation_signer
            .read()
            .await
            .clone())
    }

    /// The DID the fabric issuer attestation should claim, and which must
    /// therefore also be the issuer of the credentials peers will receive.
    pub async fn attestation_issuer_did(&self) -> Result<String> {
        match self
            .current_attestation_signer()
            .await?
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
            .current_attestation_signer()
            .await?
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
            crate::vta::key_directory::ScopedDiIssuer::Unavailable(reason) => {
                anyhow::bail!(
                    "the trust agent that issues this surface's credentials is not available ({reason}); \
                     it is not replaced by another issuer"
                )
            }
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
    fn verifies_under(
        jwt: &str,
        key: &JWK,
    ) -> bool {
        use base64::Engine;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let decode = |s: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .expect("base64url")
        };
        let parts: Vec<&str> = jwt.split('.').collect();
        let x = serde_json::to_value(key.to_public()).expect("jwk")["x"]
            .as_str()
            .expect("x")
            .to_string();
        let public: [u8; 32] = decode(&x)
            .try_into()
            .expect("32 bytes");
        VerifyingKey::from_bytes(&public)
            .expect("key")
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &Signature::from_slice(&decode(parts[2])).expect("signature"),
            )
            .is_ok()
    }

    #[tokio::test]
    async fn a_gateway_token_is_signed_by_the_vta_library_under_the_gateways_own_key() {
        let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let key = issuer
            .config
            .read()
            .await
            .signing_key
            .clone();

        let jwt = issuer
            .sign_jwt_with_gateway_key_typ(&json!({"sub": "agent", "n": 1}), "at+jwt")
            .await
            .expect("signed");

        assert!(verifies_under(&jwt, &key), "the token verifies under the gateway's published key");
    }

    #[tokio::test]
    async fn an_agent_token_is_signed_by_the_vta_library_under_the_agents_own_key() {
        let agent = JWK::generate_ed25519().expect("key");
        let store = Arc::new(MockIdentityStore::new());
        let mut record = crate::identity::test_helpers::test_surface_identity_record("did:key:z6MkAgent", "s1");
        record.private_key = Some(serde_json::to_value(&agent).expect("jwk"));
        store
            .create(record)
            .await
            .expect("stored");
        let issuer = {
            let (i, _d) = crate::identity::test_helpers::test_vc_issuer_with(store).await;
            i
        };

        let jwt = issuer
            .sign_jwt_with_agent_key("did:key:z6MkAgent", &json!({"iss": "did:key:z6MkAgent"}))
            .await
            .expect("signed");

        assert!(verifies_under(&jwt, &agent));
        assert!(
            !verifies_under(
                &jwt,
                &issuer
                    .config
                    .read()
                    .await
                    .signing_key
            ),
            "an agent's token is not valid under the gateway's key"
        );
    }

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

    fn key_ids(
        doc: &serde_json::Value,
        relationship: &str,
    ) -> Vec<String> {
        doc[relationship]
            .as_array()
            .unwrap_or_else(|| panic!("DID document missing '{relationship}'"))
            .iter()
            .map(|id| {
                id.as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    fn assert_signing_key_authorized(
        doc: &serde_json::Value,
        did: &str,
    ) {
        let multikey_id = format!("{did}#{DEFAULT_SIGNING_KEY_ID}");
        assert_eq!(key_ids(doc, "assertionMethod"), vec![format!("{did}#key-1"), multikey_id.clone()]);
        assert_eq!(key_ids(doc, "authentication"), vec![format!("{did}#key-1"), multikey_id.clone()]);
        let signing_method = doc["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vm| vm["id"] == multikey_id.as_str())
            .unwrap_or_else(|| panic!("verificationMethod must list {multikey_id}"));
        assert_eq!(signing_method["type"], "Multikey");
    }

    /// The gateway signs its credentials with the Multikey, so the DID log it publishes must
    /// list that key under assertionMethod for strict Data Integrity verifiers to accept them.
    #[tokio::test]
    async fn published_did_log_authorizes_signing_key_for_assertions() {
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

        let log = crate::storage::did_artifacts::read_did_log_raw(temp_dir.path())
            .await
            .unwrap()
            .expect("the gateway must publish a did.jsonl log");
        let latest: serde_json::Value = serde_json::from_str(log.lines().last().unwrap()).unwrap();

        assert_signing_key_authorized(&latest["state"], &did);
    }

    /// Without a stored did.json the gateway builds its document on demand, and that document
    /// authorizes the signing Multikey the same way.
    #[tokio::test]
    async fn generated_did_document_authorizes_signing_key_for_assertions() {
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
        std::fs::remove_file(
            temp_dir
                .path()
                .join("did.json"),
        )
        .unwrap();

        let doc = issuer
            .get_did_document()
            .await
            .unwrap();

        assert_eq!(doc["id"], did.as_str());
        assert_signing_key_authorized(&doc, &did);
    }

    #[test]
    fn public_key_agreement_jwk_drops_private_key() {
        let secret = affinidi_tdk_common::secrets_resolver::secrets::Secret::generate_x25519(
            Some("did:web:example.com#key-x25519-1"),
            None,
        )
        .unwrap();

        let public_jwk = public_key_agreement_jwk(&secret, "X25519").unwrap();

        assert!(public_jwk.get("d").is_none(), "public JWK must not carry the private key");
        assert_eq!(public_jwk["crv"], "X25519");
        assert!(public_jwk["x"].is_string(), "public JWK must carry the public key");
    }

    #[test]
    fn public_key_agreement_jwk_rejects_non_jwk_secret() {
        let mut secret = affinidi_tdk_common::secrets_resolver::secrets::Secret::generate_x25519(
            Some("did:web:example.com#key-x25519-1"),
            None,
        )
        .unwrap();
        secret.secret_material =
            affinidi_tdk_common::secrets_resolver::secrets::SecretMaterial::PrivateKeyMultibase("z6LS".to_string());

        let err = public_key_agreement_jwk(&secret, "X25519").unwrap_err();

        assert_eq!(err.to_string(), "X25519 secret is not a JWK");
    }

    #[cfg(feature = "didwebvh")]
    async fn did_log_entries(issuer: &VCIssuer) -> Vec<serde_json::Value> {
        crate::storage::did_artifacts::read_did_log_raw(
            &issuer
                .get_storage_path()
                .await,
        )
        .await
        .unwrap()
        .expect("the gateway must publish a did.jsonl log")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
    }

    /// A gateway that published its DID log without the signing Multikey under
    /// assertionMethod gets one new, verifiable version that lists it, under the same DID, and
    /// nothing else in the document changes.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_appends_a_version_that_authorizes_the_signing_key() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let did = issuer
            .get_issuer_did()
            .await
            .unwrap();
        let before = did_log_entries(&issuer).await;
        assert_eq!(before.len(), 1);
        assert_eq!(key_ids(&before[0]["state"], "assertionMethod"), vec![format!("{did}#key-1")]);

        let repaired = issuer
            .authorize_signing_key()
            .await
            .unwrap();

        assert!(repaired, "the repair must report that it changed the document");
        let after = did_log_entries(&issuer).await;
        assert_eq!(after.len(), 2, "the repair appends exactly one version");
        assert_eq!(after[0], before[0], "the published first version must not change");
        assert_eq!(
            issuer
                .get_issuer_did()
                .await
                .unwrap(),
            did,
            "the gateway DID must not change"
        );
        assert_eq!(after[1]["state"]["id"], did.as_str());
        assert_signing_key_authorized(&after[1]["state"], &did);

        let mut unchanged = after[1]["state"].clone();
        for relationship in SIGNING_KEY_RELATIONSHIPS {
            unchanged[relationship] = before[0]["state"][relationship].clone();
        }
        assert_eq!(unchanged, before[0]["state"], "only assertionMethod and authentication may change");

        let dir = issuer
            .get_storage_path()
            .await;
        let log = crate::storage::did_artifacts::read_did_log_raw(&dir)
            .await
            .unwrap()
            .unwrap();
        let raw_entries: Vec<String> = log
            .lines()
            .map(str::to_string)
            .collect();
        crate::identity::didwebvh::handlers::build_webvh_state(&did, &raw_entries)
            .await
            .expect("the repaired log must verify as a did:webvh log");

        let did_json: serde_json::Value = serde_json::from_str(
            &crate::storage::did_artifacts::read_did_document(&dir)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        for relationship in SIGNING_KEY_RELATIONSHIPS {
            assert!(
                key_ids(&did_json, relationship)
                    .iter()
                    .any(|id| id.ends_with(&format!("#{DEFAULT_SIGNING_KEY_ID}"))),
                "the stored did.json must list the signing key under {relationship}: {did_json}"
            );
        }
    }

    /// A repaired gateway is not repaired again, so restarts never add more versions.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_runs_once() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        let repaired_again = issuer
            .authorize_signing_key()
            .await
            .unwrap();

        assert!(!repaired_again);
        assert_eq!(
            did_log_entries(&issuer)
                .await
                .len(),
            2
        );
    }

    /// A gateway whose document already lists the signing key keeps its log as it is.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_leaves_a_correct_document_unchanged() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let before = did_log_entries(&issuer).await;

        let repaired = issuer
            .authorize_signing_key()
            .await
            .unwrap();

        assert!(!repaired);
        assert_eq!(did_log_entries(&issuer).await, before);
    }

    /// A log that does not verify is reported and left as it is.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_refuses_a_log_that_does_not_verify() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = issuer
            .get_storage_path()
            .await;
        let mut entry = did_log_entries(&issuer).await[0].clone();
        entry["state"]["service"] = json!([]);
        let tampered = entry.to_string();
        crate::storage::did_artifacts::write_did_log_raw(&dir, &tampered)
            .await
            .unwrap();

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .is_err()
        );
        assert_eq!(
            crate::storage::did_artifacts::read_did_log_raw(&dir)
                .await
                .unwrap()
                .unwrap(),
            format!("{tampered}\n")
        );
    }

    /// A repair that stopped after appending the log version but before rewriting `did.json`
    /// finishes on the next run: `did.json` is brought up to the log, and no version is added.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_rewrites_a_did_document_left_behind_by_the_log() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = issuer
            .get_storage_path()
            .await;
        let unrepaired = crate::storage::did_artifacts::read_did_document(&dir)
            .await
            .unwrap()
            .unwrap();
        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );
        crate::storage::did_artifacts::write_did_document(&dir, &unrepaired)
            .await
            .unwrap();

        let caught_up = issuer
            .authorize_signing_key()
            .await
            .unwrap();

        assert!(caught_up, "the repair must report that it changed did.json");
        assert_eq!(
            did_log_entries(&issuer)
                .await
                .len(),
            2
        );
        let did_json: serde_json::Value = serde_json::from_str(
            &crate::storage::did_artifacts::read_did_document(&dir)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(
            key_ids(&did_json, "assertionMethod")
                .iter()
                .any(|id| id.ends_with(&format!("#{DEFAULT_SIGNING_KEY_ID}"))),
            "did.json must list the signing key under assertionMethod: {did_json}"
        );
    }

    /// A log whose latest version was edited to a time an hour ahead is refused at once, not
    /// waited out, and left as it is.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_refuses_a_version_dated_in_the_future_without_waiting() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = issuer
            .get_storage_path()
            .await;
        let mut entry = did_log_entries(&issuer).await[0].clone();
        entry["versionTime"] = json!(
            (chrono::Utc::now() + chrono::Duration::hours(1))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
        );
        let ahead = entry.to_string();
        crate::storage::did_artifacts::write_did_log_raw(&dir, &ahead)
            .await
            .unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), issuer.authorize_signing_key())
            .await
            .expect("the repair must not wait for a versionTime an hour ahead");

        assert!(result.is_err());
        assert_eq!(
            crate::storage::did_artifacts::read_did_log_raw(&dir)
                .await
                .unwrap()
                .unwrap(),
            format!("{ahead}\n")
        );
    }

    #[cfg(feature = "didwebvh")]
    #[test]
    fn next_version_waits_out_a_previous_version_from_the_same_second() {
        let now = chrono::Utc::now();

        let wait = wait_before_next_version(now, now)
            .unwrap()
            .expect("a version from this second must be waited out");

        assert!(wait <= std::time::Duration::from_secs(1) && !wait.is_zero(), "unexpected wait {wait:?}");
    }

    #[cfg(feature = "didwebvh")]
    #[test]
    fn next_version_does_not_wait_after_an_older_version() {
        let now = chrono::Utc::now();

        assert_eq!(wait_before_next_version(now - chrono::Duration::minutes(5), now).unwrap(), None);
    }

    /// A previous version dated further ahead than a short wait comes from a clock that is
    /// off; it is refused rather than waited out.
    #[cfg(feature = "didwebvh")]
    #[test]
    fn next_version_refuses_a_previous_version_dated_ahead_of_the_clock() {
        let now = chrono::Utc::now();

        let err = wait_before_next_version(now + chrono::Duration::hours(1), now).unwrap_err();

        assert!(
            err.to_string()
                .contains("ahead of this node's clock"),
            "unexpected error: {err}"
        );
    }

    /// A gateway still on `did:web` publishes no log, so its `did.json` is rewritten to list the
    /// signing key under `assertionMethod`, once.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_rewrites_the_did_document_of_a_did_web_gateway() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let did = "did:web:example.com";
        let dir = issuer
            .get_storage_path()
            .await;
        let key = issuer
            .config
            .read()
            .await
            .signing_key
            .clone();
        issuer
            .config
            .write()
            .await
            .proxy_did = did.to_string();
        let mut document = gateway_did_document(did, &key, "x", json!({}), "p", json!({})).unwrap();
        document["assertionMethod"] = json!([format!("{did}#key-1")]);
        document["authentication"] = json!([format!("{did}#key-1")]);
        crate::storage::did_artifacts::write_did_document(&dir, &document.to_string())
            .await
            .unwrap();
        let log_before = crate::storage::did_artifacts::read_did_log_raw(&dir)
            .await
            .unwrap();

        let repaired = issuer
            .authorize_signing_key()
            .await
            .unwrap();

        assert!(repaired, "the repair must report that it changed did.json");
        let did_json: serde_json::Value = serde_json::from_str(
            &crate::storage::did_artifacts::read_did_document(&dir)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        for relationship in SIGNING_KEY_RELATIONSHIPS {
            assert_eq!(
                key_ids(&did_json, relationship),
                vec![format!("{did}#key-1"), format!("{did}#{DEFAULT_SIGNING_KEY_ID}")]
            );
        }
        assert_eq!(
            crate::storage::did_artifacts::read_did_log_raw(&dir)
                .await
                .unwrap(),
            log_before,
            "a did:web repair must not touch the did:webvh log"
        );
        assert!(
            !issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );
    }

    #[cfg(feature = "didwebvh")]
    fn read_json(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// Every file in `dir` with its bytes and modification time.
    #[cfg(feature = "didwebvh")]
    fn snapshot(dir: &std::path::Path) -> std::collections::BTreeMap<String, (Vec<u8>, std::time::SystemTime)> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let metadata = entry.metadata().unwrap();
                (
                    entry
                        .file_name()
                        .to_string_lossy()
                        .into_owned(),
                    (std::fs::read(entry.path()).unwrap(), metadata.modified().unwrap()),
                )
            })
            .collect()
    }

    #[cfg(feature = "didwebvh")]
    async fn start_together(
        dir: &std::path::Path,
        instances: usize,
    ) -> Vec<VCIssuerConfig> {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let starts: Vec<_> = (0..instances)
            .map(|_| {
                let dir = dir.to_path_buf();
                tokio::spawn(async move { VCIssuer::load_or_create_config(dir, "example.com".to_string()).await })
            })
            .collect();
        let mut configs = Vec::new();
        for start in starts {
            configs.push(
                start
                    .await
                    .unwrap()
                    .expect("every instance must start"),
            );
        }
        configs
    }

    /// Gateways that start together on one empty volume publish one DID, signed and listed with
    /// the one signing key every one of them holds.
    #[cfg(feature = "didwebvh")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn instances_starting_together_share_one_gateway_identity() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();

        let configs = start_together(dir, 8).await;

        let did = configs[0].proxy_did.clone();
        assert!(did.starts_with("did:webvh:"), "unexpected DID {did}");
        let key = serde_json::to_value(&configs[0].signing_key).unwrap();
        for config in &configs {
            assert_eq!(config.proxy_did, did, "every instance must hold the same DID");
            assert_eq!(
                serde_json::to_value(&config.signing_key).unwrap(),
                key,
                "every instance must hold the same key"
            );
        }
        let saved = read_json(&dir.join("issuer_config.json"));
        assert_eq!(saved["proxy_did"], did.as_str());
        assert_eq!(saved["signing_key"], key);

        let log: Vec<String> = std::fs::read_to_string(dir.join("did.jsonl"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert_eq!(log.len(), 1, "one birth log entry");
        crate::identity::didwebvh::handlers::build_webvh_state(&did, &log)
            .await
            .expect("the published log must verify");
        let published: serde_json::Value = serde_json::from_str(&log[0]).unwrap();
        assert_signing_key_authorized(&published["state"], &did);
        let expected_key = crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(&configs[0].signing_key).unwrap();
        let multikey = published["state"]["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vm| vm["id"] == format!("{did}#{DEFAULT_SIGNING_KEY_ID}").as_str())
            .unwrap();
        assert_eq!(multikey["publicKeyMultibase"], expected_key.as_str(), "the published key must be the signing key");

        let did_json = read_json(&dir.join("did.json"));
        assert!(
            key_ids(&did_json, "assertionMethod")
                .iter()
                .any(|id| id.ends_with(&format!("#{DEFAULT_SIGNING_KEY_ID}"))),
            "did.json must list the signing key: {did_json}"
        );
        for file in ["x25519_key.json", "p256_key.json"] {
            let secret = read_json(&dir.join(file));
            assert!(
                secret["id"]
                    .as_str()
                    .unwrap()
                    .starts_with(&did),
                "{file} must be named under the published DID: {secret}"
            );
        }
        assert!(
            std::fs::read_dir(dir)
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")),
            "no temporary file may be left behind"
        );
    }

    /// Gateways upgrading one did:web gateway together move it to one did:webvh DID, and every
    /// one of them holds that DID.
    #[cfg(feature = "didwebvh")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn instances_upgrading_together_agree_on_one_did() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        let key = crate::identity::test_helpers::seed_did_web_gateway_without_assertion_multikey(dir).await;

        let configs = start_together(dir, 8).await;

        let log = std::fs::read_to_string(dir.join("did.jsonl")).unwrap();
        let entry: serde_json::Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        let did = entry["state"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(log.lines().count(), 1);
        for config in &configs {
            assert_eq!(config.proxy_did, did, "every instance must hold the published DID");
            assert_eq!(config.signing_key, key, "the existing signing key must be kept");
        }
        assert_eq!(read_json(&dir.join("issuer_config.json"))["proxy_did"], did.as_str());
    }

    /// A gateway that already published its did:webvh DID starts without taking the lock and
    /// without writing anything, even on a volume it cannot write to.
    #[cfg(all(feature = "didwebvh", unix))]
    #[tokio::test]
    async fn healthy_gateway_start_takes_no_lock_and_writes_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let dir = temp_dir.path();
        let published = issuer
            .config
            .read()
            .await
            .clone();
        std::fs::remove_file(dir.join(GATEWAY_DID_LOCK_FILE)).unwrap();
        let before = snapshot(dir);
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let started = VCIssuer::load_or_create_config(dir.to_path_buf(), "example.com".to_string()).await;

        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let config = started.expect("a published gateway must start");
        assert_eq!(config.proxy_did, published.proxy_did);
        assert_eq!(config.signing_key, published.signing_key);
        assert_eq!(snapshot(dir), before, "no file may be written");
        assert!(
            !dir.join(GATEWAY_DID_LOCK_FILE)
                .exists(),
            "a published gateway takes no lock"
        );
    }

    /// A first start that cannot take the lock from another instance creating the gateway DID
    /// fails, so it is restarted, and writes nothing meanwhile.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn fresh_start_fails_while_another_instance_holds_the_lock_and_creates_nothing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        let crate::storage::file_lock::LockOutcome::Acquired(_held) =
            lock_gateway_did(dir, std::time::Duration::ZERO).await
        else {
            panic!("the lock must be free");
        };

        let started = VCIssuer::load_or_create_config_within(
            dir.to_path_buf(),
            "example.com".to_string(),
            std::time::Duration::from_millis(50),
        )
        .await;

        let err = started.expect_err("a first start must not create the gateway DID without the lock");
        assert!(
            err.to_string()
                .contains("lock"),
            "unexpected error: {err}"
        );
        assert_eq!(
            snapshot(dir)
                .into_keys()
                .collect::<Vec<_>>(),
            vec![GATEWAY_DID_LOCK_FILE.to_string()]
        );
    }

    /// A gateway still to be upgraded leaves the upgrade to whoever holds the lock: while the
    /// lock stays held it changes nothing and fails, so it is restarted.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn upgrade_changes_nothing_while_another_gateway_holds_the_lock() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        crate::identity::test_helpers::seed_did_web_gateway_without_assertion_multikey(dir).await;
        let crate::storage::file_lock::LockOutcome::Acquired(_held) =
            lock_gateway_did(dir, std::time::Duration::ZERO).await
        else {
            panic!("the lock must be free");
        };
        let before = snapshot(dir);

        let started = VCIssuer::load_or_create_config_within(
            dir.to_path_buf(),
            "example.com".to_string(),
            std::time::Duration::from_millis(50),
        )
        .await;

        assert!(started.is_err(), "an upgrade must not run without the lock");
        assert_eq!(snapshot(dir), before, "no file may be written");
    }

    /// A published gateway whose key agreement key does not parse refuses to start, as it did
    /// before published gateways skipped creating keys.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn published_gateway_with_an_unreadable_key_agreement_key_does_not_start() {
        let (_issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let dir = temp_dir.path();
        std::fs::write(dir.join("x25519_key.json"), "{").unwrap();

        let err = VCIssuer::load_or_create_config(dir.to_path_buf(), "example.com".to_string())
            .await
            .unwrap_err();

        assert!(format!("{err:#}").contains("x25519_key.json"), "unexpected error: {err:#}");
    }

    /// A gateway booting Active, as a single instance does, creates its DID without the lock on
    /// a volume where the lock file cannot be opened.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn active_gateway_creates_its_did_unlocked_when_the_lock_file_cannot_be_opened() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        std::fs::create_dir(dir.join(GATEWAY_DID_LOCK_FILE)).unwrap();

        let config = crate::server::mode::in_test_mode(
            crate::server::mode::ServerMode::Active,
            VCIssuer::load_or_create_config(dir.to_path_buf(), "example.com".to_string()),
        )
        .await
        .expect("an Active gateway must start without the lock");

        assert!(
            config
                .proxy_did
                .starts_with("did:webvh:")
        );
        assert!(dir.join("did.jsonl").exists());
    }

    /// A gateway booting Standby, as every node of a multi-node gateway does, refuses to create
    /// a new DID without the lock and writes nothing.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn standby_gateway_refuses_to_create_its_did_when_the_lock_file_cannot_be_opened() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        std::fs::create_dir(dir.join(GATEWAY_DID_LOCK_FILE)).unwrap();

        let err = crate::server::mode::in_test_mode(
            crate::server::mode::ServerMode::Standby,
            VCIssuer::load_or_create_config(dir.to_path_buf(), "example.com".to_string()),
        )
        .await
        .unwrap_err();

        assert!(format!("{err:#}").contains("Gateway DID lock unavailable"), "unexpected error: {err:#}");
        let mut written: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        written.sort();
        assert_eq!(written, vec![GATEWAY_DID_LOCK_FILE.to_string()]);
    }

    /// A Standby gateway whose identity is encrypted at rest counts it as existing, so it still
    /// upgrades it without the lock rather than refusing to start.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn standby_gateway_with_an_encrypted_identity_starts_unlocked_when_the_lock_file_cannot_be_opened() {
        enable_test_encryption();
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        let signing_key = crate::identity::test_helpers::seed_did_web_gateway(dir, |_, _| {}).await;
        assert!(
            !dir.join("issuer_config.json")
                .exists()
        );
        std::fs::create_dir(dir.join(GATEWAY_DID_LOCK_FILE)).unwrap();

        let config = crate::server::mode::in_test_mode(
            crate::server::mode::ServerMode::Standby,
            VCIssuer::load_or_create_config(dir.to_path_buf(), "example.com".to_string()),
        )
        .await
        .expect("a Standby gateway with an encrypted identity must start without the lock");

        assert_eq!(config.signing_key, signing_key);
    }

    /// A Standby gateway that finds a partly created identity, as another node creating it
    /// without the lock leaves it, refuses to complete it without the lock.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn standby_gateway_refuses_to_complete_a_partly_created_did_when_the_lock_file_cannot_be_opened() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        crate::identity::test_helpers::seed_did_web_gateway(dir, |_, _| {}).await;
        std::fs::remove_file(dir.join("did.json")).unwrap();
        std::fs::create_dir(dir.join(GATEWAY_DID_LOCK_FILE)).unwrap();

        let err = crate::server::mode::in_test_mode(
            crate::server::mode::ServerMode::Standby,
            VCIssuer::load_or_create_config(dir.to_path_buf(), "example.com".to_string()),
        )
        .await
        .unwrap_err();

        assert!(format!("{err:#}").contains("Gateway DID lock unavailable"), "unexpected error: {err:#}");
        assert!(!dir.join("did.json").exists());
        assert!(!dir.join("did.jsonl").exists());
    }

    /// A Standby gateway whose DID already exists still starts without the lock, upgrading it
    /// where it has to, so an existing gateway never stops starting because of the lock.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn standby_gateway_with_an_existing_did_starts_unlocked_when_the_lock_file_cannot_be_opened() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        let signing_key = crate::identity::test_helpers::seed_did_web_gateway(dir, |_, _| {}).await;
        std::fs::create_dir(dir.join(GATEWAY_DID_LOCK_FILE)).unwrap();

        let config = crate::server::mode::in_test_mode(
            crate::server::mode::ServerMode::Standby,
            VCIssuer::load_or_create_config(dir.to_path_buf(), "example.com".to_string()),
        )
        .await
        .expect("a Standby gateway with an existing DID must start without the lock");

        assert_eq!(config.signing_key, signing_key);
    }

    /// The repair adds the signing key to `assertionMethod` and `authentication` in the stored
    /// `did.json` and changes nothing else in it, even where it no longer matches the log.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_changes_only_the_signing_key_relationships_in_the_did_document() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = issuer
            .get_storage_path()
            .await;
        let mut drifted = read_json(&dir.join("did.json"));
        drifted["keyAgreement"] = json!(["did:web:example.com#key-x25519-2"]);
        crate::storage::did_artifacts::write_did_document(&dir, &serde_json::to_string_pretty(&drifted).unwrap())
            .await
            .unwrap();

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        let repaired = read_json(&dir.join("did.json"));
        let mut expected = drifted.clone();
        for relationship in SIGNING_KEY_RELATIONSHIPS {
            expected[relationship]
                .as_array_mut()
                .unwrap()
                .push(json!(format!("did:web:example.com#{DEFAULT_SIGNING_KEY_ID}")));
        }
        assert_eq!(repaired, expected);
    }

    #[cfg(feature = "didwebvh")]
    fn parallel_did_web(state: &serde_json::Value) -> serde_json::Value {
        let did = state["id"].as_str().unwrap();
        let scid = crate::identity::didwebvh::identifier::parse_did_webvh(did)
            .unwrap()
            .scid
            .unwrap();
        super::parallel_did_document(state, did, &scid).unwrap()
    }

    /// A did.json that does not parse holds nothing to keep, so the repair rebuilds it from the
    /// repaired log version.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_rebuilds_an_unreadable_did_document_from_the_log() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        std::fs::write(dir.join("did.json"), "{").unwrap();

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        let latest = &did_log_entries(&issuer).await[1]["state"];
        assert_eq!(read_json(&dir.join("did.json")), parallel_did_web(latest));
    }

    /// A missing did.json is written from the repaired log version.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_recreates_a_missing_did_document_from_the_log() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        std::fs::remove_file(dir.join("did.json")).unwrap();

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        let latest = &did_log_entries(&issuer).await[1]["state"];
        assert_eq!(read_json(&dir.join("did.json")), parallel_did_web(latest));
    }

    /// A repaired log stands when did.json publishes another key as the Multikey: the repair
    /// reports the log change and leaves did.json as it is.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repaired_log_stands_when_the_did_document_publishes_another_key() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        let other_key = crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(
            &crate::identity::test_helpers::test_signing_key(),
        )
        .unwrap();
        let mut did_json = read_json(&dir.join("did.json"));
        for method in did_json["verificationMethod"]
            .as_array_mut()
            .unwrap()
        {
            if method["type"] == "Multikey" {
                method["publicKeyMultibase"] = json!(other_key);
            }
        }
        crate::storage::did_artifacts::write_did_document(dir, &did_json.to_string())
            .await
            .unwrap();

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        assert_eq!(
            did_log_entries(&issuer)
                .await
                .len(),
            2
        );
        assert_eq!(read_json(&dir.join("did.json")), did_json);
    }

    /// A repaired log stands when did.json publishes the signing key under another DID's
    /// `#key-2`: that id is never listed in the gateway's relationships.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_does_not_list_another_dids_key_2_in_the_did_document() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        let foreign_id = "did:web:attacker.example#key-2";
        let mut did_json = read_json(&dir.join("did.json"));
        for method in did_json["verificationMethod"]
            .as_array_mut()
            .unwrap()
        {
            if method["type"] == "Multikey" {
                method["id"] = json!(foreign_id);
            }
        }
        crate::storage::did_artifacts::write_did_document(dir, &did_json.to_string())
            .await
            .unwrap();

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        assert_eq!(
            did_log_entries(&issuer)
                .await
                .len(),
            2
        );
        assert_eq!(read_json(&dir.join("did.json")), did_json);
    }

    /// A did.json that describes another DID is left as it is, even when it publishes the
    /// gateway signing key as that DID's `#key-2`.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_leaves_a_did_document_of_another_did_unchanged() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        let foreign = "did:web:attacker.example";
        let did_json = read_json(&dir.join("did.json"));
        let own = did_json["id"]
            .as_str()
            .unwrap()
            .to_string();
        let foreign_json: serde_json::Value = serde_json::from_str(
            &did_json
                .to_string()
                .replace(&own, foreign),
        )
        .unwrap();
        crate::storage::did_artifacts::write_did_document(dir, &foreign_json.to_string())
            .await
            .unwrap();

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        assert_eq!(read_json(&dir.join("did.json")), foreign_json);
    }

    /// The signing key reads as listed only once the latest log version and did.json both list
    /// it under assertionMethod and authentication.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn signing_key_is_listed_only_after_the_repair() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        assert!(
            !issuer
                .signing_key_is_listed()
                .await
        );

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        assert!(
            issuer
                .signing_key_is_listed()
                .await
        );
    }

    /// A node no longer Active when the repair would append, as one stepped down during the
    /// repair is, appends nothing and leaves did.json as it is.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_by_a_node_that_stepped_down_appends_nothing() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        let log_before = std::fs::read_to_string(dir.join("did.jsonl")).unwrap();
        let doc_before = std::fs::read_to_string(dir.join("did.json")).unwrap();

        let changed = issuer
            .authorize_signing_key_while(|| false)
            .await
            .unwrap();

        assert!(!changed);
        assert_eq!(std::fs::read_to_string(dir.join("did.jsonl")).unwrap(), log_before);
        assert_eq!(std::fs::read_to_string(dir.join("did.json")).unwrap(), doc_before);
    }

    /// A published gateway whose did.json is gone gets it back at start as the parallel did:web
    /// document of its DID log, which the repair then completes rather than refuses.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn missing_did_document_is_restored_from_the_log_at_start() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        std::fs::remove_file(dir.join("did.json")).unwrap();

        let config = VCIssuer::load_or_create_config(dir.to_path_buf(), "example.com".to_string())
            .await
            .unwrap();

        assert_eq!(
            config.proxy_did,
            issuer
                .get_issuer_did()
                .await
                .unwrap()
        );
        let latest = &did_log_entries(&issuer).await[0]["state"];
        assert_eq!(read_json(&dir.join("did.json")), parallel_did_web(latest));
        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );
        assert!(
            issuer
                .signing_key_is_listed()
                .await
        );
    }

    /// A published gateway whose did.json and log are both unusable still starts: the restore
    /// is skipped with a warning and did.json is generated as before.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn gateway_starts_when_its_did_document_cannot_be_restored_from_the_log() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        std::fs::remove_file(dir.join("did.json")).unwrap();
        std::fs::write(dir.join("did.jsonl"), "{\"not\": \"a log entry\"}\n").unwrap();

        let config = VCIssuer::load_or_create_config(dir.to_path_buf(), "example.com".to_string())
            .await
            .expect("a log that does not verify must not stop the gateway from starting");

        assert_eq!(
            config.proxy_did,
            issuer
                .get_issuer_did()
                .await
                .unwrap()
        );
        assert!(dir.join("did.json").exists());
    }

    /// A `did:webvh` gateway whose did.jsonl is gone still gets its did.json repaired, and no
    /// log is created for it.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_without_a_did_log_repairs_the_did_document() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        std::fs::remove_file(dir.join("did.jsonl")).unwrap();

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        assert!(!dir.join("did.jsonl").exists());
        let did_json = read_json(&dir.join("did.json"));
        let multikey_id = format!(
            "{}#{DEFAULT_SIGNING_KEY_ID}",
            did_json["id"]
                .as_str()
                .unwrap()
        );
        for relationship in SIGNING_KEY_RELATIONSHIPS {
            assert!(
                did_json[relationship]
                    .as_array()
                    .unwrap()
                    .contains(&json!(multikey_id)),
                "{relationship} must list {multikey_id}: {did_json}"
            );
        }
    }

    /// A log whose update key is not the gateway signing key is refused and left as it is: no
    /// version can be signed for it with the keys the gateway holds.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_refuses_a_log_the_signing_key_cannot_update() {
        let (issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = issuer
            .get_storage_path()
            .await;
        let entry = &did_log_entries(&issuer).await[0];
        let mut document = entry["state"].clone();
        let scid = entry["parameters"]["scid"]
            .as_str()
            .unwrap()
            .to_string();
        document = serde_json::from_str(
            &document
                .to_string()
                .replace(&format!("did:webvh:{scid}:"), "did:webvh:{SCID}:"),
        )
        .unwrap();
        let other_key = crate::identity::test_helpers::test_signing_key();
        let created = crate::identity::didwebvh::create::create_webvh_did(
            &serde_json::to_value(&other_key).unwrap(),
            document,
            &crate::identity::didwebvh::base_url_for_domain("example.com"),
        )
        .await
        .unwrap();
        crate::storage::did_artifacts::write_did_log_raw(&dir, &created.log_entry_json)
            .await
            .unwrap();
        issuer
            .config
            .write()
            .await
            .proxy_did = created.final_did.clone();
        let log_before = std::fs::read_to_string(dir.join("did.jsonl")).unwrap();

        let err = issuer
            .authorize_signing_key()
            .await
            .unwrap_err();

        assert!(format!("{err:#}").contains("updateKey"), "unexpected error: {err:#}");
        assert_eq!(std::fs::read_to_string(dir.join("did.jsonl")).unwrap(), log_before);
    }

    /// Every relationship of a gateway DID document points at a key it publishes, with the type
    /// that relationship needs: the signing key, as JsonWebKey2020 and as Multikey, under
    /// assertionMethod and authentication, and the two key agreement keys under keyAgreement.
    #[cfg(feature = "didwebvh")]
    fn assert_gateway_did_document_structure(doc: &serde_json::Value) {
        let did = doc["id"]
            .as_str()
            .unwrap_or_else(|| panic!("the DID document must name its DID: {doc}"));
        let methods: HashMap<&str, &serde_json::Value> = doc["verificationMethod"]
            .as_array()
            .unwrap_or_else(|| panic!("the DID document must publish verificationMethod: {doc}"))
            .iter()
            .map(|method| (method["id"].as_str().unwrap(), method))
            .collect();
        let expect_method = |fragment: &str, key_type: &str| {
            let id = format!("{did}#{fragment}");
            let method = methods
                .get(id.as_str())
                .unwrap_or_else(|| panic!("verificationMethod must publish {id}: {doc}"));
            assert_eq!(method["type"], key_type, "{id} type");
            assert_eq!(method["controller"], did, "{id} controller");
            id
        };
        let key_1 = expect_method("key-1", "JsonWebKey2020");
        let key_2 = expect_method(DEFAULT_SIGNING_KEY_ID, "Multikey");
        let x25519 = expect_method("key-x25519-1", "JsonWebKey2020");
        let p256 = expect_method("key-p256-1", "JsonWebKey2020");
        assert_eq!(methods.len(), 4, "no other key may be published: {doc}");
        let key_1_jwk: JWK = serde_json::from_value(methods[key_1.as_str()]["publicKeyJwk"].clone()).unwrap();
        assert_eq!(
            methods[key_2.as_str()]["publicKeyMultibase"],
            crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(&key_1_jwk)
                .unwrap()
                .as_str(),
            "#key-1 and #key-2 must publish the same signing key"
        );
        for relationship in SIGNING_KEY_RELATIONSHIPS {
            assert_eq!(key_ids(doc, relationship), vec![key_1.clone(), key_2.clone()], "{relationship}");
        }
        assert_eq!(key_ids(doc, "keyAgreement"), vec![x25519, p256], "keyAgreement");
        assert!(
            doc["service"]
                .as_array()
                .is_some_and(|services| services
                    .iter()
                    .any(|service| service["id"] == format!("{did}#didcomm").as_str())),
            "the DID document must publish its DIDComm service: {doc}"
        );
    }

    /// A new gateway publishes a complete DID document, in its DID log and in did.json.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn new_gateway_publishes_a_complete_did_document() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;

        assert_gateway_did_document_structure(&did_log_entries(&issuer).await[0]["state"]);
        assert_gateway_did_document_structure(&read_json(
            &temp_dir
                .path()
                .join("did.json"),
        ));
    }

    /// A repaired gateway publishes a complete DID document, in its DID log and in did.json.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repaired_gateway_publishes_a_complete_did_document() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        assert_gateway_did_document_structure(&did_log_entries(&issuer).await[1]["state"]);
        assert_gateway_did_document_structure(&read_json(
            &temp_dir
                .path()
                .join("did.json"),
        ));
    }

    #[cfg(feature = "didwebvh")]
    fn signing_key_document() -> (serde_json::Value, String, JWK) {
        let key = crate::identity::test_helpers::test_signing_key();
        let did = "did:web:example.com";
        let mut document = gateway_did_document(did, &key, "x", json!({}), "p", json!({})).unwrap();
        for relationship in SIGNING_KEY_RELATIONSHIPS {
            document[relationship] = json!([format!("{did}#key-1")]);
        }
        (document, format!("{did}#{DEFAULT_SIGNING_KEY_ID}"), key)
    }

    /// A document missing a relationship the signing key belongs to, or holding something
    /// other than a list there, is refused and left exactly as it was.
    #[cfg(feature = "didwebvh")]
    #[test]
    fn signing_key_is_not_authorized_in_a_document_missing_a_relationship() {
        for relationship in SIGNING_KEY_RELATIONSHIPS {
            for broken in [None, Some(json!("did:web:example.com#key-1"))] {
                let (mut document, multikey_id, key) = signing_key_document();
                match &broken {
                    None => {
                        document
                            .as_object_mut()
                            .unwrap()
                            .remove(relationship);
                    }
                    Some(value) => document[relationship] = value.clone(),
                }
                let before = document.clone();

                let err = add_signing_key_to_relationships(&mut document, &multikey_id, &key).unwrap_err();

                assert!(
                    err.to_string()
                        .contains(&format!("has no {relationship}")),
                    "{relationship} {broken:?}: unexpected error: {err}"
                );
                assert_eq!(document, before, "{relationship} {broken:?}: the document must not change");
            }
        }
    }

    /// A document that publishes no verification methods, or publishes the signing key id as a
    /// key of another type, is refused and left exactly as it was.
    #[cfg(feature = "didwebvh")]
    #[test]
    fn signing_key_is_not_authorized_without_its_published_multikey() {
        type BreakDocument = fn(&mut serde_json::Value);
        let cases: [(&str, BreakDocument); 3] = [
            ("does not publish", |document| {
                document
                    .as_object_mut()
                    .unwrap()
                    .remove("verificationMethod");
            }),
            ("does not publish", |document| document["verificationMethod"] = json!([])),
            ("a key other than the gateway signing key", |document| {
                document["verificationMethod"][1]["type"] = json!("JsonWebKey2020");
            }),
        ];
        for (expected, break_document) in cases {
            let (mut document, multikey_id, key) = signing_key_document();
            break_document(&mut document);
            let before = document.clone();

            let err = add_signing_key_to_relationships(&mut document, &multikey_id, &key).unwrap_err();

            assert!(
                err.to_string()
                    .contains(expected),
                "unexpected error: {err}"
            );
            assert_eq!(document, before, "the document must not change");
        }
    }

    /// A gateway DID log whose latest version has no authentication is refused: no version is
    /// added and did.json is left as it is.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_refuses_a_did_log_without_authentication() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        crate::identity::test_helpers::seed_did_web_gateway(dir, |document, did| {
            document["assertionMethod"] = json!([format!("{did}#key-1")]);
            document
                .as_object_mut()
                .unwrap()
                .remove("authentication");
        })
        .await;
        let issuer = VCIssuer::new(
            dir,
            "example.com",
            Arc::new(MockIdentityStore::new()),
            Arc::new(MockVpChallengeStore::new()),
            None,
            None,
        )
        .await
        .unwrap();
        let before = snapshot(dir);

        let err = issuer
            .authorize_signing_key()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("has no authentication"),
            "unexpected error: {err:#}"
        );
        assert_eq!(snapshot(dir), before, "nothing may be written");
    }

    /// A did.json without assertionMethod behind a repaired DID log is refused and left as it
    /// is, rather than rebuilt from the log.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_refuses_a_did_document_without_assertion_method() {
        let (issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer_without_assertion_multikey().await;
        let dir = temp_dir.path();
        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );
        let mut did_json = read_json(&dir.join("did.json"));
        did_json
            .as_object_mut()
            .unwrap()
            .remove("assertionMethod");
        crate::storage::did_artifacts::write_did_document(dir, &did_json.to_string())
            .await
            .unwrap();
        let before = snapshot(dir);

        let err = issuer
            .authorize_signing_key()
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("has no assertionMethod"),
            "unexpected error: {err:#}"
        );
        assert_eq!(snapshot(dir), before, "nothing may be written");
    }

    #[cfg(feature = "didwebvh")]
    #[test]
    fn signing_key_is_added_to_assertion_method_and_authentication_once() {
        let key = crate::identity::test_helpers::test_signing_key();
        let did = "did:web:example.com";
        let multikey_id = format!("{did}#{DEFAULT_SIGNING_KEY_ID}");
        let mut document = gateway_did_document(did, &key, "x", json!({}), "p", json!({})).unwrap();
        document["assertionMethod"] = json!([format!("{did}#key-1")]);
        document["authentication"] = json!([format!("{did}#key-1")]);

        assert!(add_signing_key_to_relationships(&mut document, &multikey_id, &key).unwrap());
        assert!(!add_signing_key_to_relationships(&mut document, &multikey_id, &key).unwrap());

        for relationship in SIGNING_KEY_RELATIONSHIPS {
            assert_eq!(key_ids(&document, relationship), vec![format!("{did}#key-1"), multikey_id.clone()]);
        }
    }

    /// A document that already lists the signing key under assertionMethod, as gateways created
    /// after it was listed there publish, gets it added under authentication only.
    #[cfg(feature = "didwebvh")]
    #[test]
    fn signing_key_is_added_to_authentication_when_assertion_method_lists_it() {
        let key = crate::identity::test_helpers::test_signing_key();
        let did = "did:web:example.com";
        let multikey_id = format!("{did}#{DEFAULT_SIGNING_KEY_ID}");
        let mut document = gateway_did_document(did, &key, "x", json!({}), "p", json!({})).unwrap();
        document["authentication"] = json!([format!("{did}#key-1")]);
        let assertion_method = document["assertionMethod"].clone();

        assert!(add_signing_key_to_relationships(&mut document, &multikey_id, &key).unwrap());

        assert_eq!(document["assertionMethod"], assertion_method);
        assert_eq!(key_ids(&document, "authentication"), vec![format!("{did}#key-1"), multikey_id]);
    }

    /// A gateway that already lists its signing key under assertionMethod but not under
    /// authentication gets one new version that adds it there, and nothing else changes.
    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn repair_adds_the_signing_key_to_authentication_of_a_gateway_that_lists_it_for_assertions() {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path();
        crate::identity::test_helpers::seed_did_web_gateway(dir, |document, did| {
            document["authentication"] = json!([format!("{did}#key-1")]);
        })
        .await;
        let issuer = VCIssuer::new(
            dir,
            "example.com",
            Arc::new(MockIdentityStore::new()),
            Arc::new(MockVpChallengeStore::new()),
            None,
            None,
        )
        .await
        .unwrap();
        let did = issuer
            .get_issuer_did()
            .await
            .unwrap();
        let before = did_log_entries(&issuer).await;
        assert_eq!(key_ids(&before[0]["state"], "authentication"), vec![format!("{did}#key-1")]);

        assert!(
            issuer
                .authorize_signing_key()
                .await
                .unwrap()
        );

        let after = did_log_entries(&issuer).await;
        assert_eq!(after.len(), 2);
        assert_signing_key_authorized(&after[1]["state"], &did);
        let mut unchanged = after[1]["state"].clone();
        unchanged["authentication"] = before[0]["state"]["authentication"].clone();
        assert_eq!(unchanged, before[0]["state"], "only authentication may change");
    }

    /// Only the gateway's own signing key is ever authorized, never a key published under its id.
    #[cfg(feature = "didwebvh")]
    #[test]
    fn signing_key_is_not_authorized_when_the_document_publishes_another_key() {
        let did = "did:web:example.com";
        let multikey_id = format!("{did}#{DEFAULT_SIGNING_KEY_ID}");
        let other_key = crate::identity::test_helpers::test_signing_key();
        let mut document = gateway_did_document(did, &other_key, "x", json!({}), "p", json!({})).unwrap();
        document["assertionMethod"] = json!([format!("{did}#key-1")]);
        let before = document.clone();

        let err = add_signing_key_to_relationships(
            &mut document,
            &multikey_id,
            &crate::identity::test_helpers::test_signing_key(),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("a key other than the gateway signing key"),
            "unexpected error: {err}"
        );
        assert_eq!(document, before);
    }

    #[cfg(feature = "didwebvh")]
    #[test]
    fn signing_key_is_not_authorized_when_the_document_publishes_key_2_twice() {
        let key = crate::identity::test_helpers::test_signing_key();
        let did = "did:web:example.com";
        let multikey_id = format!("{did}#{DEFAULT_SIGNING_KEY_ID}");
        let mut document = gateway_did_document(did, &key, "x", json!({}), "p", json!({})).unwrap();
        document["assertionMethod"] = json!([format!("{did}#key-1")]);
        let other_key = crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(
            &crate::identity::test_helpers::test_signing_key(),
        )
        .unwrap();
        document["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": multikey_id,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": other_key
            }));
        let before = document.clone();

        let err = add_signing_key_to_relationships(&mut document, &multikey_id, &key).unwrap_err();

        assert!(
            err.to_string()
                .contains("more than once"),
            "unexpected error: {err}"
        );
        assert_eq!(document, before);
    }

    #[cfg(feature = "didwebvh")]
    #[test]
    fn signing_key_is_not_authorized_when_the_document_does_not_publish_it() {
        let key = crate::identity::test_helpers::test_signing_key();
        let did = "did:web:example.com";
        let multikey_id = format!("{did}#{DEFAULT_SIGNING_KEY_ID}");
        let mut document = json!({
            "id": did,
            "verificationMethod": [],
            "assertionMethod": [format!("{did}#key-1")]
        });

        let err = add_signing_key_to_relationships(&mut document, &multikey_id, &key).unwrap_err();

        assert!(
            err.to_string()
                .contains("does not publish"),
            "unexpected error: {err}"
        );
        assert_eq!(key_ids(&document, "assertionMethod"), vec![format!("{did}#key-1")]);
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

    /// Runs the calling test again in a process of its own started with
    /// `AG_TEST_MODE=true`. Returns `true` in that process, where the test body
    /// should run.
    fn run_with_ag_test_mode_env() -> bool {
        crate::a2a::version::run_isolated_from_other_tests_with_env(&[("AG_TEST_MODE", "true")], &[])
    }

    #[tokio::test]
    async fn test_mode_does_not_accept_unverifiable_presentation() {
        if !run_with_ag_test_mode_env() {
            return;
        }
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

        let result = issuer
            .verify_agent_presentation_full(&vp)
            .await;

        let err = result.expect_err("an unsigned presentation must never verify, whatever the environment says");
        assert!(format!("{err:#}").contains("VP verification failed"), "unexpected error: {err:#}");
    }

    #[tokio::test]
    async fn test_mode_does_not_mint_for_unknown_agent_did() {
        if !run_with_ag_test_mode_env() {
            return;
        }
        let (issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let identity_fields = HashMap::from([("name".to_string(), json!("agent"))]);

        let result = issuer
            .create_agent_identity_presentation("did:example:no-key", &identity_fields, None, None)
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
                    .save(&crate::identity::test_helpers::test_surface_with_managed_identity(surface_id, name))
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

        fn protected() -> ManagedIdentitySource {
            ManagedIdentitySource::protected()
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
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-managed".into()), None, protected())
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
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-rename".into()), None, protected())
                .await
                .unwrap();

            f.save_surface("vc-name-rename", "HELIUM")
                .await;
            let second = issuer
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-rename".into()), None, protected())
                .await
                .unwrap();

            assert_eq!(second.did, first.did);
            assert!(!second.is_new);
            assert_eq!(jwt_subject(&second.credential)["name"], json!("HELIUM"));
        }

        #[tokio::test]
        async fn did_on_two_surfaces_gets_no_name() {
            let f = fixture().await;
            f.save_surface("vc-name-shared-a", "OXYGEN")
                .await;
            f.save_surface("vc-name-shared-b", "HELIUM")
                .await;
            let issuer = &f.issuer;
            let first = issuer
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-shared-a".into()), None, protected())
                .await
                .unwrap();

            let mut sibling =
                crate::identity::test_helpers::test_surface_identity_record(&first.did, "vc-name-shared-b");
            sibling.identity_hash = "sibling".to_string();
            sibling.origin = Some(IdentityOrigin::Managed);
            issuer
                .get_identity_store()
                .create(sibling)
                .await
                .unwrap();

            let second = issuer
                .issue_or_get_managed_credential(fields("a"), None, Some("vc-name-shared-a".into()), None, protected())
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
        async fn managed_agent_calling_another_surface_keeps_its_name() {
            let f = fixture().await;
            f.save_surface("vc-name-calls-oxygen", "OXYGEN")
                .await;
            f.save_surface("vc-name-calls-delta", "DELTA")
                .await;
            let issuer = &f.issuer;
            let managed = issuer
                .issue_or_get_managed_credential(
                    fields("bravo"),
                    None,
                    Some("vc-name-calls-oxygen".into()),
                    None,
                    protected(),
                )
                .await
                .unwrap();
            let caller = issuer
                .issue_or_get_caller_credential(fields("bravo"), None, Some("vc-name-calls-delta".into()), None)
                .await
                .unwrap();

            let reissued = issuer
                .issue_or_get_managed_credential(
                    fields("bravo"),
                    None,
                    Some("vc-name-calls-oxygen".into()),
                    None,
                    protected(),
                )
                .await
                .unwrap();

            assert_eq!(caller.did, managed.did);
            assert_eq!(reissued.did, managed.did);
            assert_eq!(jwt_subject(&reissued.credential)["name"], json!("OXYGEN"));
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
                .issue_or_get_managed_credential(
                    fields("legacy"),
                    None,
                    Some("vc-name-backfill".into()),
                    None,
                    protected(),
                )
                .await
                .unwrap();
            let still_caller = issuer
                .issue_or_get_managed_credential(
                    fields("caller"),
                    None,
                    Some("vc-name-backfill".into()),
                    None,
                    protected(),
                )
                .await
                .unwrap();

            assert_eq!(backfilled.did, legacy.did);
            assert_eq!(origin_of(issuer, &legacy.did).await, Some(IdentityOrigin::Managed));
            assert_eq!(jwt_subject(&backfilled.credential)["name"], json!("OXYGEN"));
            assert_eq!(origin_of(issuer, &caller.did).await, Some(IdentityOrigin::ExternalCaller));
            let slot_of = |did: String| async move {
                issuer
                    .get_identity_store()
                    .find_by_did(&did)
                    .await
                    .unwrap()
                    .unwrap()
                    .slot
            };
            assert_eq!(slot_of(legacy.did.clone()).await, Some(crate::identity::filesystem::ManagedSlot::Protected));
            assert_eq!(slot_of(caller.did.clone()).await, None, "a caller record never takes a managed slot");
            assert!(
                jwt_subject(&still_caller.credential)
                    .get("name")
                    .is_none()
            );
        }

        fn api_key_fields(key_id: &str) -> HashMap<String, serde_json::Value> {
            HashMap::from([
                ("credential_type".to_string(), json!("api_key")),
                ("api_key_id".to_string(), json!(key_id)),
            ])
        }

        fn api_key_hash(key_id: &str) -> Option<String> {
            Some(format!("hash-{key_id}"))
        }

        /// Reads every record without its origin, as a lookup that ran before
        /// a concurrent request stamped it would.
        struct StaleOriginStore(crate::identity::test_helpers::MockIdentityStore);

        #[async_trait::async_trait]
        impl IdentityStore for StaleOriginStore {
            async fn create(
                &self,
                record: crate::identity::filesystem::AgentIdentityRecord,
            ) -> Result<()> {
                self.0.create(record).await
            }
            async fn find_by_hash(
                &self,
                identity_hash: &str,
            ) -> Result<Option<crate::identity::filesystem::AgentIdentityRecord>> {
                Ok(self
                    .0
                    .find_by_hash(identity_hash)
                    .await?
                    .map(|record| crate::identity::filesystem::AgentIdentityRecord { origin: None, ..record }))
            }
            async fn find_by_did(
                &self,
                did: &str,
            ) -> Result<Option<crate::identity::filesystem::AgentIdentityRecord>> {
                self.0.find_by_did(did).await
            }
            async fn list_all(&self) -> Result<Vec<crate::identity::filesystem::AgentIdentityRecord>> {
                self.0.list_all().await
            }
            async fn update_usage(
                &self,
                identity_hash: &str,
                channel_config_id: Option<String>,
                role: Option<IdentityOrigin>,
            ) -> Result<()> {
                self.0
                    .update_usage(identity_hash, channel_config_id, role)
                    .await
            }
            async fn store_external_did(
                &self,
                did: &str,
                identity_fields: HashMap<String, serde_json::Value>,
                channel_config_id: Option<String>,
                verified: bool,
            ) -> Result<()> {
                self.0
                    .store_external_did(did, identity_fields, channel_config_id, verified)
                    .await
            }
            async fn set_origin(
                &self,
                identity_hash: &str,
                origin: IdentityOrigin,
            ) -> Result<Option<IdentityOrigin>> {
                self.0
                    .set_origin(identity_hash, origin)
                    .await
            }
        }

        async fn existing_identity_with_failing_origin_store(
            fields: HashMap<String, serde_json::Value>,
            hash: &str,
        ) -> (Result<AgentIdentityResponse>, String) {
            let store = Arc::new(crate::identity::test_helpers::OriginFailingIdentityStore(
                crate::identity::test_helpers::MockIdentityStore::new(),
            ));
            let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer_with(store).await;
            let legacy = issuer
                .issue_or_get_credential(fields.clone(), Some(hash.to_string()), Some("vc-origin-fail".into()), None)
                .await
                .unwrap();
            let result = issuer
                .issue_or_get_caller_credential(fields, Some(hash.to_string()), Some("vc-origin-fail".into()), None)
                .await;
            (result, legacy.did)
        }

        #[tokio::test]
        async fn api_key_identity_resolves_when_its_origin_cannot_be_recorded() {
            let (result, legacy_did) =
                existing_identity_with_failing_origin_store(api_key_fields("atgk_f"), "hash-atgk_f").await;

            assert_eq!(result.unwrap().did, legacy_did);
        }

        #[tokio::test]
        async fn other_identity_resolves_when_its_origin_cannot_be_recorded() {
            let (result, legacy_did) =
                existing_identity_with_failing_origin_store(fields("payload"), "hash-payload").await;

            assert_eq!(result.unwrap().did, legacy_did);
        }

        #[tokio::test]
        async fn api_key_role_stamped_concurrently_is_kept_and_shared() {
            let store = Arc::new(StaleOriginStore(crate::identity::test_helpers::MockIdentityStore::new()));
            let (issuer, _dir) = crate::identity::test_helpers::test_vc_issuer_with(store.clone()).await;
            let managed = issuer
                .issue_or_get_managed_credential(
                    api_key_fields("atgk_r"),
                    api_key_hash("atgk_r"),
                    Some("vc-shared-r".into()),
                    None,
                    ManagedIdentitySource::protected(),
                )
                .await
                .unwrap();

            let caller = issuer
                .issue_or_get_caller_credential(
                    api_key_fields("atgk_r"),
                    api_key_hash("atgk_r"),
                    Some("vc-shared-r".into()),
                    None,
                )
                .await
                .unwrap();

            assert_eq!(caller.did, managed.did);
            let record = store
                .0
                .find_by_did(&managed.did)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.origin, Some(IdentityOrigin::Managed));
        }

        #[tokio::test]
        async fn caller_api_key_on_a_managed_record_shares_its_did_and_role() {
            let f = fixture().await;
            let issuer = &f.issuer;
            let managed = issuer
                .issue_or_get_managed_credential(
                    api_key_fields("atgk_m"),
                    api_key_hash("atgk_m"),
                    Some("vc-shared-m".into()),
                    None,
                    ManagedIdentitySource::protected(),
                )
                .await
                .unwrap();

            let caller = issuer
                .issue_or_get_caller_credential(
                    api_key_fields("atgk_m"),
                    api_key_hash("atgk_m"),
                    Some("vc-shared-m".into()),
                    None,
                )
                .await
                .unwrap();

            assert_eq!(caller.did, managed.did);
            assert!(!caller.is_new);
            assert_eq!(origin_of(issuer, &managed.did).await, Some(IdentityOrigin::Managed));
        }

        #[tokio::test]
        async fn managed_api_key_on_a_caller_record_shares_its_did_and_role() {
            let f = fixture().await;
            let issuer = &f.issuer;
            let caller = issuer
                .issue_or_get_caller_credential(
                    api_key_fields("atgk_c"),
                    api_key_hash("atgk_c"),
                    Some("vc-shared-c".into()),
                    None,
                )
                .await
                .unwrap();

            let managed = issuer
                .issue_or_get_managed_credential(
                    api_key_fields("atgk_c"),
                    api_key_hash("atgk_c"),
                    Some("vc-shared-c".into()),
                    None,
                    ManagedIdentitySource::protected(),
                )
                .await
                .unwrap();

            assert_eq!(managed.did, caller.did);
            assert!(!managed.is_new);
            assert_eq!(origin_of(issuer, &caller.did).await, Some(IdentityOrigin::ExternalCaller));
        }

        #[tokio::test]
        async fn api_key_in_its_own_role_resolves_the_same_did() {
            let f = fixture().await;
            let issuer = &f.issuer;
            let first = issuer
                .issue_or_get_caller_credential(
                    api_key_fields("atgk_s"),
                    api_key_hash("atgk_s"),
                    Some("vc-shared-s".into()),
                    None,
                )
                .await
                .unwrap();
            let second = issuer
                .issue_or_get_caller_credential(
                    api_key_fields("atgk_s"),
                    api_key_hash("atgk_s"),
                    Some("vc-shared-s".into()),
                    None,
                )
                .await
                .unwrap();

            assert_eq!(second.did, first.did);
            assert!(!second.is_new);
        }

        #[tokio::test]
        async fn display_name_for_did_follows_record_origin() {
            let f = fixture().await;
            f.save_surface("vc-name-vp", "OXYGEN")
                .await;
            let issuer = &f.issuer;
            let managed = issuer
                .issue_or_get_managed_credential(fields("m"), None, Some("vc-name-vp".into()), None, protected())
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
        async fn managed_credential_records_its_slot_and_credential_rotations() {
            let f = fixture().await;
            let issuer = &f.issuer;
            let key = |updated_at: i64| {
                ManagedIdentitySource::transit_point("tp-1")
                    .with_credential_updated_at(chrono::DateTime::from_timestamp(1_767_225_600 + updated_at, 0))
            };
            let mtls = |fingerprint: &str| {
                HashMap::from([
                    ("credential_type".to_string(), json!("mtls")),
                    ("fingerprint_sha256".to_string(), json!(fingerprint)),
                ])
            };

            let first = issuer
                .issue_or_get_managed_credential(mtls("aa"), Some("cred".into()), None, None, key(0))
                .await
                .unwrap();
            let rotated = issuer
                .issue_or_get_managed_credential(mtls("bb"), Some("cred".into()), None, None, key(60))
                .await
                .unwrap();
            issuer
                .issue_or_get_managed_credential(mtls("bb"), Some("cred".into()), None, None, protected())
                .await
                .unwrap();

            assert_eq!(rotated.did, first.did);
            let record = issuer
                .get_identity_store()
                .find_by_did(&first.did)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                record.slot,
                Some(crate::identity::filesystem::ManagedSlot::TransitPoint { alias: "tp-1".into() })
            );
            assert_eq!(record.identity_fields, mtls("bb"));
            assert_eq!(record.rotations.len(), 1);
            assert_eq!(record.rotations[0].previous, HashMap::from([("fingerprint_sha256".to_string(), json!("aa"))]));
        }

        #[tokio::test]
        async fn caller_credential_records_no_slot() {
            let f = fixture().await;
            let issuer = &f.issuer;

            let response = issuer
                .issue_or_get_caller_credential(fields("c"), None, None, None)
                .await
                .unwrap();

            let record = issuer
                .get_identity_store()
                .find_by_did(&response.did)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.slot, None);
        }

        #[tokio::test]
        async fn unknown_surface_issues_without_name() {
            let f = fixture().await;
            let issuer = &f.issuer;

            let response = issuer
                .issue_or_get_managed_credential(
                    fields("a"),
                    None,
                    Some("vc-name-missing-surface".into()),
                    None,
                    protected(),
                )
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

        // The same seed the hex above encodes, and the one the other live
        // suites authenticate with, so a single ACL grant covers them all.
        let control = Arc::new(ControlKey::from_seed([0x2a; 32]));
        let client = VtaRestClient::new(&url, &vta_did, control, std::time::Duration::from_secs(15), 8, None)
            .expect("build a live client");
        let idx: u32 = rand::random::<u32>() % 2_000_000;
        let key_id = format!("gateway-surface-e2e-{idx}");
        let created: serde_json::Value = client
            .dispatch_signed(
                "https://trusttasks.org/spec/keys/create/0.1",
                json!({
                    "keyType": "ed25519",
                    "keyId": key_id,
                    "label": "gateway-surface-e2e",
                    "contextId": context,
                    "internal": true,
                }),
            )
            .await
            .expect("the granted control DID can mint a key in its context");
        // An internal key's record is never returned again, so its public half
        // is taken from the response that created it — what provisioning does.
        let public_key = crate::vta::context_identity::payload_of(&created)["key"]["publicKey"]
            .as_str()
            .expect("the create response carries the public key")
            .to_string();

        crate::config::vta::VtaConfig {
            enabled: true,
            base_url: Some(url),
            vta_did: Some(vta_did),
            context_id: Some(context),
            signing_key_id: Some(key_id),
            signing_key_public: Some(public_key),
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

    /// Mint a key in the granted context, returning its id and public key. The
    /// public half comes from the response that created the key, because an
    /// internal key's record is never returned again.
    async fn mint_key(client: &Arc<crate::vta::client::VtaRestClient>) -> (String, String) {
        let key_id = format!("live-conn-{}", uuid::Uuid::new_v4());
        let context =
            std::env::var("VTA_LIVE_PARENT_CONTEXT").expect("set VTA_LIVE_PARENT_CONTEXT to the granted context");
        let created: serde_json::Value = client
            .dispatch_signed(
                "https://trusttasks.org/spec/keys/create/0.1",
                json!({
                    "keyType": "ed25519",
                    "keyId": key_id,
                    "label": "live connection test",
                    "contextId": context,
                    "internal": true,
                }),
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "could not mint a key as {}.\n\
                     Grant it first (stop the VTA, it holds a file lock):\n  \
                     vta --config <cfg> acl create --did {} --role initiator \
                     --contexts <context> --capabilities context-create,key-mint,sign-jws,sign-document\n\
                     underlying error: {e}",
                    control_did(),
                    control_did(),
                )
            });
        let public_key = crate::vta::context_identity::payload_of(&created)["key"]["publicKey"]
            .as_str()
            .expect("the create response carries the public key")
            .to_string();
        (key_id, public_key)
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
        let (active_key, active_public_key) = mint_key(&client).await;
        let (other_key, other_public_key) = mint_key(&client).await;

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
                control_did: None,
                control_key_state: Default::default(),
                status: VtaConnectionStatus::Connected,
                keys: SigningKeys {
                    active: Some(SigningKey {
                        key_id: active_key.clone(),
                        public_key: Some(active_public_key.clone()),
                        label: None,
                        added_at: now,
                        retired_at: None,
                    }),
                    // The second surface names a different key of the same agent.
                    // The connection records both halves, as provisioning does,
                    // because an internal key's record is never returned again.
                    retiring: vec![SigningKey {
                        key_id: other_key.clone(),
                        public_key: Some(other_public_key),
                        label: None,
                        added_at: now,
                        retired_at: Some(now),
                    }],
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
            format!("did:key:{active_public_key}"),
            "a connection-backed surface must be issued by the key that signed it — its own did:key, never the gateway's"
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
    use serde_json::json;

    /// A trust agent that holds the surface's context key and really signs, so
    /// the credential the surface's agent issues is a real one.
    async fn spawn_agent() -> (String, crate::vta::context_identity::mock::MockContextVta) {
        let vta = crate::vta::context_identity::mock::MockContextVta::new("ctx-a", "ctx-a-issuer");
        let url = vta.spawn().await;
        (url, vta)
    }

    /// A connection `vta-a` to the trust agent at `agent_url`, connected and
    /// holding its control key, behind a registry.
    async fn agent_registry(
        dir: &std::path::Path,
        agent_url: &str,
    ) -> Arc<crate::vta::registry::VtaConnectionRegistry> {
        // The control key the connection authenticates with.
        let secrets: Arc<dyn crate::secrets::SecretsStore> = Arc::new(
            crate::secrets::FilesystemSecretsStore::new_async(
                dir.join("secrets")
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
            crate::vta::connections::FileSystemVtaConnectionStore::new(dir.join("conns"))
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
                endpoint: agent_url.to_string(),
                vta_did: "did:webvh:agent.example".to_string(),
                default_context_id: Some("ctx-a".to_string()),
                control_key_ref: Some("ctl".to_string()),
                control_did: None,
                control_key_state: Default::default(),
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

        Arc::new(crate::vta::registry::VtaConnectionRegistry::new(
            connections,
            Some(secrets),
            None,
            None,
            std::time::Duration::from_secs(5),
            4,
        ))
    }

    /// The whole chain, as the proxy drives it: a surface that names an agent
    /// must have that agent issue the credential embedded in the presentation
    /// it forwards.
    #[tokio::test]
    async fn a_surface_mapped_to_an_agent_has_it_issue_the_embedded_credential() {
        let (agent_url, recorder) = spawn_agent().await;
        let tmp = tempfile::tempdir().expect("tempdir");
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
        let registry = agent_registry(tmp.path(), &agent_url).await;
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
        let signed_before = recorder.sign_calls();
        let outcome = issuer
            .create_agent_identity_presentation_with_binding(&agent_did, &fields, None, None, None, Some("surface-1"))
            .await;
        // The presentation itself is asserted below only through what the agent
        // was asked to do: every bug behind this symptom silently signed
        // locally instead, and produced a perfectly valid presentation while
        // doing so, so a valid presentation proves nothing here.
        let presentation = outcome.expect("the surface's presentation is assembled");
        assert!(!presentation.is_empty(), "a presentation was produced");

        assert!(
            recorder.sign_calls() > signed_before,
            "the surface's agent must sign the embedded credential; no new signature means the \
             gateway signed locally and the agent never saw the request"
        );
        assert_eq!(
            recorder
                .last_context_read
                .lock()
                .unwrap()
                .as_deref(),
            Some("ctx-a"),
            "issued in the surface's own context"
        );
        assert_eq!(
            recorder
                .last_sign_request
                .lock()
                .unwrap()
                .as_ref()
                .map(|r| r["keyId"].clone()),
            Some(json!("ctx-a-issuer")),
            "signed with the key that backs the surface's context"
        );
    }

    mod first_use {
        use super::*;
        use crate::identity::FilesystemIdentityStore;
        use std::collections::HashMap;

        const ROUNDS: usize = 20;

        struct Fixture {
            issuer: Arc<VCIssuer>,
            store_dir: tempfile::TempDir,
            _issuer_dir: tempfile::TempDir,
        }

        async fn fixture() -> Fixture {
            let store_dir = tempfile::tempdir().unwrap();
            let store = Arc::new(
                FilesystemIdentityStore::new(store_dir.path())
                    .await
                    .unwrap(),
            );
            let (issuer, issuer_dir) = crate::identity::test_helpers::test_vc_issuer_with(store).await;
            Fixture {
                issuer: Arc::new(issuer),
                store_dir,
                _issuer_dir: issuer_dir,
            }
        }

        fn api_key_fields(key_id: &str) -> HashMap<String, serde_json::Value> {
            HashMap::from([
                ("credential_type".to_string(), json!("api_key")),
                ("api_key_id".to_string(), json!(key_id)),
            ])
        }

        async fn issue(
            issuer: Arc<VCIssuer>,
            barrier: Arc<tokio::sync::Barrier>,
            key_id: String,
            origin: IdentityOrigin,
        ) -> Result<AgentIdentityResponse> {
            barrier.wait().await;
            let hash = Some(format!("hash-{key_id}"));
            let surface = Some("first-use".to_string());
            match origin {
                IdentityOrigin::Managed => {
                    issuer
                        .issue_or_get_managed_credential(
                            api_key_fields(&key_id),
                            hash,
                            surface,
                            None,
                            ManagedIdentitySource::protected(),
                        )
                        .await
                }
                IdentityOrigin::ExternalCaller => {
                    issuer
                        .issue_or_get_caller_credential(api_key_fields(&key_id), hash, surface, None)
                        .await
                }
            }
        }

        async fn records_for(
            issuer: &VCIssuer,
            key_id: &str,
        ) -> Vec<AgentIdentityRecord> {
            issuer
                .get_identity_store()
                .list_all()
                .await
                .unwrap()
                .into_iter()
                .filter(|record| record.identity_hash == format!("hash-{key_id}"))
                .collect()
        }

        fn birth_logs(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry.path().is_dir() && entry.file_name() != crate::identity::filesystem::ROTATION_HISTORY_DIR
                })
                .count()
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn a_managed_and_a_caller_first_use_share_one_did_and_role() {
            let f = fixture().await;
            for round in 0..ROUNDS {
                let key_id = format!("atgk_first_mixed_{round}");
                let barrier = Arc::new(tokio::sync::Barrier::new(2));
                let managed =
                    tokio::spawn(issue(f.issuer.clone(), barrier.clone(), key_id.clone(), IdentityOrigin::Managed));
                let caller =
                    tokio::spawn(issue(f.issuer.clone(), barrier, key_id.clone(), IdentityOrigin::ExternalCaller));
                let managed = managed
                    .await
                    .unwrap()
                    .unwrap();
                let caller = caller.await.unwrap().unwrap();

                assert_eq!(managed.did, caller.did, "round {round}");
                let records = records_for(&f.issuer, &key_id).await;
                assert_eq!(records.len(), 1, "round {round}");
                assert_eq!(records[0].did, managed.did, "round {round}");
                assert_ne!(managed.is_new, caller.is_new, "round {round}: exactly one request creates the record");
                let creator = if managed.is_new {
                    IdentityOrigin::Managed
                } else {
                    IdentityOrigin::ExternalCaller
                };
                assert_eq!(records[0].origin, Some(creator), "round {round}");
            }
            assert_eq!(birth_logs(f.store_dir.path()), ROUNDS, "a discarded DID leaves no birth log");
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn concurrent_caller_first_use_shares_one_did() {
            const CALLERS: usize = 6;
            let f = fixture().await;
            for round in 0..ROUNDS {
                let key_id = format!("atgk_first_callers_{round}");
                let barrier = Arc::new(tokio::sync::Barrier::new(CALLERS));
                let tasks: Vec<_> = (0..CALLERS)
                    .map(|_| {
                        tokio::spawn(issue(
                            f.issuer.clone(),
                            barrier.clone(),
                            key_id.clone(),
                            IdentityOrigin::ExternalCaller,
                        ))
                    })
                    .collect();
                let mut dids = Vec::new();
                for task in tasks {
                    dids.push(
                        task.await
                            .unwrap()
                            .unwrap()
                            .did,
                    );
                }

                let records = records_for(&f.issuer, &key_id).await;
                assert_eq!(records.len(), 1, "round {round}");
                assert!(
                    dids.iter()
                        .all(|did| did == &records[0].did),
                    "round {round}: {dids:?}"
                );
                assert_eq!(records[0].origin, Some(IdentityOrigin::ExternalCaller));
                assert_eq!(records[0].usage_count, CALLERS as u64, "round {round}");
            }
            assert_eq!(birth_logs(f.store_dir.path()), ROUNDS, "a discarded DID leaves no birth log");
        }
    }

    struct AgentIsTheDefault;

    impl crate::vta::key_directory::ApplianceSigningDefault for AgentIsTheDefault {
        fn signing(&self) -> Option<crate::config::agent_surface::SurfaceSigningConfig> {
            Some(crate::config::agent_surface::SurfaceSigningConfig {
                backend: Some(crate::config::agent_surface::SigningBackendKind::Vta),
                connection_id: Some("vta-a".to_string()),
                context_id: Some("ctx-a".to_string()),
                key_id: Some("gateway-jwt-1".to_string()),
            })
        }
    }

    /// The gateway-wide default naming a trust agent that cannot be reached
    /// leaves the attestation unsigned rather than claiming the gateway DID,
    /// which peers would pin while the credentials are refused.
    #[tokio::test]
    async fn the_attestation_is_refused_while_the_chosen_trust_agent_is_unusable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (issuer, _issuer_tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let local: Arc<dyn crate::identity::authority::CredentialAuthority> =
            Arc::new(crate::identity::authority::LocalCredentialAuthority::new(Arc::clone(&issuer)));
        let directory =
            crate::vta::key_directory::KeyDirectory::build(&crate::config::vta::VtaConfig::default(), local)
                .await
                .expect("a disabled [vta] block builds")
                .with_connections(agent_registry(tmp.path(), "http://127.0.0.1:1").await)
                .with_appliance_default(Arc::new(AgentIsTheDefault));
        issuer
            .set_key_directory(Arc::new(directory))
            .await;

        let err = issuer
            .attestation_issuer_did()
            .await
            .expect_err("an unreachable chosen agent is not replaced by the gateway DID");
        assert!(
            err.to_string()
                .contains("ctx-a"),
            "refused as the chosen context: {err}"
        );
    }

    /// With a trust agent connected in the dashboard and made the gateway-wide
    /// default, and no `[vta]` block, the fabric issuer attestation claims the
    /// agent context's DID — the DID that issues the credentials peers receive —
    /// and is signed by that context's key, so a peer that pins the attested
    /// issuer accepts those credentials.
    #[tokio::test]
    async fn the_attestation_claims_the_context_that_issues_the_appliances_credentials() {
        let (agent_url, agent) = spawn_agent().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let (issuer, _issuer_tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(issuer);
        let gateway_did = issuer
            .get_issuer_did()
            .await
            .expect("gateway did");
        let local: Arc<dyn crate::identity::authority::CredentialAuthority> =
            Arc::new(crate::identity::authority::LocalCredentialAuthority::new(Arc::clone(&issuer)));
        let directory = Arc::new(
            crate::vta::key_directory::KeyDirectory::build(&crate::config::vta::VtaConfig::default(), local)
                .await
                .expect("a disabled [vta] block builds")
                .with_connections(agent_registry(tmp.path(), &agent_url).await)
                .with_appliance_default(Arc::new(AgentIsTheDefault)),
        );
        assert_eq!(
            issuer
                .attestation_issuer_did()
                .await
                .unwrap(),
            gateway_did,
            "no directory, no agent"
        );
        issuer
            .set_key_directory(Arc::clone(&directory))
            .await;

        let attested = issuer
            .attestation_issuer_did()
            .await
            .expect("the attested issuer");
        assert_eq!(attested, agent.did(), "the attestation claims the issuing context, not the gateway DID");
        assert!(
            matches!(
                directory
                    .di_vc_issuer_for(&crate::vta::key_directory::KeyScope::default())
                    .await,
                crate::vta::key_directory::ScopedDiIssuer::Agent(_)
            ),
            "the same context issues the appliance's credentials"
        );

        let jws = issuer
            .sign_attestation_typ(&json!({ "iss": attested }), "issuer-attestation+jwt")
            .await
            .expect("signed as the context");
        let header: serde_json::Value = serde_json::from_slice(
            &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, jws.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(header["kid"], json!(agent.verification_method()), "signed by the key the attested DID declares");
    }
}
