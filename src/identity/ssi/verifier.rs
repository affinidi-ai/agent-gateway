use std::collections::HashMap;
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use anyhow::{Context as AnyhowContext, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use did_peer::resolve_did_peer;
use serde_json::Value;
use ssi::claims::data_integrity::AnyDataIntegrity;
use ssi::claims::vc::v2::syntax::{JsonCredential, JsonPresentation};
use ssi::claims::{ProofValidationError, Verification, VerificationParameters};
use ssi::dids::document::{self, representation::MediaType};
use ssi::dids::resolution::{self, Options};
use ssi::dids::{AnyDidMethod, DID, DIDResolver, DIDURL, VerificationMethodDIDResolver};
use ssi::verification_methods::AnyMethod;

use super::context::create_signature_environment;
use super::vp_issuer::VP_LIFETIME_MINUTES;

/// The one cryptosuite `ssi` cannot parse, and the one the Verifiable Trust
/// Agent produces. Its presence on a proof is what routes that proof to
/// `affinidi-data-integrity` instead.
const JCS_CRYPTOSUITE: &str = "eddsa-jcs-2022";

#[allow(dead_code)]
pub struct VcVerificationResult {
    pub issuer_did: String,
    pub subject_did: String,
    pub identity_fields: HashMap<String, Value>,
}

pub struct VpVerificationResult {
    pub holder_did: String,
    pub credentials: Vec<VcVerificationResult>,
    /// Raw `verifiableCredential` entries from the verified VP, preserved so
    /// downstream gateways can flatten this hop's VCs into a chained-provenance
    /// VP they re-issue. Order matches the inbound VP.
    pub raw_credentials: Vec<Value>,
    #[allow(unused)]
    pub domain: Option<String>,
    pub challenge: Option<String>,
}

#[async_trait]
pub trait Verifier: Send + Sync {
    async fn verify_vp(
        &self,
        presentation: &Value,
    ) -> Result<VpVerificationResult>;
}

pub struct LocalVerifier {
    did_cache: Arc<DIDCacheClient>,
}

impl LocalVerifier {
    pub fn new(did_cache: Arc<DIDCacheClient>) -> Self {
        Self { did_cache }
    }
}

pub struct CompositeResolver {
    ssi_resolver: AnyDidMethod,
    did_cache: Arc<DIDCacheClient>,
}

impl CompositeResolver {
    pub fn new(did_cache: Arc<DIDCacheClient>) -> Self {
        Self {
            ssi_resolver: AnyDidMethod::default(),
            did_cache,
        }
    }

    async fn resolve_peer_did(
        &self,
        did_str: &str,
    ) -> Result<Vec<u8>, resolution::Error> {
        let doc_json = resolve_did_peer(did_str)
            .await
            .map_err(|e| resolution::Error::Internal(format!("Failed to resolve did:peer: {:?}", e)))?;

        let mut doc: serde_json::Value = serde_json::from_str(&doc_json)
            .map_err(|e| resolution::Error::Internal(format!("Failed to parse did:peer document: {}", e)))?;
        // ssi lib expects did/v1
        doc["@context"] = serde_json::json!(["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]);

        serde_json::to_vec(&doc).map_err(|e| resolution::Error::Internal(e.to_string()))
    }
}

impl DIDResolver for CompositeResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        let method = did.method_name();

        match method {
            "peer" => {
                let doc_bytes = self
                    .resolve_peer_did(did.as_str())
                    .await?;
                Ok(resolution::Output::new(
                    doc_bytes,
                    document::Metadata::default(),
                    resolution::Metadata::from_content_type(Some(MediaType::JsonLd.to_string())),
                ))
            }
            "key" | "jwk" | "pkh" | "ethr" | "ion" | "tz" => {
                self.ssi_resolver
                    .resolve_representation(did, options)
                    .await
            }
            _ => {
                let resolve_result = self
                    .did_cache
                    .resolve(did.as_str())
                    .await
                    .map_err(|e| resolution::Error::Internal(e.to_string()))?;

                let doc_bytes =
                    serde_json::to_vec(&resolve_result.doc).map_err(|e| resolution::Error::Internal(e.to_string()))?;

                Ok(resolution::Output::new(
                    doc_bytes,
                    document::Metadata::default(),
                    resolution::Metadata::from_content_type(Some(MediaType::JsonLd.to_string())),
                ))
            }
        }
    }
}

fn verify_vc_lifetime(vc: &Value) -> Result<()> {
    let now = Utc::now();

    if let Some(valid_from) = vc
        .get("validFrom")
        .and_then(|v| v.as_str())
    {
        let valid_from_dt: DateTime<Utc> = valid_from
            .parse()
            .context("Invalid validFrom date format")?;
        if now < valid_from_dt {
            anyhow::bail!("VC is not yet valid (validFrom: {})", valid_from);
        }
    }

    if let Some(valid_until) = vc
        .get("validUntil")
        .and_then(|v| v.as_str())
    {
        let valid_until_dt: DateTime<Utc> = valid_until
            .parse()
            .context("Invalid validUntil date format")?;
        if now > valid_until_dt {
            anyhow::bail!("VC has expired (validUntil: {})", valid_until);
        }
    }

    if let Some(expiration_date) = vc
        .get("expirationDate")
        .and_then(|v| v.as_str())
    {
        let expiration_dt: DateTime<Utc> = expiration_date
            .parse()
            .context("Invalid expirationDate format")?;
        if now > expiration_dt {
            anyhow::bail!("VC has expired (expirationDate: {})", expiration_date);
        }
    }

    if let Some(issuance_date) = vc
        .get("issuanceDate")
        .and_then(|v| v.as_str())
    {
        let issuance_dt: DateTime<Utc> = issuance_date
            .parse()
            .context("Invalid issuanceDate format")?;
        if now < issuance_dt {
            anyhow::bail!("VC is not yet valid (issuanceDate: {})", issuance_date);
        }
    }

    Ok(())
}

fn verify_vp_proof_lifetime(proof: &Value) -> Result<()> {
    let now = Utc::now();

    if let Some(expires) = proof
        .get("expires")
        .and_then(|v| v.as_str())
    {
        let expires_dt: DateTime<Utc> = expires
            .parse()
            .context("Invalid proof expires date format")?;
        if now > expires_dt {
            anyhow::bail!("VP proof has expired (expires: {})", expires);
        }
        return Ok(());
    }

    // Proofs without expires are bounded by their signed created timestamp instead.
    let created = proof
        .get("created")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("VP proof has neither expires nor created"))?;
    let created_dt: DateTime<Utc> = created
        .parse()
        .context("Invalid proof created date format")?;
    if now > created_dt + Duration::minutes(VP_LIFETIME_MINUTES) {
        anyhow::bail!("VP proof has expired (created: {}, no expires)", created);
    }

    Ok(())
}

fn check_revocation_status(vc: &Value) -> Result<()> {
    if let Some(status) = vc.get("credentialStatus") {
        let status_type = status
            .get("type")
            .and_then(|t| t.as_str());

        match status_type {
            Some("BitstringStatusListEntry") | Some("StatusList2021Entry") => {
                // TODO: Implement actual revocation check against status list
                // For now, we note that a status exists but don't fail
                tracing::warn!(
                    "VC has credentialStatus of type {:?}, revocation check not yet implemented",
                    status_type
                );
            }
            Some(other) => {
                tracing::warn!("Unknown credentialStatus type: {}", other);
            }
            None => {}
        }
    }
    Ok(())
}

/// The proofs on a document, as raw JSON.
///
/// `proof` may be a single object or an array; both are normalised here so
/// every caller sees the same shape. An absent or empty `proof` is an error:
/// an unsigned document must never reach a verification decision.
fn proofs_of(
    document: &Value,
    what: &str,
) -> Result<Vec<Value>> {
    let proofs = match document.get("proof") {
        Some(Value::Array(items)) => items.clone(),
        Some(Value::Object(_)) => vec![document["proof"].clone()],
        Some(_) => anyhow::bail!("{} proof must be an object or an array", what),
        None => anyhow::bail!("{} has no proof", what),
    };
    if proofs.is_empty() {
        anyhow::bail!("{} has no proof", what);
    }
    Ok(proofs)
}

/// The DID that controls a proof, taken from its `verificationMethod`.
fn proof_controller(proof: &Value) -> Result<String> {
    let vm = proof
        .get("verificationMethod")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("proof has no verificationMethod"))?;
    let did = DIDURL::new(vm.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid proof verificationMethod {}", vm))?
        .did()
        .to_string();
    Ok(did)
}

/// `document` with its `proof` member removed.
///
/// Both cryptosuites hash the document *without* its proof, so this is what
/// either verifier must be handed.
fn without_proof(document: &Value) -> Value {
    let mut unsigned = document.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("proof");
    }
    unsigned
}

/// Check every proof on `document` against `expected_controller`, and verify
/// any `eddsa-jcs-2022` proofs. Returns whether the document carried one.
///
/// This is the **only** place the binding decision is made, for every
/// cryptosuite. That the proof's `verificationMethod` must be a method of the
/// DID the document claims is the gateway's own invariant — `ssi` does not
/// enforce it — so keeping it here, on raw JSON, means it holds identically
/// whichever library checks the signature.
///
/// Signature checking is the only thing that dispatches by suite:
/// - `eddsa-jcs-2022` → `affinidi-data-integrity`, here, because `ssi`
///   implements no JCS cryptosuite at any released version.
/// - everything else → `ssi` at the call site, which owns `eddsa-rdfc-2022` and
///   the legacy suites and whose JSON-LD loader carries this gateway's own
///   contexts.
///
/// Returning `true` tells the caller to **skip** the `ssi` pass: `ssi` cannot
/// parse the JCS suite and would reject the document for the wrong reason. The
/// signature has already been checked here, and the bindings for every proof
/// on the document were checked above regardless.
async fn check_bindings_and_jcs_proofs(
    document: &Value,
    expected_controller: &str,
    role: &str,
    what: &str,
    did_cache: &Arc<DIDCacheClient>,
) -> Result<bool> {
    let proofs = proofs_of(document, what)?;
    let unsigned = without_proof(document);
    let mut any_jcs = false;

    for proof in &proofs {
        let controller = proof_controller(proof).with_context(|| format!("{} proof binding failed", what))?;
        if controller != expected_controller {
            anyhow::bail!(
                "{}: proof verificationMethod {} does not belong to {} {}",
                what,
                proof
                    .get("verificationMethod")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<none>"),
                role,
                expected_controller
            );
        }

        if proof
            .get("cryptosuite")
            .and_then(|c| c.as_str())
            == Some(JCS_CRYPTOSUITE)
        {
            any_jcs = true;
            super::di_jcs::verify_jcs_proof(&unsigned, proof, did_cache.clone())
                .await
                .with_context(|| format!("{} verification failed", what))?;
        }
    }

    Ok(any_jcs)
}

fn ensure_verified(
    outcome: Result<Verification, ProofValidationError>,
    what: &str,
) -> Result<()> {
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(invalid)) => anyhow::bail!("{} proof verification failed: {}", what, invalid),
        Err(e) => Err(e).with_context(|| format!("{} verification failed", what)),
    }
}

fn verify_vc_fields(
    vc: &Value,
    holder_did: &str,
) -> Result<VcVerificationResult> {
    verify_vc_lifetime(vc)?;
    check_revocation_status(vc)?;

    let subject_did = vc
        .get("credentialSubject")
        .and_then(|cs| cs.get("id"))
        .and_then(|id| id.as_str())
        .ok_or_else(|| anyhow::anyhow!("VC missing credentialSubject.id"))?
        .to_string();

    if subject_did != holder_did {
        anyhow::bail!("VP holder ({:?}) does not match VC subject ({:?})", holder_did, subject_did);
    }

    let issuer_did = vc
        .get("issuer")
        .and_then(|i| i.as_str())
        .ok_or_else(|| anyhow::anyhow!("VC missing issuer field"))?
        .to_string();

    let mut identity_fields = vc
        .get("credentialSubject")
        .and_then(|cs| cs.get("identityFields"))
        .and_then(|fields| fields.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<HashMap<String, Value>>()
        })
        .unwrap_or_default();

    // Carry the Workload Binding object through so the identity-binding consumer
    // (`IdentityBindingContext::from_verified_parts`) can parse the nested
    // caller / delegated / target / agentIdentity shape. The Workload Binding
    // feature stores it under `credentialSubject.workloadBinding` (not the flat
    // `identityFields`), so without this the binding degrades to a flat identity
    // with `caller` absent.
    if let Some(workload_binding) = vc
        .get("credentialSubject")
        .and_then(|cs| cs.get("workloadBinding"))
    {
        identity_fields.insert("workloadBinding".to_string(), workload_binding.clone());
    }

    Ok(VcVerificationResult {
        issuer_did,
        subject_did,
        identity_fields,
    })
}

#[async_trait]
impl Verifier for LocalVerifier {
    async fn verify_vp(
        &self,
        presentation: &Value,
    ) -> Result<VpVerificationResult> {
        let holder_did = presentation
            .get("holder")
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow::anyhow!("VP missing holder field"))?
            .to_string();

        let vc_field = presentation
            .get("verifiableCredential")
            .ok_or_else(|| anyhow::anyhow!("VP missing verifiableCredential field"))?;

        let vcs: Vec<&Value> = if let Some(arr) = vc_field.as_array() {
            if arr.is_empty() {
                anyhow::bail!("VP has no credentials");
            }
            arr.iter().collect()
        } else if vc_field.is_object() {
            vec![vc_field]
        } else {
            anyhow::bail!("VP verifiableCredential must be an object or array");
        };

        // Reject a stale presentation before doing any signature work: the
        // proof's own `expires`, falling back to its signed `created` time.
        let proof = presentation
            .get("proof")
            .ok_or_else(|| anyhow::anyhow!("VP missing proof field"))?;
        verify_vp_proof_lifetime(proof)?;

        let resolver = CompositeResolver::new(self.did_cache.clone());
        let vm_resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(resolver);

        let env = create_signature_environment(None).await?;
        let params = VerificationParameters::from_resolver(vm_resolver).with_json_ld_loader(env.json_ld_loader);

        // The VP's bindings are checked on raw JSON, and a JCS holder proof is
        // verified there too. Only when it carries none is the `ssi` pass run —
        // and the typed parse that pass needs is deferred until then, because
        // `ssi` cannot deserialize a JCS proof and would fail on the shape
        // rather than on the signature.
        let vp_has_jcs =
            check_bindings_and_jcs_proofs(presentation, &holder_did, "holder", "VP", &self.did_cache).await?;

        if !vp_has_jcs {
            // Credentials are parsed as raw values, not as `AnyDataIntegrity`.
            // During the migration a presentation legitimately mixes suites —
            // VTA-signed JCS credentials inside a gateway-signed RDFC
            // presentation — and typing them here would reject the whole VP
            // because of one credential `ssi` has no suite for.
            let vp: AnyDataIntegrity<JsonPresentation<Value>> = serde_json::from_value(presentation.clone())
                .context("Failed to parse VP as Data Integrity presentation")?;
            anyhow::ensure!(
                vp.claims
                    .verifiable_credentials
                    .len()
                    == vcs.len(),
                "VP credential count mismatch: {} parsed vs {} raw",
                vp.claims
                    .verifiable_credentials
                    .len(),
                vcs.len()
            );
            ensure_verified(vp.verify(&params).await, "VP")?;
        }

        let mut credentials = Vec::with_capacity(vcs.len());
        for (i, vc_json) in vcs.iter().enumerate() {
            let what = format!("VC[{}]", i);
            let vc_result =
                verify_vc_fields(vc_json, &holder_did).with_context(|| format!("{} validation failed", what))?;

            let vc_has_jcs =
                check_bindings_and_jcs_proofs(vc_json, &vc_result.issuer_did, "issuer", &what, &self.did_cache).await?;

            if !vc_has_jcs {
                let vc: AnyDataIntegrity<JsonCredential> = serde_json::from_value((*vc_json).clone())
                    .with_context(|| format!("{} is not a Data Integrity credential", what))?;
                ensure_verified(vc.verify(&params).await, &what)?;
            }

            credentials.push(vc_result);
        }

        let domain = proof
            .get("domain")
            .and_then(|d| d.as_str())
            .map(String::from);
        let challenge = proof
            .get("challenge")
            .and_then(|c| c.as_str())
            .map(String::from);

        Ok(VpVerificationResult {
            holder_did,
            credentials,
            raw_credentials: vcs
                .iter()
                .map(|v| (*v).clone())
                .collect(),
            domain,
            challenge,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;

    use serde_json::{Value, json};
    use ssi::jwk::JWK;
    use tokio::sync::RwLock;

    use super::*;
    use crate::identity::VCIssuerConfig;
    use crate::identity::ssi::did_utils::create_signing_did_peer;
    use crate::identity::ssi::did_utils::jwk_to_multibase_ed25519;
    use crate::identity::ssi::vc_issuer::{
        AgentIdentity, IssueVcPayload, LocalVcIssuer, LocalVcSigner, VcIssuer, VcSigner,
    };
    use crate::identity::ssi::vp_issuer::{
        Credentials, LocalVpIssuer, LocalVpSigner, VpIssuer, VpIssuerPayload, VpSigner,
    };
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    struct Fixture {
        issuer_did: String,
        holder_key: JWK,
        holder_did: String,
        verifier: LocalVerifier,
        issuer_config: Arc<RwLock<VCIssuerConfig>>,
    }

    fn signer_config(
        did: &str,
        key: &JWK,
    ) -> Arc<RwLock<VCIssuerConfig>> {
        Arc::new(RwLock::new(VCIssuerConfig {
            storage_path: Default::default(),
            proxy_did: did.to_string(),
            signing_key: key.clone(),
            is_vp_challenge_required: false,
        }))
    }

    async fn fixture() -> Fixture {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .expect("init_shared_resolver failed");
        let issuer_key = JWK::generate_ed25519().unwrap();
        let issuer_did = create_signing_did_peer(&issuer_key).unwrap();
        let holder_key = JWK::generate_ed25519().unwrap();
        let holder_did = create_signing_did_peer(&holder_key).unwrap();
        Fixture {
            issuer_config: signer_config(&issuer_did, &issuer_key),
            issuer_did,
            holder_key,
            holder_did,
            verifier: LocalVerifier::new(crate::gateways::did_cache::shared_resolver().clone()),
        }
    }

    async fn issue_vc(
        f: &Fixture,
        subject_did: &str,
    ) -> Value {
        let signer = Arc::new(LocalVcSigner::new(f.issuer_config.clone()));
        let mut identity_fields = HashMap::new();
        identity_fields.insert("region".to_string(), json!("eu"));
        LocalVcIssuer::new(f.issuer_config.clone(), signer)
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: Cow::Borrowed(subject_did),
                identity_fields: Cow::Owned(identity_fields),
                workload_binding: None,
                display_name: None,
            }))
            .await
            .expect("VC issuance should succeed")
    }

    async fn present(
        holder_key: &JWK,
        holder_did: &str,
        vcs: Vec<Value>,
    ) -> Value {
        LocalVpIssuer::new(Arc::new(LocalVpSigner::new()))
            .issue(VpIssuerPayload::Credentials(Credentials {
                holder_key: Some(Cow::Borrowed(holder_key)),
                holder_did: Cow::Borrowed(holder_did),
                verifiable_credentials: Cow::Owned(vcs),
                challenge: None,
                domain: None,
            }))
            .await
            .expect("VP issuance should succeed")
    }

    async fn verify(
        f: &Fixture,
        vp: &Value,
    ) -> Result<VpVerificationResult, String> {
        f.verifier
            .verify_vp(vp)
            .await
            .map_err(|e| format!("{:#}", e))
    }

    #[tokio::test]
    async fn verifies_vp_over_vc_with_display_name() {
        let f = fixture().await;
        let signer = Arc::new(LocalVcSigner::new(f.issuer_config.clone()));
        let vc = LocalVcIssuer::new(f.issuer_config.clone(), signer)
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: Cow::Borrowed(&f.holder_did),
                identity_fields: Cow::Owned(HashMap::new()),
                workload_binding: None,
                display_name: Some(Cow::Borrowed("OXYGEN")),
            }))
            .await
            .expect("VC issuance with a display name should succeed");
        assert_eq!(vc["credentialSubject"]["name"], json!("OXYGEN"));
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let result = verify(&f, &vp)
            .await
            .expect("VP over a named VC verifies");

        assert_eq!(result.credentials.len(), 1);
        assert_eq!(result.credentials[0].subject_did, f.holder_did);
        assert_eq!(result.raw_credentials[0]["credentialSubject"]["name"], json!("OXYGEN"));
    }

    #[tokio::test]
    async fn rejects_vc_whose_display_name_was_altered_after_signing() {
        let f = fixture().await;
        let signer = Arc::new(LocalVcSigner::new(f.issuer_config.clone()));
        let mut vc = LocalVcIssuer::new(f.issuer_config.clone(), signer)
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: Cow::Borrowed(&f.holder_did),
                identity_fields: Cow::Owned(HashMap::new()),
                workload_binding: None,
                display_name: Some(Cow::Borrowed("OXYGEN")),
            }))
            .await
            .unwrap();
        vc["credentialSubject"]["name"] = json!("HELIUM");
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        assert!(verify(&f, &vp).await.is_err(), "a tampered display name must fail verification");
    }

    #[tokio::test]
    async fn verifies_vp_signed_by_holder_over_issuer_signed_vc() {
        let f = fixture().await;
        let vc = issue_vc(&f, &f.holder_did).await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let result = verify(&f, &vp)
            .await
            .expect("holder-signed VP over issuer-signed VC verifies");

        assert_eq!(result.holder_did, f.holder_did);
        assert_eq!(result.credentials.len(), 1);
        assert_eq!(result.credentials[0].issuer_did, f.issuer_did);
        assert_eq!(result.credentials[0].subject_did, f.holder_did);
        assert_eq!(result.credentials[0].identity_fields["region"], json!("eu"));
        assert_eq!(result.raw_credentials.len(), 1);
        assert!(result.challenge.is_none());
    }

    #[tokio::test]
    async fn rejects_vc_subject_other_than_holder() {
        let f = fixture().await;
        let vc = issue_vc(&f, &f.issuer_did).await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("VC subject must equal the VP holder");

        assert!(err.contains("does not match VC subject"), "{err}");
    }

    #[tokio::test]
    async fn rejects_vc_without_proof() {
        let f = fixture().await;
        let mut vc = issue_vc(&f, &f.holder_did).await;
        vc.as_object_mut()
            .unwrap()
            .remove("proof");
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a VC without a proof must be rejected");

        assert!(err.contains("VC[0]") && err.contains("has no proof"), "{err}");
    }

    #[tokio::test]
    async fn rejects_vc_mutated_after_issuance() {
        let f = fixture().await;
        let mut vc = issue_vc(&f, &f.holder_did).await;
        vc["credentialSubject"]["identityFields"]["region"] = json!("evil");
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a VC changed after the issuer signed it must be rejected");

        assert!(err.contains("VC[0]") && err.contains("proof verification failed"), "{err}");
    }

    #[tokio::test]
    async fn rejects_vc_whose_proof_key_is_not_the_issuer() {
        let f = fixture().await;
        let mut vc = issue_vc(&f, &f.holder_did).await;
        vc.as_object_mut()
            .unwrap()
            .remove("proof");
        assert_eq!(vc["issuer"], json!(f.issuer_did));
        let forged = LocalVcSigner::new(signer_config(&f.holder_did, &f.holder_key))
            .sign(vc)
            .await
            .expect("holder can sign a credential with its own key");
        let vp = present(&f.holder_key, &f.holder_did, vec![forged]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a VC signed by a key the issuer does not control must be rejected");

        assert!(err.contains("does not belong to issuer"), "{err}");
    }

    #[tokio::test]
    async fn rejects_vp_signed_by_key_of_another_did() {
        let f = fixture().await;
        let attacker_key = JWK::generate_ed25519().unwrap();
        let attacker_did = create_signing_did_peer(&attacker_key).unwrap();
        let vc = issue_vc(&f, &f.holder_did).await;
        let unsigned_vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": f.holder_did,
            "verifiableCredential": [vc],
            "id": "urn:uuid:5d5d5d5d-0000-4000-8000-000000000001",
        });
        let vp = LocalVpSigner::new()
            .sign(unsigned_vp, &attacker_key, &attacker_did, None, None)
            .await
            .expect("attacker can sign a presentation with its own key");

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a VP whose proof key is not the holder's must be rejected");

        assert!(err.contains("does not belong to holder"), "{err}");
    }

    fn two_key_peer_did(key: &JWK) -> String {
        let public_key = jwk_to_multibase_ed25519(key).unwrap();
        let keys = (0..2)
            .map(|_| did_peer::DIDPeerCreateKeys {
                purpose: did_peer::DIDPeerKeys::Verification,
                type_: None,
                public_key_multibase: Some(public_key.clone()),
            })
            .collect::<Vec<_>>();
        did_peer::DIDPeer::create_peer_did(&keys, None)
            .unwrap()
            .0
    }

    async fn mint_vp() -> (Value, String) {
        let signing_key = JWK::generate_ed25519().unwrap();
        let issuer_did = two_key_peer_did(&signing_key);
        let holder_key = JWK::generate_ed25519().unwrap();
        let holder_did = two_key_peer_did(&holder_key);
        let config = Arc::new(RwLock::new(VCIssuerConfig {
            storage_path: Default::default(),
            proxy_did: issuer_did,
            signing_key,
            is_vp_challenge_required: false,
        }));
        let vc = LocalVcIssuer::new(config.clone(), Arc::new(LocalVcSigner::new(config)))
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: Cow::Borrowed(&holder_did),
                identity_fields: Cow::Owned(HashMap::new()),
                workload_binding: None,
                display_name: None,
            }))
            .await
            .unwrap();
        let vp = LocalVpIssuer::new(Arc::new(LocalVpSigner::new()))
            .issue(VpIssuerPayload::Credentials(Credentials {
                holder_key: Some(Cow::Owned(holder_key)),
                holder_did: Cow::Borrowed(&holder_did),
                verifiable_credentials: Cow::Owned(vec![vc]),
                challenge: None,
                domain: None,
            }))
            .await
            .unwrap();
        (vp, holder_did)
    }

    async fn did_web_resolution_error(
        host_policy: affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy
    ) -> String {
        let client = DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_host_policy(host_policy)
                .build(),
        )
        .await
        .expect("Failed to create DID cache client");
        let resolver = CompositeResolver::new(Arc::new(client));
        match resolver
            .resolve_representation(DID::new("did:web:localhost%3A1").unwrap(), Options::default())
            .await
        {
            Ok(_) => panic!("resolving an unreachable did:web must fail"),
            Err(error) => error.to_string(),
        }
    }

    #[tokio::test]
    async fn did_web_on_a_private_host_is_refused_under_the_default_policy() {
        let error =
            did_web_resolution_error(affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy::PublicOnly).await;
        assert!(error.contains("SSRF-prone host"), "expected a blocked-host refusal, got: {error}");
    }

    #[tokio::test]
    async fn did_web_on_a_private_host_is_fetched_when_private_hosts_are_allowed() {
        let error =
            did_web_resolution_error(affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy::AllowPrivate)
                .await;
        assert!(!error.contains("SSRF-prone host"), "AllowPrivate must not refuse localhost, got: {error}");
    }

    async fn local_verifier() -> LocalVerifier {
        let config = DIDCacheConfigBuilder::default()
            .with_cache_capacity(100)
            .with_cache_ttl(300)
            .build();
        let client = DIDCacheClient::new(config)
            .await
            .expect("Failed to create DID cache client");
        LocalVerifier::new(Arc::new(client))
    }

    #[test]
    fn proof_lifetime_rejects_past_expires() {
        let err = verify_vp_proof_lifetime(&json!({
            "created": "2000-01-01T00:00:00Z",
            "expires": "2000-01-01T00:05:00Z"
        }))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("expired"),
            "{err}"
        );
    }

    #[test]
    fn proof_lifetime_accepts_future_expires() {
        verify_vp_proof_lifetime(&json!({
            "created": "2000-01-01T00:00:00Z",
            "expires": "2999-01-01T00:00:00Z"
        }))
        .unwrap();
    }

    #[test]
    fn proof_lifetime_rejects_malformed_expires() {
        assert!(verify_vp_proof_lifetime(&json!({ "expires": "not-a-date" })).is_err());
    }

    #[test]
    fn proof_lifetime_without_expires_is_bounded_by_created() {
        let fresh = (Utc::now() - Duration::minutes(1)).to_rfc3339();
        verify_vp_proof_lifetime(&json!({ "created": fresh })).unwrap();

        let stale = (Utc::now() - Duration::minutes(VP_LIFETIME_MINUTES + 1)).to_rfc3339();
        let err = verify_vp_proof_lifetime(&json!({ "created": stale })).unwrap_err();
        assert!(
            err.to_string()
                .contains("expired"),
            "{err}"
        );
    }

    #[test]
    fn proof_lifetime_rejects_proof_without_timestamps() {
        assert!(verify_vp_proof_lifetime(&json!({ "type": "DataIntegrityProof" })).is_err());
    }

    #[tokio::test]
    async fn verify_vp_accepts_fresh_presentation_within_lifetime() {
        let (vp, holder_did) = mint_vp().await;

        let result = local_verifier()
            .await
            .verify_vp(&vp)
            .await
            .expect("fresh VP must verify");

        assert_eq!(result.holder_did, holder_did);
        assert_eq!(result.credentials.len(), 1);
        let expires: DateTime<Utc> = vp["proof"]["expires"]
            .as_str()
            .expect("minted VP proof must carry expires")
            .parse()
            .unwrap();
        assert!(expires > Utc::now());
        assert!(expires <= Utc::now() + Duration::minutes(VP_LIFETIME_MINUTES));
    }

    #[tokio::test]
    async fn verify_vp_rejects_expired_proof() {
        let (mut vp, _) = mint_vp().await;
        vp["proof"]["expires"] = json!("2000-01-01T00:00:00Z");

        let err = local_verifier()
            .await
            .verify_vp(&vp)
            .await
            .err()
            .expect("expired VP proof must be rejected");
        assert!(format!("{err:#}").contains("VP proof has expired"), "{err:#}");
    }

    #[tokio::test]
    async fn verify_vp_rejects_tampered_issuer() {
        let (mut vp, _) = mint_vp().await;
        let vc = if vp["verifiableCredential"].is_array() {
            &mut vp["verifiableCredential"][0]
        } else {
            &mut vp["verifiableCredential"]
        };
        vc["issuer"] = json!("did:web:did.dev.example.io:fake-issuer");

        assert!(
            local_verifier()
                .await
                .verify_vp(&vp)
                .await
                .is_err()
        );
    }

    // ─── `eddsa-jcs-2022` (the suite the Verifiable Trust Agent produces) ───
    //
    // `ssi` implements no JCS cryptosuite, so these credentials are signed with
    // `affinidi-data-integrity` — the same crate the VTA signs with — and must
    // be verified through the dispatch in `check_bindings_and_jcs_proofs`.

    /// Sign `credential` with an `eddsa-jcs-2022` proof as `did:key` holder of
    /// `key`, the way the VTA's context-scoped issue task does.
    async fn sign_jcs(
        mut credential: Value,
        key: &ed25519_dalek::SigningKey,
        issuer_did: &str,
        verification_method: &str,
        proof_purpose: &str,
    ) -> Value {
        use affinidi_data_integrity::crypto_suites::CryptoSuite;
        use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
        use affinidi_secrets_resolver::secrets::Secret;

        credential
            .as_object_mut()
            .expect("credential is an object")
            .insert("issuer".into(), json!(issuer_did));

        let mut private = vec![0x80, 0x26];
        private.extend_from_slice(&key.to_bytes());
        let mut secret = Secret::from_multibase(&multibase::encode(multibase::Base::Base58Btc, &private), None)
            .expect("secret from multibase");
        secret.id = verification_method.to_string();

        let proof = DataIntegrityProof::sign(
            &credential,
            &secret,
            SignOptions::new()
                .with_proof_purpose(proof_purpose)
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .expect("JCS signing should succeed");

        credential
            .as_object_mut()
            .unwrap()
            .insert("proof".into(), serde_json::to_value(&proof).expect("proof serialises"));
        credential
    }

    /// A `did:key` identity: the signing key, the DID, and its verification
    /// method — which for `did:key` is `<did>#<multibase>`.
    fn did_key_identity() -> (ed25519_dalek::SigningKey, String, String) {
        // Seeded from UUIDs rather than an RNG: two `rand` majors are in the
        // tree and `ed25519-dalek` accepts only one of them. Test keys need to
        // differ between calls, not to be cryptographically sourced.
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(key.verifying_key().as_bytes());
        let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
        let did = format!("did:key:{multibase}");
        let vm = format!("{did}#{multibase}");
        (key, did, vm)
    }

    fn unsigned_agent_vc(
        subject_did: &str,
        issuer_did: &str,
    ) -> Value {
        json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                crate::identity::ssi::context::CTX_AGENT_IDENTITY_V1_URL,
            ],
            "type": ["VerifiableCredential", "AgentIdentityCredential"],
            "issuer": issuer_did,
            "validFrom": chrono::Utc::now().to_rfc3339(),
            "validUntil": (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
            "credentialSubject": { "id": subject_did, "identityFields": { "region": "eu" } },
            "id": "urn:uuid:1c5d0000-0000-4000-8000-00000000f00d",
        })
    }

    /// The shape VTA-11b produces: a VTA-signed `eddsa-jcs-2022` credential
    /// inside a gateway-signed `eddsa-rdfc-2022` presentation. Both suites must
    /// verify in one pass.
    #[tokio::test]
    async fn verifies_a_jcs_credential_inside_an_rdfc_presentation() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();

        let vc = sign_jcs(
            unsigned_agent_vc(&f.holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let result = verify(&f, &vp)
            .await
            .expect("a JCS credential in an RDFC presentation must verify");

        assert_eq!(result.credentials.len(), 1);
        assert_eq!(result.credentials[0].issuer_did, issuer_did);
        assert_eq!(result.credentials[0].subject_did, f.holder_did);
        assert_eq!(result.credentials[0].identity_fields["region"], json!("eu"));
    }

    /// The custom `AgentIdentityCredential` context is exactly what
    /// `affinidi-data-integrity`'s RDFC path cannot expand. JCS does no
    /// expansion, so it must verify regardless — this pins that.
    #[tokio::test]
    async fn a_jcs_credential_verifies_despite_the_custom_jsonld_context() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let vc = unsigned_agent_vc(&f.holder_did, &issuer_did);
        assert_eq!(
            vc["@context"][1],
            json!(crate::identity::ssi::context::CTX_AGENT_IDENTITY_V1_URL),
            "this test is meaningless unless the custom context is present"
        );

        let vc = sign_jcs(vc, &issuer_key, &issuer_did, &issuer_vm, "assertionMethod").await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        verify(&f, &vp)
            .await
            .expect("JCS needs no JSON-LD expansion, so the custom context is irrelevant");
    }

    /// The gateway's own invariant — a proof key must belong to the issuer —
    /// is enforced for JCS exactly as it is for RDFC. This is the check that
    /// must never differ between the two paths.
    #[tokio::test]
    async fn rejects_a_jcs_credential_whose_proof_key_is_not_the_issuer() {
        let f = fixture().await;
        let (attacker_key, _attacker_did, attacker_vm) = did_key_identity();
        let (_, claimed_issuer, _) = did_key_identity();

        // Signed by the attacker's key, but claiming someone else as issuer.
        let vc = sign_jcs(
            unsigned_agent_vc(&f.holder_did, &claimed_issuer),
            &attacker_key,
            &claimed_issuer,
            &attacker_vm,
            "assertionMethod",
        )
        .await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a JCS proof key that is not the issuer's must be rejected");
        assert!(err.contains("does not belong to issuer"), "{err}");
    }

    /// A tampered JCS credential must fail the signature check, not slip
    /// through because the binding check passed.
    #[tokio::test]
    async fn rejects_a_jcs_credential_mutated_after_issuance() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let mut vc = sign_jcs(
            unsigned_agent_vc(&f.holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;

        vc["credentialSubject"]["identityFields"]["region"] = json!("us");
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a mutated JCS credential must fail verification");
        assert!(err.contains("verification failed") || err.contains("InvalidSignature"), "{err}");
    }

    /// A JCS presentation is the VTA-12 shape — the holder proof moves to the
    /// VTA too. The dispatch must handle it at the VP level, not just for
    /// embedded credentials.
    #[tokio::test]
    async fn verifies_a_jcs_presentation() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let (holder_key, holder_did, holder_vm) = did_key_identity();

        let vc = sign_jcs(
            unsigned_agent_vc(&holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;

        let unsigned_vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [vc],
            "id": "urn:uuid:7a7a0000-0000-4000-8000-000000000002",
        });
        let vp = sign_jcs(unsigned_vp, &holder_key, &holder_did, &holder_vm, "authentication").await;

        let result = verify(&f, &vp)
            .await
            .expect("an all-JCS presentation must verify");
        assert_eq!(result.holder_did, holder_did);
        assert_eq!(result.credentials[0].issuer_did, issuer_did);
    }

    /// An unsigned document must never reach a verification decision, whichever
    /// suite is in play.
    #[tokio::test]
    async fn rejects_a_presentation_with_no_proof() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let vc = sign_jcs(
            unsigned_agent_vc(&f.holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;
        let vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": f.holder_did,
            "verifiableCredential": [vc],
        });

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("an unsigned presentation must be rejected");
        assert!(err.contains("has no proof"), "{err}");
    }
}
