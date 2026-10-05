use std::collections::HashMap;
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use anyhow::{Context as AnyhowContext, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use did_peer::resolve_did_peer;
use serde_json::Value;
use ssi::claims::data_integrity::{AnyDataIntegrity, AnySuite, Proofs};
use ssi::claims::vc::v2::syntax::{JsonCredential, JsonPresentation};
use ssi::claims::{ProofValidationError, Verification, VerificationParameters};
use ssi::dids::document::{self, representation::MediaType};
use ssi::dids::resolution::{self, Options};
use ssi::dids::{AnyDidMethod, DID, DIDResolver, DIDURL, VerificationMethodDIDResolver};
use ssi::verification_methods::AnyMethod;

use super::context::create_signature_environment;
use super::vp_issuer::VP_LIFETIME_MINUTES;

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

fn ensure_proofs_controlled_by(
    proofs: &Proofs<AnySuite>,
    expected_did: &str,
    role: &str,
) -> Result<()> {
    if proofs.is_empty() {
        anyhow::bail!("has no proof");
    }
    for proof in proofs.iter() {
        let vm = proof.verification_method.id();
        let did = DIDURL::new(vm.as_str())
            .map_err(|e| anyhow::anyhow!("invalid proof verificationMethod {}: {}", vm, e))?
            .did();
        if did.as_str() != expected_did {
            anyhow::bail!("proof verificationMethod {} does not belong to {} {}", vm, role, expected_did);
        }
    }
    Ok(())
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

        let vp: AnyDataIntegrity<JsonPresentation<AnyDataIntegrity<JsonCredential>>> =
            serde_json::from_value(presentation.clone())
                .context("Failed to parse VP as Data Integrity presentation")?;

        let typed_vcs = &vp
            .claims
            .verifiable_credentials;
        anyhow::ensure!(
            typed_vcs.len() == vcs.len(),
            "VP credential count mismatch: {} parsed vs {} raw",
            typed_vcs.len(),
            vcs.len()
        );

        ensure_proofs_controlled_by(&vp.proofs, &holder_did, "holder").context("VP proof binding failed")?;
        ensure_verified(vp.verify(&params).await, "VP")?;

        let mut credentials = Vec::with_capacity(vcs.len());
        for (i, (vc_json, vc)) in vcs
            .iter()
            .zip(typed_vcs)
            .enumerate()
        {
            let vc_result =
                verify_vc_fields(vc_json, &holder_did).with_context(|| format!("VC[{}] validation failed", i))?;
            ensure_proofs_controlled_by(&vc.proofs, &vc_result.issuer_did, "issuer")
                .with_context(|| format!("VC[{}] proof binding failed", i))?;
            ensure_verified(vc.verify(&params).await, &format!("VC[{}]", i))?;
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
                holder_key: Cow::Borrowed(holder_key),
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
                holder_key: Cow::Owned(holder_key),
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
}
