use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Ok, Result};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::{Value, json};

use ssi::claims::vc;
use ssi::crypto::ed25519::VerifyingKey;
use ssi::dids::DIDKey;
use ssi::jwk::JWK;
use ssi::prelude::{AnyMethod, AnySuite, CryptographicSuite, ProofOptions, SingleSecretSigner};
use ssi::verification_methods::LocalSigner as SsiLocalSigner;
use ssi::verification_methods::{Multikey, ReferenceOrOwned};
use ssi_json_ld::IriBuf;

use crate::identity::ssi::context::create_signature_environment;

pub const VP_LIFETIME_MINUTES: i64 = 5;
pub const DEFAULT_SIGNING_KEY_ID: &str = "key-2";

/// Represents a presentation containing one or more Verifiable Credentials
pub struct Credentials<'a> {
    /// The holder's key for signing the presentation
    pub holder_key: Cow<'a, JWK>,
    /// The holder's did
    pub holder_did: Cow<'a, str>,
    /// The verifiable credentials to include in the presentation
    pub verifiable_credentials: Cow<'a, [Value]>,
    /// Optional challenge for the presentation (for authentication)
    pub challenge: Option<Cow<'a, str>>,
    /// Optional domain for the presentation
    pub domain: Option<Cow<'a, str>>,
}

/// Payload types for VP issuance
pub enum VpIssuerPayload<'a> {
    Credentials(Credentials<'a>),
}

/// Trait for signing Verifiable Presentations
#[async_trait]
pub trait VpSigner: Send + Sync {
    async fn sign(
        &self,
        payload: Value,
        holder_key: &JWK,
        holder_did: &str,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<Value>;
}

/// Trait for issuing Verifiable Presentations
#[async_trait]
pub trait VpIssuer: Send + Sync {
    async fn issue<'a>(
        &self,
        payload: VpIssuerPayload<'a>,
    ) -> Result<Value>;
}

/// Local implementation of VpIssuer
pub struct LocalVpIssuer {
    signer: Arc<dyn VpSigner>,
}

impl LocalVpIssuer {
    pub fn new(signer: Arc<dyn VpSigner>) -> Self {
        Self { signer }
    }
}

/// Local implementation of VpSigner
pub struct LocalVpSigner;

impl LocalVpSigner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LocalVpSigner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VpSigner for LocalVpSigner {
    async fn sign(
        &self,
        payload: Value,
        holder_key: &JWK,
        holder_did: &str,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<Value> {
        self.sign_w3c_ldv2(payload.clone(), holder_key, holder_did, challenge, domain)
            .await
    }
}

impl LocalVpSigner {
    async fn sign_w3c_ldv2(
        &self,
        presentation: Value,
        holder_key: &JWK,
        holder_did: &str,
        challenge: Option<String>,
        domain: Option<String>,
    ) -> Result<Value> {
        let vp: vc::v2::syntax::JsonPresentation =
            serde_json::from_value(presentation).context("Failed to parse as v2 presentation")?;

        let did_key = DIDKey::generate(holder_key).context("Failed to generate DID key")?;

        let verification_method_str = format!("{}#{}", holder_did, DEFAULT_SIGNING_KEY_ID);

        let mut resolver_map: HashMap<IriBuf, AnyMethod> = HashMap::new();

        let public_key_multicodec = holder_key
            .to_public()
            .to_multicodec()
            .context("Failed to convert public key to multicodec")?;
        let public_key_bytes = public_key_multicodec.as_bytes();

        let verifying_key = VerifyingKey::from_bytes(
            &public_key_bytes[2..]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid public key length"))?,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create verifying key: {}", e))?;

        let verification_method_key = Multikey::from_public_key(
            did_key.into_iri(),
            holder_did
                .to_string()
                .try_into()?,
            &verifying_key,
        );

        let verification_method_unwrapped = AnyMethod::Multikey(verification_method_key.clone());

        let verification_method: ReferenceOrOwned<AnyMethod> = ReferenceOrOwned::Reference(
            verification_method_str
                .clone()
                .try_into()?,
        );

        resolver_map.insert(
            verification_method_str
                .clone()
                .try_into()?,
            verification_method_unwrapped,
        );

        let signer: SsiLocalSigner<SingleSecretSigner<JWK>> = SingleSecretSigner::new(holder_key.clone()).into_local();

        let mut options = ProofOptions::from_method_and_options(verification_method, Default::default());

        if let Some(c) = challenge {
            options.challenge = Some(c);
        }

        if let Some(d) = domain {
            options.domains = vec![d];
        }

        let expires = Utc::now() + Duration::minutes(VP_LIFETIME_MINUTES);
        let expires_str = expires.to_rfc3339();
        options.expires = Some(
            expires_str
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid expires format: {}", e))?,
        );

        let env = create_signature_environment(None).await?;

        let suite = AnySuite::EdDsaRdfc2022;

        let signed_vp = suite
            .sign_with(env, vp, &resolver_map, signer, options, Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("VP Signing failed: {}", e))?;

        let signed_json = serde_json::to_value(&signed_vp).context("Failed to serialize signed presentation")?;

        Ok(signed_json)
    }
}

#[async_trait]
impl VpIssuer for LocalVpIssuer {
    async fn issue<'a>(
        &self,
        payload: VpIssuerPayload<'a>,
    ) -> Result<Value> {
        let VpIssuerPayload::Credentials(pc) = payload;

        let holder_key = pc.holder_key.as_ref().clone();
        let holder_did = pc.holder_did.as_ref();

        let presentation = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2"
            ],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": pc.verifiable_credentials.as_ref(),
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        });

        let challenge = pc
            .challenge
            .map(|c| c.as_ref().to_string());
        let domain = pc
            .domain
            .map(|d| d.as_ref().to_string());

        self.signer
            .sign(presentation, &holder_key, holder_did, challenge, domain)
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::identity::VCIssuerConfig;
    use crate::identity::ssi::did_utils::create_did_peer_from_ed25519_jwk;
    use crate::identity::ssi::vc_issuer::{
        AgentIdentity, IssueVcPayload, LocalVcIssuer, LocalVcSigner, VcIssuer, VcSigner,
    };

    use super::*;
    use serde_json::json;
    use tokio::sync::RwLock;

    fn create_test_config() -> VCIssuerConfig {
        let signing_key = crate::identity::test_helpers::test_signing_key();
        VCIssuerConfig {
            storage_path: "".into(),
            proxy_did: "did:web:gateway.example.com".to_string(),
            signing_key,
            is_vp_challenge_required: false,
        }
    }

    fn create_test_holder_key() -> JWK {
        JWK::generate_ed25519().unwrap()
    }

    fn create_test_agent_identity(agent_did: String) -> AgentIdentity<'static> {
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
                },
                "region": "us-east-1"
            }),
        );

        AgentIdentity {
            did: Cow::Owned(agent_did),
            identity_fields: Cow::Owned(identity_fields),
            workload_binding: None,
            display_name: None,
        }
    }

    async fn issue_real_test_vc(
        config: Arc<RwLock<VCIssuerConfig>>,
        agent_did: String,
    ) -> Value {
        let vc_signer = Arc::new(LocalVcSigner::new(config.clone())) as Arc<dyn VcSigner>;
        let vc_issuer = LocalVcIssuer::new(config, vc_signer);

        let agent_identity = create_test_agent_identity(agent_did);
        let payload = IssueVcPayload::AgentIdentity(agent_identity);

        vc_issuer
            .issue(payload)
            .await
            .expect("VC issuance should succeed")
    }

    fn create_test_presentation_credentials_with_vc(
        vc: Value,
        holder_key: JWK,
        holder_did: String,
    ) -> Credentials<'static> {
        Credentials {
            holder_key: Cow::Owned(holder_key),
            holder_did: Cow::Owned(holder_did),
            verifiable_credentials: Cow::Owned(vec![vc]),
            challenge: Some(Cow::Borrowed("test-challenge-123")),
            domain: Some(Cow::Borrowed("https://example.com")),
        }
    }

    #[tokio::test]
    async fn test_issue_happy_path() {
        let config = create_test_config();
        let config = Arc::new(RwLock::new(config));

        let holder_key = create_test_holder_key();
        let expected_agent_did = create_did_peer_from_ed25519_jwk(&holder_key).unwrap();

        let signed_vc = issue_real_test_vc(config.clone(), expected_agent_did.clone()).await;
        println!("Signed VC: {}", serde_json::to_string_pretty(&signed_vc).unwrap());

        let signer = Arc::new(LocalVpSigner::new()) as Arc<dyn VpSigner>;
        let vp_issuer = LocalVpIssuer::new(signer);

        let presentation_creds =
            create_test_presentation_credentials_with_vc(signed_vc, holder_key, expected_agent_did.clone());
        let payload = VpIssuerPayload::Credentials(presentation_creds);

        let result = vp_issuer.issue(payload).await;

        assert!(result.is_ok(), "Expected successful VP issuance, got: {:?}", result);

        let vp = result.unwrap();
        println!("VP Result: {}", serde_json::to_string_pretty(&vp).unwrap());

        assert_eq!(vp["type"], json!(["VerifiablePresentation"]));
        assert_eq!(vp["holder"], json!(expected_agent_did));
        assert!(
            vp["holder"]
                .as_str()
                .unwrap()
                .starts_with("did:peer:2.V")
        );

        let vc = &vp["verifiableCredential"];
        assert!(!vc.is_null(), "verifiableCredential should exist");

        let vc_proof = if vc.is_array() {
            &vc[0]["proof"]
        } else {
            &vc["proof"]
        };
        assert!(vc_proof.is_object(), "VC inside VP should have a proof");
        assert_eq!(vc_proof["type"], json!("DataIntegrityProof"));
        assert_eq!(vc_proof["cryptosuite"], json!("eddsa-rdfc-2022"));

        assert!(
            vp["id"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:")
        );

        assert!(vp["proof"].is_object());
        let proof = &vp["proof"];
        assert_eq!(proof["type"], json!("DataIntegrityProof"));
        assert_eq!(proof["cryptosuite"], json!("eddsa-rdfc-2022"));
        assert!(proof["created"].is_string());
        assert!(!proof["verificationMethod"].is_null());
        assert_eq!(proof["proofPurpose"], json!("assertionMethod"));
        assert!(proof["proofValue"].is_string());

        assert_eq!(proof["challenge"], json!("test-challenge-123"));
        assert_eq!(proof["domain"], json!("https://example.com"));

        let context = vp["@context"]
            .as_array()
            .unwrap();
        assert!(context.contains(&json!("https://www.w3.org/ns/credentials/v2")));
    }

    #[tokio::test]
    async fn test_issue_vp_without_challenge_and_domain() {
        let config = create_test_config();
        let config = Arc::new(RwLock::new(config));

        let holder_key = create_test_holder_key();
        let agent_did = create_did_peer_from_ed25519_jwk(&holder_key).unwrap();

        let signed_vc = issue_real_test_vc(config.clone(), agent_did.clone()).await;

        let signer = Arc::new(LocalVpSigner::new()) as Arc<dyn VpSigner>;
        let vp_issuer = LocalVpIssuer::new(signer);

        let presentation_creds = Credentials {
            holder_key: Cow::Owned(holder_key.clone()),
            holder_did: Cow::Owned(agent_did),
            verifiable_credentials: Cow::Owned(vec![signed_vc]),
            challenge: None,
            domain: None,
        };
        let payload = VpIssuerPayload::Credentials(presentation_creds);

        let result = vp_issuer.issue(payload).await;

        assert!(result.is_ok(), "Expected successful VP issuance without challenge/domain");

        let vp = result.unwrap();

        assert!(vp.get("challenge").is_none());
        assert!(vp.get("domain").is_none());

        let proof = &vp["proof"];
        assert!(proof.is_object());
        assert!(
            proof
                .get("challenge")
                .is_none()
                || proof["challenge"].is_null()
        );
        assert!(proof.get("domain").is_none() || proof["domain"].is_null());
    }

    #[tokio::test]
    async fn test_issue_vp_with_multiple_credentials() {
        let config = create_test_config();
        let config = Arc::new(RwLock::new(config));

        let holder_key = create_test_holder_key();
        let agent_did = create_did_peer_from_ed25519_jwk(&holder_key).unwrap();

        let signed_vc1 = issue_real_test_vc(config.clone(), agent_did.clone()).await;
        let signed_vc2 = issue_real_test_vc(config.clone(), agent_did.clone()).await;

        let signer = Arc::new(LocalVpSigner::new()) as Arc<dyn VpSigner>;
        let vp_issuer = LocalVpIssuer::new(signer);

        let presentation_creds = Credentials {
            holder_key: Cow::Owned(holder_key.clone()),
            holder_did: Cow::Owned(agent_did),
            verifiable_credentials: Cow::Owned(vec![signed_vc1, signed_vc2]),
            challenge: None,
            domain: None,
        };
        let payload = VpIssuerPayload::Credentials(presentation_creds);

        let result = vp_issuer.issue(payload).await;

        assert!(result.is_ok(), "Expected successful VP issuance with multiple credentials");

        let vp = result.unwrap();
        let vcs = vp["verifiableCredential"]
            .as_array()
            .unwrap();
        assert_eq!(vcs.len(), 2);

        for vc in vcs {
            assert!(vc["proof"].is_object(), "Each VC should have a proof");
            assert_eq!(vc["proof"]["type"], json!("DataIntegrityProof"));
            assert_eq!(vc["proof"]["cryptosuite"], json!("eddsa-rdfc-2022"));
        }
    }

    #[tokio::test]
    async fn test_vp_holder_did_is_did_peer() {
        let config = create_test_config();
        let config = Arc::new(RwLock::new(config));

        let holder_key = create_test_holder_key();
        let expected_did_peer = create_did_peer_from_ed25519_jwk(&holder_key).unwrap();

        let signed_vc = issue_real_test_vc(config.clone(), expected_did_peer.clone()).await;

        let signer = Arc::new(LocalVpSigner::new()) as Arc<dyn VpSigner>;
        let vp_issuer = LocalVpIssuer::new(signer);

        let presentation_creds = Credentials {
            holder_key: Cow::Owned(holder_key),
            holder_did: Cow::Owned(expected_did_peer.clone()),
            verifiable_credentials: Cow::Owned(vec![signed_vc]),
            challenge: None,
            domain: None,
        };
        let payload = VpIssuerPayload::Credentials(presentation_creds);

        let result = vp_issuer.issue(payload).await;
        let vp = result.unwrap();

        let holder = vp["holder"].as_str().unwrap();
        assert!(holder.starts_with("did:peer:2.V"), "Holder DID should be did:peer method 2");
        assert_eq!(holder, expected_did_peer, "Holder DID should match expected did:peer");
    }
}
