use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Ok, Result};
use async_trait::async_trait;
use serde_json::{Value, json};

use ssi::claims::vc;
use ssi::crypto::ed25519::VerifyingKey;
use ssi::dids::DIDKey;
use ssi::jwk::JWK;
use ssi::prelude::{AnyMethod, AnySuite, CryptographicSuite, ProofOptions, SingleSecretSigner};
use ssi::verification_methods::LocalSigner as SsiLocalSigner;
use ssi::verification_methods::{Multikey, ReferenceOrOwned};
use ssi_json_ld::IriBuf;
use tokio::sync::RwLock;

use crate::identity::VCIssuerConfig;
use crate::identity::ssi::context::{CTX_AGENT_IDENTITY_V1_URL, create_signature_environment};

pub const VC_LIFETIME_DAYS: i64 = 365;
pub const DEFAULT_SIGNING_KEY_ID: &str = "key-2";

pub struct AgentIdentity<'a> {
    pub identity_fields: Cow<'a, HashMap<String, serde_json::Value>>,
    pub did: Cow<'a, str>,
    /// Pre-built workload binding JSON for the credential subject.
    /// When present, replaces the flat `identityFields` with structured `workloadBinding`.
    pub workload_binding: Option<serde_json::Value>,
}

pub enum IssueVcPayload<'a> {
    AgentIdentity(AgentIdentity<'a>),
}

#[async_trait]
pub trait VcSigner: Send + Sync {
    async fn sign(
        &self,
        payload: Value,
    ) -> Result<Value>;
}

#[async_trait]
pub trait VcIssuer: Send + Sync {
    async fn issue<'a>(
        &self,
        payload: IssueVcPayload<'a>,
    ) -> Result<Value>;
}

pub struct LocalVcIssuer {
    config: Arc<RwLock<VCIssuerConfig>>,
    signer: Arc<dyn VcSigner>,
}

impl LocalVcIssuer {
    pub fn new(
        config: Arc<RwLock<VCIssuerConfig>>,
        signer: Arc<dyn VcSigner>,
    ) -> Self {
        Self { config, signer }
    }
}

pub struct LocalVcSigner {
    config: Arc<RwLock<VCIssuerConfig>>,
}

impl LocalVcSigner {
    pub fn new(config: Arc<RwLock<VCIssuerConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl VcSigner for LocalVcSigner {
    async fn sign(
        &self,
        payload: Value,
    ) -> Result<Value> {
        self.sign_w3c_ldv2(payload.clone())
            .await
    }
}

impl LocalVcSigner {
    async fn sign_w3c_ldv2(
        &self,
        credential: Value,
    ) -> Result<Value> {
        // Read config at signing time for current values
        let config = self.config.read().await;
        let signing_key = config.signing_key.clone();
        let issuer_did = config.proxy_did.clone();
        drop(config);

        // Parse as SSI v2 credential
        let vc: vc::v2::SpecializedJsonCredential =
            serde_json::from_value(credential).context("Failed to parse as v2 credential")?;

        // Generate DIDKey from the JWK
        let did_key = DIDKey::generate(&signing_key).context("Failed to generate DID key")?;

        let verification_method_str = format!("{}#{}", issuer_did, DEFAULT_SIGNING_KEY_ID);

        // Setup verification method and resolver
        let mut resolver_map: HashMap<IriBuf, AnyMethod> = HashMap::new();

        // Extract Ed25519 public key from JWK
        let public_key_multicodec = signing_key
            .to_public()
            .to_multicodec()
            .context("Failed to convert public key to multicodec")?;
        let public_key_bytes = public_key_multicodec.as_bytes();

        // Create Ed25519 verifying key (skip first 2 bytes of multicodec prefix)
        let verifying_key = VerifyingKey::from_bytes(
            &public_key_bytes[2..]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid public key length"))?,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create verifying key: {}", e))?;

        // Create verification method
        let verification_method_key = Multikey::from_public_key(
            did_key.into_iri(),
            issuer_did
                .clone()
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

        // Create signer
        let signer: SsiLocalSigner<SingleSecretSigner<JWK>> = SingleSecretSigner::new(signing_key).into_local();

        // Setup proof options
        let options = ProofOptions::from_method_and_options(verification_method, Default::default());

        let env = create_signature_environment(None).await?;

        let suite = AnySuite::EdDsaRdfc2022;

        // Sign the credential
        let signed_vc = suite
            .sign_with(env, vc, &resolver_map, signer, options, Default::default())
            .await
            .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;

        // Convert back to JSON Value
        let signed_json = serde_json::to_value(&signed_vc).context("Failed to serialize signed credential")?;

        Ok(signed_json)
    }
}

#[async_trait]
impl VcIssuer for LocalVcIssuer {
    async fn issue<'a>(
        &self,
        payload: IssueVcPayload<'a>,
    ) -> Result<Value> {
        let IssueVcPayload::AgentIdentity(air) = payload;

        // Read issuer DID from config at issuance time
        let config = self.config.read().await;
        let proxy_did = config.proxy_did.clone();
        drop(config);

        // Build credential subject — use workloadBinding if provided, else legacy identityFields
        let credential_subject = if let Some(ref wb) = air.workload_binding {
            json!({
                "id": air.did.as_ref(),
                "workloadBinding": wb,
            })
        } else {
            let identity_json =
                serde_json::to_value(&*air.identity_fields).context("Failed to serialize identity fields")?;
            json!({
                "id": air.did.as_ref(),
                "identityFields": identity_json,
            })
        };

        // Create unsigned VC v2 payload
        let now = chrono::Utc::now();
        let credential = json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                CTX_AGENT_IDENTITY_V1_URL.to_string()
            ],
            "type": ["VerifiableCredential", "AgentIdentityCredential"],
            "issuer": proxy_did,
            "validFrom": now.to_rfc3339(),
            "validUntil": (now + chrono::Duration::days(VC_LIFETIME_DAYS)).to_rfc3339(),
            "credentialSubject": credential_subject,
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        });

        // Sign using SSI library

        self.signer
            .sign(credential)
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::identity::VCIssuerConfig;

    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn create_test_config() -> VCIssuerConfig {
        let signing_key = crate::identity::test_helpers::test_signing_key();
        VCIssuerConfig {
            storage_path: "".into(),
            proxy_did: "did:web:gateway.example.com".to_string(),
            signing_key,
            is_vp_challenge_required: false,
        }
    }

    fn create_test_agent_identity_record() -> AgentIdentity<'static> {
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
            did: Cow::Borrowed("did:web:example.com:agent:123"),
            identity_fields: Cow::Owned(identity_fields),
            workload_binding: None,
        }
    }

    #[tokio::test]
    async fn test_issue_happy_path() {
        // Arrange
        let config = create_test_config();
        let config = Arc::new(RwLock::new(config));

        let signer = Arc::new(LocalVcSigner::new(config.clone())) as Arc<dyn VcSigner>;
        let vc_issuer = LocalVcIssuer::new(config.clone(), signer);

        let agent_record = create_test_agent_identity_record();
        let agent_did = agent_record.did.clone();
        let payload = IssueVcPayload::AgentIdentity(agent_record);

        // Act
        let result = vc_issuer.issue(payload).await;

        // Assert
        assert!(result.is_ok(), "Expected successful VC issuance");

        let vc = result.unwrap();

        // Verify VC structure
        assert_eq!(vc["type"], json!(["VerifiableCredential", "AgentIdentityCredential"]));
        assert_eq!(vc["issuer"], json!("did:web:gateway.example.com"));

        // Verify credential subject
        let credential_subject = &vc["credentialSubject"];
        assert_eq!(credential_subject["id"], json!(agent_did));
        assert!(credential_subject["identityFields"].is_object());

        // Verify dates are present
        assert!(vc["validFrom"].is_string());
        assert!(vc["validUntil"].is_string());

        // Verify credential ID
        assert!(
            vc["id"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:")
        );

        // Verify proof was added by the real signer
        assert!(vc["proof"].is_object());
        let proof = &vc["proof"];
        assert_eq!(proof["type"], json!("DataIntegrityProof"));
        assert_eq!(proof["cryptosuite"], json!("eddsa-rdfc-2022"));
        assert!(proof["created"].is_string());
        // verificationMethod can be either a string or an object
        assert!(!proof["verificationMethod"].is_null());
        assert_eq!(proof["proofPurpose"], json!("assertionMethod"));
        assert!(proof["proofValue"].is_string());

        // Verify context
        let context = vc["@context"]
            .as_array()
            .unwrap();
        assert!(context.contains(&json!("https://www.w3.org/ns/credentials/v2")));
    }
}
