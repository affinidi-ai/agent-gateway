use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use chrono::{Duration, Utc};
use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::prelude::{CreateDIDConfig, Parameters, Secret, UpdateDIDConfig, create_did, update_did};
use serde_json::{Value, json};
use ssi::claims::SignatureEnvironment;
use ssi::claims::data_integrity::AnyInputOptions;
use ssi::claims::vc;
use ssi::crypto::ed25519::VerifyingKey;
use ssi::dids::DIDKey;
use ssi::jwk::JWK;
use ssi::prelude::{AnyMethod, AnySuite, CryptographicSuite, ProofOptions, SingleSecretSigner};
use ssi::verification_methods::{LocalSigner, Multikey, ProofPurpose, ReferenceOrOwned};
use ssi_json_ld::IriBuf;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const KEY_ID: &str = "key-2";
const CREDENTIALS_V2: &str = "https://www.w3.org/ns/credentials/v2";

/// The verification methods a signature resolves, the signer, and the proof options.
type ProofSetup = (HashMap<IriBuf, AnyMethod>, LocalSigner<SingleSecretSigner<JWK>>, AnyInputOptions);

/// A party that signs credentials and presentations with one Ed25519 key.
struct SigningKey {
    did: String,
    key: JWK,
}

impl SigningKey {
    fn verification_method(&self) -> String {
        format!("{}#{KEY_ID}", self.did)
    }

    async fn sign_credential(
        &self,
        subject: &str,
    ) -> Value {
        let now = Utc::now();
        let credential = json!({
            "@context": [CREDENTIALS_V2],
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": ["VerifiableCredential"],
            "issuer": self.did,
            "validFrom": (now - Duration::minutes(1)).to_rfc3339(),
            "validUntil": (now + Duration::days(1)).to_rfc3339(),
            "credentialSubject": { "id": subject },
        });
        let credential: vc::v2::SpecializedJsonCredential =
            serde_json::from_value(credential).expect("the credential is a v2 credential");
        let (methods, signer, options) = self.signing_parts(ProofPurpose::Assertion);
        let signed = AnySuite::EdDsaRdfc2022
            .sign_with(SignatureEnvironment::default(), credential, &methods, signer, options, Default::default())
            .await
            .expect("sign the credential");
        serde_json::to_value(&signed).expect("serialize the signed credential")
    }

    async fn sign_presentation(
        &self,
        credentials: Vec<Value>,
    ) -> Value {
        let presentation = json!({
            "@context": [CREDENTIALS_V2],
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": ["VerifiablePresentation"],
            "holder": self.did,
            "verifiableCredential": credentials,
        });
        let presentation: vc::v2::syntax::JsonPresentation =
            serde_json::from_value(presentation).expect("the presentation is a v2 presentation");
        let (methods, signer, mut options) = self.signing_parts(ProofPurpose::Authentication);
        let expires = (Utc::now() + Duration::minutes(5)).to_rfc3339();
        options.expires = Some(
            expires
                .parse()
                .expect("an RFC 3339 time"),
        );
        let signed = AnySuite::EdDsaRdfc2022
            .sign_with(SignatureEnvironment::default(), presentation, &methods, signer, options, Default::default())
            .await
            .expect("sign the presentation");
        serde_json::to_value(&signed).expect("serialize the signed presentation")
    }

    fn signing_parts(
        &self,
        purpose: ProofPurpose,
    ) -> ProofSetup {
        let multicodec = self
            .key
            .to_public()
            .to_multicodec()
            .expect("an Ed25519 public key");
        let public_key: [u8; 32] = multicodec.as_bytes()[2..]
            .try_into()
            .expect("a 32-byte Ed25519 public key");
        let verifying_key = VerifyingKey::from_bytes(&public_key).expect("an Ed25519 verifying key");
        let method = Multikey::from_public_key(
            DIDKey::generate(&self.key)
                .expect("a did:key for the signing key")
                .into_iri(),
            self.did
                .clone()
                .try_into()
                .expect("the signer DID is a URI"),
            &verifying_key,
        );
        let id: IriBuf = self
            .verification_method()
            .try_into()
            .expect("the verification method is an IRI");
        let methods = HashMap::from([(id.clone(), AnyMethod::Multikey(method))]);
        let mut options = ProofOptions::from_method_and_options(ReferenceOrOwned::Reference(id), Default::default());
        options.proof_purpose = purpose;
        (methods, SingleSecretSigner::new(self.key.clone()).into_local(), options)
    }
}

fn public_key_multibase(key: &JWK) -> String {
    let multicodec = key
        .to_public()
        .to_multicodec()
        .expect("an Ed25519 public key");
    format!("z{}", bs58::encode(multicodec.as_bytes()).into_string())
}

/// A `did:peer` whose key is listed under every verification relationship.
fn peer_signer() -> SigningKey {
    let key = JWK::generate_ed25519().expect("generate an Ed25519 key");
    let public_key = public_key_multibase(&key);
    let keys = (0..2)
        .map(|_| did_peer::DIDPeerCreateKeys {
            purpose: did_peer::DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(public_key.clone()),
        })
        .collect::<Vec<_>>();
    let did = did_peer::DIDPeer::create_peer_did(&keys, None)
        .expect("create a did:peer")
        .0;
    SigningKey { did, key }
}

fn did_document(
    did: &str,
    public_key: &str,
    relationships: &[&str],
) -> Value {
    let method = format!("{did}#{KEY_ID}");
    let mut document = json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": did,
        "verificationMethod": [{
            "id": method,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key,
        }],
    });
    for relationship in relationships {
        document[*relationship] = json!([method]);
    }
    document
}

fn update_secret(key: &JWK) -> Secret {
    let jwk = serde_json::to_value(key).expect("serialize the update key");
    let public_key = public_key_multibase(key);
    let id = format!("did:key:{public_key}#{public_key}");
    Secret::from_jwk_value(&id, &jwk).expect("a did:webvh update key")
}

/// A caller with a `did:webvh` whose DID log this process serves over plain HTTP on localhost,
/// so its DID document can change between requests the way a published one does.
pub struct PresentationSigner {
    signer: SigningKey,
    log: Arc<RwLock<Vec<String>>>,
    handle: JoinHandle<()>,
}

impl std::fmt::Debug for PresentationSigner {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("PresentationSigner")
            .field("did", &self.signer.did)
            .finish()
    }
}

impl Drop for PresentationSigner {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Waits until the clock is past the latest version's `versionTime`, which has whole-second
/// precision: a did:webvh version must be dated strictly after the one before it, and not in the
/// future.
async fn wait_past_version_time(jsonl: &str) {
    let latest = jsonl
        .lines()
        .last()
        .and_then(|line| serde_json::from_str::<Value>(line).ok())
        .and_then(|entry| {
            entry["versionTime"]
                .as_str()
                .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
        })
        .expect("the published DID log has a versionTime");
    while Utc::now().timestamp() <= latest.timestamp() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn serve_log(State(log): State<Arc<RwLock<Vec<String>>>>) -> String {
    log.read()
        .expect("the DID log lock")
        .join("\n")
}

impl PresentationSigner {
    /// Publishes a DID whose document lists the signing key under `relationships` only.
    pub async fn publish(relationships: &[&str]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the DID host");
        let port = listener
            .local_addr()
            .expect("the DID host address")
            .port();
        let key = JWK::generate_ed25519().expect("generate an Ed25519 key");
        let public_key = public_key_multibase(&key);
        let created = create_did(
            CreateDIDConfig::builder()
                .address(format!("http://localhost:{port}/"))
                .authorization_key(update_secret(&key))
                .did_document(did_document("{DID}", &public_key, relationships))
                .parameters(Parameters {
                    update_keys: Some(Arc::new(vec![didwebvh_rs::Multibase::new(public_key.clone())])),
                    ..Default::default()
                })
                .build()
                .expect("a did:webvh create config"),
        )
        .await
        .expect("create the did:webvh");
        let did = created.did().to_string();
        let log = Arc::new(RwLock::new(vec![
            serde_json::to_string(created.log_entry()).expect("serialize the DID log entry"),
        ]));
        let app = Router::new()
            .route("/.well-known/did.jsonl", get(serve_log))
            .with_state(log.clone());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve the DID log");
        });
        Self {
            signer: SigningKey { did, key },
            log,
            handle,
        }
    }

    pub fn did(&self) -> &str {
        &self.signer.did
    }

    /// Publishes a new version of the DID document that lists the signing key under `relationships`.
    pub async fn republish(
        &self,
        relationships: &[&str],
    ) {
        let jsonl = self
            .log
            .read()
            .expect("the DID log lock")
            .join("\n");
        wait_past_version_time(&jsonl).await;
        let mut state = DIDWebVHState::default();
        state
            .resolve_log(&self.signer.did, &jsonl, None)
            .await
            .expect("read the published DID log");
        let public_key = public_key_multibase(&self.signer.key);
        let updated = update_did(
            UpdateDIDConfig::builder()
                .state(state)
                .signing_key(update_secret(&self.signer.key))
                .document(did_document(&self.signer.did, &public_key, relationships))
                .build()
                .expect("a did:webvh update config"),
        )
        .await
        .expect("update the did:webvh");
        let entry = serde_json::to_string(updated.log_entry()).expect("serialize the DID log entry");
        self.log
            .write()
            .expect("the DID log lock")
            .push(entry);
    }

    /// A presentation signed by this caller for authentication, of a credential it issued to itself.
    pub async fn present_own_credential(&self) -> Value {
        let credential = self
            .signer
            .sign_credential(&self.signer.did)
            .await;
        self.signer
            .sign_presentation(vec![credential])
            .await
    }

    /// A presentation signed by this caller for authentication, of a credential another issuer, whose
    /// key is listed for every purpose, issued to it.
    pub async fn present_credential_from_another_issuer(&self) -> Value {
        let credential = peer_signer()
            .sign_credential(&self.signer.did)
            .await;
        self.signer
            .sign_presentation(vec![credential])
            .await
    }
}
