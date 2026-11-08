//! A VTA context as a DID that signs.
//!
//! A context the gateway provisions signs as its own `did:key`, and that DID is
//! the `did:key` of one Ed25519 key held in the context. So the whole identity
//! is recoverable from two reads the trust agent already answers: the context's
//! `did`, and the key in that context whose public half the DID names. Nothing
//! has to be *designated*, which is why there is no designation to keep in step.
//!
//! Signing a document goes through `keys/sign-document/0.1`. The trust agent
//! builds the proof itself and signs only as the DID the document names, only
//! with a key that DID's own document lists for the requested proof purpose, so
//! a request cannot point the signature at a key that is not the document's
//! signer. This module still checks the answer against what it asked for before
//! anything is attributed to the context: a proof from some other key, or over
//! some other document, is refused rather than passed on.

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::RwLock;

use crate::vta::client::VtaRestClient;

/// `vta/contexts/get/1.0`.
const TASK_CONTEXTS_GET: &str = "https://trusttasks.org/spec/vta/contexts/get/1.0";

/// `keys/list/0.1`.
///
/// Not `keys/show`: that refuses an **internal** key outright, because the
/// guard is on the key's origin rather than on what is read. `list` returns the
/// same public records.
const TASK_KEYS_LIST: &str = "https://trusttasks.org/spec/keys/list/0.1";

/// `keys/sign-document/0.1`.
const TASK_KEYS_SIGN_DOCUMENT: &str = "https://trusttasks.org/spec/keys/sign-document/0.1";

/// The verification relationship a credential's issuer signs under.
pub const PURPOSE_ASSERTION_METHOD: &str = "assertionMethod";

/// The verification relationship a DID signs under to present something as
/// itself, such as a holder proof on a presentation.
pub const PURPOSE_AUTHENTICATION: &str = "authentication";

/// Keys a context is asked for in one listing. A provisioned context holds a
/// handful, so this is a bound rather than a page size to walk.
const KEY_LISTING_LIMIT: u64 = 100;

/// The body of a Trust Task response.
///
/// Every answer arrives wrapped in an envelope that carries its own fields,
/// including a top-level `id`. Reading through `payload` first keeps a caller
/// from binding to the envelope's uuid instead of the thing it asked for;
/// falling back to the whole value keeps the flat shape working.
pub(crate) fn payload_of(response: &Value) -> &Value {
    response
        .get("payload")
        .unwrap_or(response)
}

/// The DID a context signs as, the key that DID is, and the verification
/// method a verifier resolves for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextIdentity {
    pub did: String,
    pub key_id: String,
    pub verification_method: String,
}

/// Work out a context's identity from its record and a listing of its keys.
///
/// Fails closed: a context with no DID, a DID that is not a `did:key`, or a DID
/// that no active Ed25519 key in the context backs has no identity it can sign
/// as, and saying so here is better than a refusal from the signing task.
fn identity_from_records(
    context_id: &str,
    context: &Value,
    keys: &Value,
) -> Result<ContextIdentity> {
    let did = context
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("context `{context_id}` has no DID, so nothing it signs would be attributable"))?;
    let public_key = did
        .strip_prefix("did:key:")
        .ok_or_else(|| anyhow!("context `{context_id}` has DID `{did}`; only a did:key context signs through here"))?;

    let backing = keys
        .get("keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|key| {
            key.get("publicKey")
                .and_then(Value::as_str)
                == Some(public_key)
                && key
                    .get("keyType")
                    .and_then(Value::as_str)
                    == Some("ed25519")
                && key
                    .get("status")
                    .and_then(Value::as_str)
                    == Some("active")
        })
        .and_then(|key| {
            key.get("keyId")
                .and_then(Value::as_str)
        })
        .ok_or_else(|| {
            anyhow!(
                "context `{context_id}` holds no active Ed25519 key for its DID `{did}`, so it cannot sign as itself"
            )
        })?;

    Ok(ContextIdentity {
        did: did.to_string(),
        key_id: backing.to_string(),
        verification_method: format!("{did}#{public_key}"),
    })
}

/// The members of a `keys/sign-document` answer the gateway consumes.
#[derive(Debug, Deserialize)]
struct SignDocumentResult {
    document: Value,
    proof: Value,
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "signerDid")]
    signer_did: String,
}

/// What a signed document must still be, however the trust agent answered.
///
/// The check is against the **request**, not against the response's own
/// claims: a proof is attributed to the context only if its key, signer,
/// verification method and purpose are the ones asked for, the document is
/// exactly what was sent plus that proof, and any challenge or domain the
/// caller bound it to came back in the proof.
fn verify_signed_document(
    identity: &ContextIdentity,
    requested: &Value,
    purpose: &str,
    challenge: Option<&str>,
    domain: Option<&str>,
    result: &SignDocumentResult,
) -> Result<()> {
    if result.key_id != identity.key_id {
        bail!("the trust agent signed with key `{}` but `{}` was requested", result.key_id, identity.key_id);
    }
    if result.signer_did != identity.did {
        bail!("the trust agent signed as `{}` but `{}` was requested", result.signer_did, identity.did);
    }
    let proof_member = |name: &str| {
        result
            .proof
            .get(name)
            .and_then(Value::as_str)
    };
    if proof_member("verificationMethod")
        != Some(
            identity
                .verification_method
                .as_str(),
        )
    {
        bail!(
            "the proof names verification method {:?}, not `{}`",
            proof_member("verificationMethod"),
            identity.verification_method
        );
    }
    if proof_member("proofPurpose") != Some(purpose) {
        bail!("the proof carries purpose {:?}, not `{purpose}`", proof_member("proofPurpose"));
    }
    if proof_member("cryptosuite") != Some("eddsa-jcs-2022") {
        bail!("the proof uses cryptosuite {:?}, not `eddsa-jcs-2022`", proof_member("cryptosuite"));
    }
    if proof_member("proofValue").is_none() {
        bail!("the proof carries no `proofValue`");
    }
    if proof_member("challenge") != challenge {
        bail!("the proof's challenge is {:?}, not the {challenge:?} it was asked to carry", proof_member("challenge"));
    }
    if proof_member("domain") != domain {
        bail!("the proof's domain is {:?}, not the {domain:?} it was asked to carry", proof_member("domain"));
    }

    let mut secured = result.document.clone();
    let attached = secured
        .as_object_mut()
        .and_then(|members| members.remove("proof"));
    if attached.as_ref() != Some(&result.proof) {
        bail!("the signed document does not carry the proof that was returned beside it");
    }
    if &secured != requested {
        bail!("the signed document is not the document that was sent");
    }
    Ok(())
}

/// Resolves, and signs as, one VTA context.
pub struct ContextIdentityResolver {
    client: Arc<VtaRestClient>,
    context_id: String,
    /// Resolved once and kept. A context's DID is write-once and names a key
    /// that stays in it, so reading them per signature would add two round
    /// trips for values that cannot change.
    cached: RwLock<Option<ContextIdentity>>,
}

impl ContextIdentityResolver {
    pub fn new(
        client: Arc<VtaRestClient>,
        context_id: String,
    ) -> Self {
        Self {
            client,
            context_id,
            cached: RwLock::new(None),
        }
    }

    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// The context's identity, read once.
    pub async fn identity(&self) -> Result<ContextIdentity> {
        if let Some(identity) = self
            .cached
            .read()
            .await
            .as_ref()
        {
            return Ok(identity.clone());
        }

        let context = self
            .client
            .dispatch_signed::<Value>(TASK_CONTEXTS_GET, json!({ "id": self.context_id }))
            .await
            .map_err(|e| anyhow!("reading context `{}` to sign as it: {e}", self.context_id))?;
        let keys = self
            .client
            .dispatch_signed::<Value>(
                TASK_KEYS_LIST,
                json!({ "contextId": self.context_id, "status": "active", "limit": KEY_LISTING_LIMIT }),
            )
            .await
            .map_err(|e| anyhow!("listing the keys of context `{}`: {e}", self.context_id))?;

        let identity = identity_from_records(&self.context_id, payload_of(&context), payload_of(&keys))?;
        *self.cached.write().await = Some(identity.clone());
        Ok(identity)
    }

    /// Attach a Data-Integrity proof to `document` as this context.
    ///
    /// The document must already name this context's DID as its signer. The
    /// trust agent refuses a document that names any other, or that already
    /// carries a proof, so neither can be signed through here by accident.
    pub async fn sign_document(
        &self,
        document: Value,
        purpose: &str,
        challenge: Option<&str>,
        domain: Option<&str>,
    ) -> Result<Value> {
        let identity = self.identity().await?;
        let mut request = json!({
            "keyId": identity.key_id,
            "document": document,
            "proofPurpose": purpose,
        });
        if let Some(challenge) = challenge {
            request["challenge"] = json!(challenge);
        }
        if let Some(domain) = domain {
            request["domain"] = json!(domain);
        }
        let result: SignDocumentResult = self
            .client
            .dispatch_signed(TASK_KEYS_SIGN_DOCUMENT, request)
            .await
            .map_err(|e| anyhow!("signing a document as context `{}`: {e}", self.context_id))?;
        verify_signed_document(&identity, &document, purpose, challenge, domain, &result)
            .map_err(|e| anyhow!("signing a document as context `{}`: {e}", self.context_id))?;
        Ok(result.document)
    }
}

#[cfg(test)]
pub(crate) mod mock {
    //! A trust agent that holds one context's key and really signs.
    //!
    //! It answers the reads this module makes and `keys/sign-document` the way
    //! the real handler does — builds the `eddsa-jcs-2022` proof itself and
    //! signs as the document's own issuer or holder — so what comes back
    //! verifies for real. Each flag below breaks exactly one property, to drive
    //! the checks that refuse an answer the gateway did not ask for.

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Json, Router, extract::State, routing::post};
    use sha2::{Digest, Sha256};

    use super::*;

    #[derive(Clone)]
    pub(crate) struct MockContextVta {
        pub context_id: String,
        pub did: Option<String>,
        pub key_id: String,
        pub public_key: String,
        pub key_status: &'static str,
        signing: Arc<ed25519_dalek::SigningKey>,
        pub sign_calls: Arc<AtomicUsize>,
        pub last_sign_request: Arc<Mutex<Option<Value>>>,
        pub last_context_read: Arc<Mutex<Option<String>>>,
        pub echo_key_id: Arc<Mutex<Option<String>>>,
        pub tamper_document: Arc<Mutex<bool>>,
        pub refuse_signing: Arc<Mutex<bool>>,
    }

    impl MockContextVta {
        pub(crate) fn new(
            context_id: &str,
            key_id: &str,
        ) -> Self {
            let mut seed = [0u8; 32];
            seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            let mut multicodec = vec![0xed, 0x01];
            multicodec.extend_from_slice(
                signing
                    .verifying_key()
                    .as_bytes(),
            );
            let public_key = multibase::encode(multibase::Base::Base58Btc, &multicodec);
            Self {
                context_id: context_id.to_string(),
                did: Some(format!("did:key:{public_key}")),
                key_id: key_id.to_string(),
                public_key,
                key_status: "active",
                signing: Arc::new(signing),
                sign_calls: Arc::new(AtomicUsize::new(0)),
                last_sign_request: Arc::new(Mutex::new(None)),
                last_context_read: Arc::new(Mutex::new(None)),
                echo_key_id: Arc::new(Mutex::new(None)),
                tamper_document: Arc::new(Mutex::new(false)),
                refuse_signing: Arc::new(Mutex::new(false)),
            }
        }

        pub(crate) fn did(&self) -> String {
            self.did
                .clone()
                .expect("this mock context has a DID")
        }

        pub(crate) fn verification_method(&self) -> String {
            format!("{}#{}", self.did(), self.public_key)
        }

        pub(crate) fn sign_calls(&self) -> usize {
            self.sign_calls
                .load(Ordering::SeqCst)
        }

        pub(crate) async fn spawn(&self) -> String {
            let app = Router::new()
                .route("/trust-tasks", post(handle))
                .with_state(self.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener
                .local_addr()
                .expect("addr");
            tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .expect("serve");
            });
            format!("http://{addr}")
        }

        pub(crate) fn client(
            &self,
            url: &str,
        ) -> Arc<VtaRestClient> {
            Arc::new(
                VtaRestClient::new(
                    url,
                    "did:webvh:vta.example",
                    Arc::new(crate::vta::control_key::ControlKey::from_seed([7u8; 32])),
                    std::time::Duration::from_secs(5),
                    4,
                    None,
                )
                .expect("build client"),
            )
        }
    }

    async fn handle(
        State(vta): State<MockContextVta>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let type_uri = body
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let payload = body
            .get("payload")
            .cloned()
            .unwrap_or_default();
        if type_uri.contains("auth/challenge") {
            return Json(json!({ "challenge": "c", "sessionId": "s" }));
        }
        if type_uri.contains("auth/authenticate") {
            return Json(json!({
                "session": { "id": "s", "subject": body["issuer"] },
                "tokens": { "accessToken": "tok", "tokenType": "Bearer", "expiresIn": 3600 }
            }));
        }
        if type_uri.contains("contexts/get") {
            *vta.last_context_read
                .lock()
                .unwrap() = payload["id"]
                .as_str()
                .map(str::to_owned);
            let mut record = json!({ "id": vta.context_id, "name": "ctx", "baseDerivationPath": "m/26'/2'/1'" });
            if let Some(did) = &vta.did {
                record["did"] = json!(did);
            }
            return Json(json!({ "id": "urn:uuid:envelope", "payload": record }));
        }
        if type_uri.contains("keys/list") {
            return Json(json!({ "id": "urn:uuid:envelope", "payload": { "keys": [{
                "keyId": vta.key_id,
                "keyType": "ed25519",
                "status": vta.key_status,
                "publicKey": vta.public_key,
                "contextId": vta.context_id,
            }]}}));
        }
        if type_uri.contains("keys/sign-document") {
            vta.sign_calls
                .fetch_add(1, Ordering::SeqCst);
            *vta.last_sign_request
                .lock()
                .unwrap() = Some(payload.clone());
            if *vta
                .refuse_signing
                .lock()
                .unwrap()
            {
                return Json(json!({ "error": "keys:documentInvalid: noSigner" }));
            }
            let mut document = payload["document"].clone();
            let purpose = payload["proofPurpose"]
                .as_str()
                .unwrap_or("assertionMethod");
            // The proof is built here, as the real handler builds it: the
            // configuration carries the verification method, purpose and any
            // challenge or domain, and the signature covers
            // `SHA-256(JCS(config)) || SHA-256(JCS(document))`.
            let mut config = json!({
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "created": "2026-01-01T00:00:00Z",
                "verificationMethod": vta.verification_method(),
                "proofPurpose": purpose,
            });
            if let Some(context) = document.get("@context") {
                config["@context"] = context.clone();
            }
            if let Some(challenge) = payload["challenge"].as_str() {
                config["challenge"] = json!(challenge);
            }
            if let Some(domain) = payload["domain"].as_str() {
                config["domain"] = json!(domain);
            }
            let jcs = |value: &Value| serde_json_canonicalizer::to_string(value).expect("canonicalise");
            let mut hash_data = Vec::with_capacity(64);
            hash_data.extend_from_slice(&Sha256::digest(jcs(&config).as_bytes()));
            hash_data.extend_from_slice(&Sha256::digest(jcs(&document).as_bytes()));
            let signature = ed25519_dalek::Signer::sign(&*vta.signing, &hash_data);
            let mut proof = config;
            proof["proofValue"] = json!(multibase::encode(multibase::Base::Base58Btc, signature.to_bytes()));
            document["proof"] = proof.clone();
            if *vta
                .tamper_document
                .lock()
                .unwrap()
            {
                document["credentialSubject"] = json!({ "id": "did:key:zSomeoneElse" });
            }
            let echoed = vta
                .echo_key_id
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| vta.key_id.clone());
            return Json(json!({
                "id": "urn:uuid:envelope",
                "payload": {
                    "document": document,
                    "proof": proof,
                    "keyId": echoed,
                    "signerDid": vta.did(),
                }
            }));
        }
        if type_uri.contains("keys/sign-jws") {
            vta.sign_calls
                .fetch_add(1, Ordering::SeqCst);
            *vta.last_sign_request
                .lock()
                .unwrap() = Some(payload.clone());
            let mut header = payload["header"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            header.insert("alg".to_string(), json!("EdDSA"));
            let b64 = |bytes: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes);
            let signing_input = format!(
                "{}.{}",
                b64(&serde_json::to_vec(&Value::Object(header)).unwrap()),
                b64(&serde_json::to_vec(&payload["payload"]).unwrap()),
            );
            let signature = ed25519_dalek::Signer::sign(&*vta.signing, signing_input.as_bytes());
            return Json(json!({
                "id": "urn:uuid:envelope",
                "payload": {
                    "jws": format!("{signing_input}.{}", b64(&signature.to_bytes())),
                    "alg": "EdDSA",
                    "keyId": payload["keyId"],
                }
            }));
        }
        Json(json!({ "error": "unexpected task" }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::mock::MockContextVta;
    use super::*;

    fn credential(did: &str) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": did,
            "credentialSubject": { "id": "did:key:zAgent" },
        })
    }

    #[test]
    fn the_identity_is_the_did_and_the_active_ed25519_key_it_names() {
        let context = json!({ "did": "did:key:z6MkAbc" });
        let keys = json!({ "keys": [
            { "keyId": "other", "keyType": "ed25519", "status": "active", "publicKey": "z6MkOther" },
            { "keyId": "ctx-issuer", "keyType": "ed25519", "status": "active", "publicKey": "z6MkAbc" },
        ]});
        let identity = identity_from_records("ctx", &context, &keys).expect("an identity");
        assert_eq!(identity.did, "did:key:z6MkAbc");
        assert_eq!(identity.key_id, "ctx-issuer");
        assert_eq!(identity.verification_method, "did:key:z6MkAbc#z6MkAbc");
    }

    #[test]
    fn a_context_without_an_identity_is_refused_with_the_reason() {
        let keys =
            json!({ "keys": [{ "keyId": "k", "keyType": "ed25519", "status": "active", "publicKey": "z6MkAbc" }] });
        for (what, context, needle) in [
            ("no DID", json!({}), "no DID"),
            ("a did:web", json!({ "did": "did:web:example.com" }), "only a did:key"),
            ("a DID no key backs", json!({ "did": "did:key:z6MkNobody" }), "no active Ed25519 key"),
        ] {
            let err = identity_from_records("ctx", &context, &keys)
                .expect_err(what)
                .to_string();
            assert!(err.contains(needle), "{what}: {err}");
        }
    }

    #[test]
    fn a_revoked_or_non_ed25519_key_does_not_back_the_did() {
        let context = json!({ "did": "did:key:z6MkAbc" });
        for (status, key_type) in [("revoked", "ed25519"), ("active", "p256")] {
            let keys =
                json!({ "keys": [{ "keyId": "k", "keyType": key_type, "status": status, "publicKey": "z6MkAbc" }] });
            assert!(
                identity_from_records("ctx", &context, &keys).is_err(),
                "a {status} {key_type} key must not be the context's identity"
            );
        }
    }

    #[tokio::test]
    async fn a_document_is_signed_as_the_context_and_the_proof_is_the_one_that_verifies() {
        let vta = MockContextVta::new("gw/ctx", "ctx-issuer");
        let url = vta.spawn().await;
        let resolver = ContextIdentityResolver::new(vta.client(&url), "gw/ctx".to_string());

        let signed = resolver
            .sign_document(credential(&vta.did()), PURPOSE_ASSERTION_METHOD, None, None)
            .await
            .expect("signed");

        assert_eq!(signed["proof"]["verificationMethod"], json!(vta.verification_method()));
        assert_eq!(signed["proof"]["proofPurpose"], json!("assertionMethod"));
        assert_eq!(signed["proof"]["cryptosuite"], json!("eddsa-jcs-2022"));
        let request = vta
            .last_sign_request
            .lock()
            .unwrap()
            .clone()
            .expect("a request");
        assert_eq!(request["keyId"], json!("ctx-issuer"), "the key is named, resolved from the context");
        assert!(
            request
                .get("challenge")
                .is_none()
                && request
                    .get("domain")
                    .is_none()
        );
    }

    /// The proof the mock builds is accepted by the library the gateway verifies
    /// with — so the other tests, which sign through the mock, are not testing
    /// a proof no verifier would accept.
    #[tokio::test]
    async fn the_proof_verifies_with_the_gateways_own_library() {
        let vta = MockContextVta::new("gw/ctx", "ctx-issuer");
        let url = vta.spawn().await;
        let resolver = ContextIdentityResolver::new(vta.client(&url), "gw/ctx".to_string());

        let signed = resolver
            .sign_document(credential(&vta.did()), PURPOSE_ASSERTION_METHOD, None, None)
            .await
            .expect("signed");

        let proof: affinidi_data_integrity::DataIntegrityProof =
            serde_json::from_value(signed["proof"].clone()).expect("proof deserialises");
        let mut unsigned = signed.clone();
        unsigned
            .as_object_mut()
            .unwrap()
            .remove("proof");
        let (_, public) = multibase::decode(&vta.public_key).expect("multibase");
        proof
            .verify_with_public_key(&unsigned, &public[2..], affinidi_data_integrity::VerifyOptions::default())
            .expect("the proof must verify");
    }

    #[tokio::test]
    async fn a_challenge_and_domain_are_carried_into_the_proof() {
        let vta = MockContextVta::new("gw/ctx", "ctx-issuer");
        let url = vta.spawn().await;
        let resolver = ContextIdentityResolver::new(vta.client(&url), "gw/ctx".to_string());

        let signed = resolver
            .sign_document(credential(&vta.did()), PURPOSE_AUTHENTICATION, Some("nonce-123"), Some("verifier.example"))
            .await
            .expect("signed");

        assert_eq!(signed["proof"]["challenge"], json!("nonce-123"));
        assert_eq!(signed["proof"]["domain"], json!("verifier.example"));
        assert_eq!(signed["proof"]["proofPurpose"], json!("authentication"));
    }

    #[tokio::test]
    async fn a_response_echoing_a_different_key_is_refused() {
        let vta = MockContextVta::new("gw/ctx", "ctx-issuer");
        *vta.echo_key_id
            .lock()
            .unwrap() = Some("some-other-key".to_string());
        let url = vta.spawn().await;
        let resolver = ContextIdentityResolver::new(vta.client(&url), "gw/ctx".to_string());

        let err = resolver
            .sign_document(credential(&vta.did()), PURPOSE_ASSERTION_METHOD, None, None)
            .await
            .expect_err("an attribution mismatch must not yield a document")
            .to_string();
        assert!(err.contains("some-other-key"), "{err}");
    }

    #[tokio::test]
    async fn a_document_changed_in_transit_is_refused() {
        let vta = MockContextVta::new("gw/ctx", "ctx-issuer");
        *vta.tamper_document
            .lock()
            .unwrap() = true;
        let url = vta.spawn().await;
        let resolver = ContextIdentityResolver::new(vta.client(&url), "gw/ctx".to_string());

        let err = resolver
            .sign_document(credential(&vta.did()), PURPOSE_ASSERTION_METHOD, None, None)
            .await
            .expect_err("a document that is not the one sent must not be passed on")
            .to_string();
        assert!(err.contains("not the document that was sent"), "{err}");
    }

    #[tokio::test]
    async fn the_identity_is_resolved_once() {
        let vta = MockContextVta::new("gw/ctx", "ctx-issuer");
        let url = vta.spawn().await;
        let resolver = ContextIdentityResolver::new(vta.client(&url), "gw/ctx".to_string());

        let first = resolver
            .identity()
            .await
            .expect("identity");
        let second = resolver
            .identity()
            .await
            .expect("identity");
        assert_eq!(first, second);
        for _ in 0..2 {
            resolver
                .sign_document(credential(&vta.did()), PURPOSE_ASSERTION_METHOD, None, None)
                .await
                .expect("signed");
        }
        assert_eq!(
            vta.sign_calls
                .load(Ordering::SeqCst),
            2
        );
    }

    #[tokio::test]
    async fn an_unreachable_agent_is_an_error_and_never_a_fallback() {
        let vta = MockContextVta::new("gw/ctx", "ctx-issuer");
        let resolver = ContextIdentityResolver::new(vta.client("http://127.0.0.1:1"), "gw/ctx".to_string());
        assert!(
            resolver
                .identity()
                .await
                .is_err()
        );
        assert!(
            resolver
                .sign_document(credential("did:key:zX"), PURPOSE_ASSERTION_METHOD, None, None)
                .await
                .is_err()
        );
    }
}
