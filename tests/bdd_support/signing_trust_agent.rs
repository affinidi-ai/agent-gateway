//! A mock trust agent, in the test process, that really signs.
//!
//! It holds one context and one Ed25519 key, and the context signs as the
//! `did:key` of that key. It answers the authentication handshake with a
//! session token scoped to that context, the key and context reads, and
//! `keys/sign-jws` and `keys/sign-document` the way the real agent does, so
//! what the gateway hands out verifies against the key only this mock holds.
//! Stopping it leaves the gateway with an agent it cannot reach.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub const SIGNING_TRUST_AGENT_DID: &str = "did:key:z6MkhSigningTrustAgentForSignedResultScenarios000";

#[derive(Debug)]
struct Agent {
    context_id: String,
    key_id: String,
    signing: SigningKey,
    public_multibase: String,
}

impl Agent {
    fn did(&self) -> String {
        format!("did:key:{}", self.public_multibase)
    }

    fn verification_method(&self) -> String {
        format!("{}#{}", self.did(), self.public_multibase)
    }

    fn key_record(&self) -> Value {
        json!({
            "keyId": self.key_id, "keyType": "ed25519", "status": "active",
            "publicKey": self.public_multibase, "contextId": self.context_id,
        })
    }
}

#[derive(Debug)]
pub struct SigningTrustAgent {
    pub url: String,
    agent: Arc<Agent>,
    server: JoinHandle<()>,
}

impl Drop for SigningTrustAgent {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn jcs(value: &Value) -> String {
    serde_json_canonicalizer::to_string(value).expect("canonical JSON")
}

fn eddsa_jcs_hash(
    config: &Value,
    document: &Value,
) -> Vec<u8> {
    let mut hash = Sha256::digest(jcs(config).as_bytes()).to_vec();
    hash.extend(Sha256::digest(jcs(document).as_bytes()));
    hash
}

async fn health() -> &'static str {
    "ok"
}

fn answer(payload: Value) -> axum::response::Response {
    Json(json!({ "payload": payload })).into_response()
}

fn sign_jws(
    agent: &Agent,
    request: &Value,
) -> Value {
    let mut header = request["header"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    header.insert("alg".to_string(), json!("EdDSA"));
    let input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(&Value::Object(header)).expect("header")),
        b64(&serde_json::to_vec(&request["payload"]).expect("payload")),
    );
    let signature = agent
        .signing
        .sign(input.as_bytes());
    json!({ "jws": format!("{input}.{}", b64(&signature.to_bytes())), "alg": "EdDSA", "keyId": agent.key_id })
}

fn sign_document(
    agent: &Agent,
    request: &Value,
) -> Value {
    let mut document = request["document"].clone();
    let mut proof = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "created": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "verificationMethod": agent.verification_method(),
        "proofPurpose": request["proofPurpose"].as_str().unwrap_or("assertionMethod"),
    });
    if let Some(context) = document.get("@context") {
        proof["@context"] = context.clone();
    }
    for member in ["challenge", "domain"] {
        if let Some(value) = request[member].as_str() {
            proof[member] = json!(value);
        }
    }
    let signature = agent
        .signing
        .sign(&eddsa_jcs_hash(&proof, &document));
    proof["proofValue"] = json!(multibase::encode(multibase::Base::Base58Btc, signature.to_bytes()));
    document["proof"] = proof.clone();
    json!({ "document": document, "proof": proof, "keyId": agent.key_id, "signerDid": agent.did() })
}

async fn trust_tasks(
    State(agent): State<Arc<Agent>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let task = body["type"]
        .as_str()
        .unwrap_or_default();
    let request = &body["payload"];
    if task.contains("auth/challenge") {
        return Json(json!({ "challenge": "c", "sessionId": "s" })).into_response();
    }
    if task.contains("auth/authenticate") {
        let claims = json!({ "role": "initiator", "contexts": [agent.context_id] });
        let token = format!("h.{}.s", b64(claims.to_string().as_bytes()));
        return Json(json!({ "session": { "id": "s" }, "tokens": { "accessToken": token, "expiresIn": 3600 } }))
            .into_response();
    }
    if task.contains("auth/whoami") {
        return answer(json!({
            "roles": ["initiator"], "scopes": [format!("ctx:{}", agent.context_id)],
            "capabilities": ["sign-jws", "sign-document"],
        }));
    }
    if task.contains("contexts/get") {
        return answer(json!({ "id": agent.context_id, "did": agent.did() }));
    }
    if task.contains("keys/list") {
        return answer(json!({ "keys": [agent.key_record()] }));
    }
    if task.contains("keys/show") && request["keyId"] == agent.key_id {
        return answer(json!({ "key": agent.key_record() }));
    }
    if task.contains("keys/sign-jws") && request["keyId"] == agent.key_id {
        return answer(sign_jws(&agent, request));
    }
    if task.contains("keys/sign-document") && request["keyId"] == agent.key_id {
        return answer(sign_document(&agent, request));
    }
    (StatusCode::BAD_REQUEST, Json(json!({ "error": "unexpected task" }))).into_response()
}

impl SigningTrustAgent {
    pub async fn start(
        context_id: &str,
        key_id: &str,
    ) -> Self {
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let signing = SigningKey::from_bytes(&seed);
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(
            signing
                .verifying_key()
                .as_bytes(),
        );
        let agent = Arc::new(Agent {
            context_id: context_id.to_string(),
            key_id: key_id.to_string(),
            public_multibase: multibase::encode(multibase::Base::Base58Btc, &multicodec),
            signing,
        });
        let app = Router::new()
            .route("/health", get(health))
            .route("/trust-tasks", post(trust_tasks))
            .with_state(Arc::clone(&agent));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the mock signing trust agent");
        let url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("local address")
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { url, agent, server }
    }

    /// Stop answering: the gateway can no longer reach this trust agent.
    pub fn stop(&self) {
        self.server.abort();
    }

    pub fn context_id(&self) -> &str {
        &self.agent.context_id
    }

    pub fn key_id(&self) -> &str {
        &self.agent.key_id
    }

    /// The DID the context signs as: the `did:key` of the key it holds.
    pub fn context_did(&self) -> String {
        self.agent.did()
    }

    pub fn verification_method(&self) -> String {
        self.agent
            .verification_method()
    }

    /// The public key as the `x` of an Ed25519 JWK.
    pub fn public_jwk_x(&self) -> String {
        b64(self
            .agent
            .signing
            .verifying_key()
            .as_bytes())
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.agent
            .signing
            .verifying_key()
    }

    /// Whether a compact JWS was signed by this agent's key.
    pub fn signed_jws(
        &self,
        jws: &str,
    ) -> bool {
        let parts: Vec<&str> = jws.split('.').collect();
        let [header, payload, signature] = parts[..] else {
            return false;
        };
        let Ok(signature) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signature) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature) else {
            return false;
        };
        self.verifying_key()
            .verify(format!("{header}.{payload}").as_bytes(), &signature)
            .is_ok()
    }

    /// Whether a document carries an `eddsa-jcs-2022` proof made by this
    /// agent's key over exactly its content.
    pub fn proved_document(
        &self,
        document: &Value,
    ) -> bool {
        let Some(proof) = document.get("proof") else {
            return false;
        };
        let Some(Ok((_, signature))) = proof["proofValue"]
            .as_str()
            .map(multibase::decode)
        else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature) else {
            return false;
        };
        let mut unsecured = document.clone();
        unsecured
            .as_object_mut()
            .map(|members| members.remove("proof"));
        let mut config = proof.clone();
        config
            .as_object_mut()
            .map(|members| members.remove("proofValue"));
        self.verifying_key()
            .verify(&eddsa_jcs_hash(&config, &unsecured), &signature)
            .is_ok()
    }
}
