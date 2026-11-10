//! A mock custom trust agent, in the test process, for scenarios about the
//! control key of a connection an operator added.
//!
//! It behaves as the real one does where that matters to a key rotation: on
//! every authentication it fetches the gateway's published `did.jsonl`, finds
//! the verification method the proof names among the document's
//! `authentication` keys, and checks the proof's signature against that key. A
//! DID that was never granted is refused, and a DID that signs in again ends
//! the session it had, so a call on the old token answers `token superseded`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub const CUSTOM_TRUST_AGENT_DID: &str = "did:key:z6MkfCustomTrustAgentForKeyRotationScenarios00000";

#[derive(Debug, Default)]
struct AgentState {
    gateway_root: Option<String>,
    granted: HashSet<String>,
    sessions: HashMap<String, String>,
    counter: u64,
    only_accepts: Option<String>,
    signed_in: Vec<(String, String)>,
    refused: Vec<String>,
}

#[derive(Debug)]
pub struct CustomTrustAgent {
    pub url: String,
    state: Arc<Mutex<AgentState>>,
    server: JoinHandle<()>,
}

impl Drop for CustomTrustAgent {
    fn drop(&mut self) {
        self.server.abort();
    }
}

type Shared = Arc<Mutex<AgentState>>;

async fn health() -> &'static str {
    "ok"
}

fn connection_id_of(did: &str) -> Option<String> {
    did.split(':')
        .next_back()
        .map(str::to_string)
}

fn jcs(value: &Value) -> String {
    serde_json_canonicalizer::to_string(value).expect("canonical JSON")
}

/// The `eddsa-jcs-2022` check the real trust agent makes.
fn proof_verifies(
    document: &Value,
    public_multibase: &str,
) -> bool {
    use ed25519_dalek::Verifier;
    let Some(proof) = document.get("proof") else {
        return false;
    };
    let Some(proof_value) = proof["proofValue"].as_str() else {
        return false;
    };
    let mut unsecured = document.clone();
    unsecured
        .as_object_mut()
        .map(|o| o.remove("proof"));
    let mut config = proof.clone();
    config
        .as_object_mut()
        .map(|o| o.remove("proofValue"));
    let mut hash = Sha256::digest(jcs(&config).as_bytes()).to_vec();
    hash.extend(Sha256::digest(jcs(&unsecured).as_bytes()));
    let Ok((_, signature)) = multibase::decode(proof_value) else {
        return false;
    };
    let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature) else {
        return false;
    };
    let Ok((_, key)) = multibase::decode(public_multibase) else {
        return false;
    };
    let Some(key) = key
        .get(2..)
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
    else {
        return false;
    };
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map(|k| {
            k.verify(&hash, &signature)
                .is_ok()
        })
        .unwrap_or(false)
}

/// The keys the newest entry of a published log declares for authentication, as
/// `(fragment, publicKeyMultibase)`.
fn keys_declared(log: &str) -> Vec<(String, String)> {
    let Some(last) = log
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str::<Value>(l).ok())
    else {
        return Vec::new();
    };
    let state = &last["state"];
    let authenticating: Vec<String> = state["authentication"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    state["verificationMethod"]
        .as_array()
        .map(|methods| {
            methods
                .iter()
                .filter_map(|m| {
                    let id = m["id"].as_str()?;
                    authenticating
                        .iter()
                        .any(|a| a == id)
                        .then(|| {
                            (
                                id.rsplit('#')
                                    .next()
                                    .unwrap_or_default()
                                    .to_string(),
                                m["publicKeyMultibase"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_string(),
                            )
                        })
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn fetch_log(
    root: &str,
    did: &str,
) -> Option<String> {
    let id = connection_id_of(did)?;
    reqwest::get(format!("{root}/vta-auth/{id}/did.jsonl"))
        .await
        .ok()?
        .text()
        .await
        .ok()
}

fn denied(code: &str) -> axum::response::Response {
    (StatusCode::FORBIDDEN, Json(json!({ "payload": { "code": code } }))).into_response()
}

async fn trust_tasks(
    State(state): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let task = body["type"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let issuer = body["issuer"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    if task.contains("auth/challenge") {
        return Json(json!({ "challenge": "c", "sessionId": "s" })).into_response();
    }

    if task.contains("auth/authenticate") {
        let (root, granted) = {
            let s = state
                .lock()
                .expect("mock state");
            (s.gateway_root.clone(), s.granted.contains(&issuer))
        };
        if !granted {
            return denied("permissionDenied");
        }
        let Some(log) = fetch_log(
            root.as_deref()
                .unwrap_or_default(),
            &issuer,
        )
        .await
        else {
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "payload": { "code": "didUnresolvable" } })))
                .into_response();
        };
        let method = body["proof"]["verificationMethod"]
            .as_str()
            .unwrap_or_default();
        let fragment = method
            .rsplit('#')
            .next()
            .unwrap_or_default()
            .to_string();
        let declared = keys_declared(&log);
        let public = declared
            .iter()
            .find(|(f, _)| *f == fragment)
            .map(|(_, mb)| mb.clone());
        let mut s = state
            .lock()
            .expect("mock state");
        let accepted = public
            .as_deref()
            .is_some_and(|mb| proof_verifies(&body, mb))
            && s.only_accepts
                .as_deref()
                .is_none_or(|only| only == fragment);
        if !accepted {
            s.refused.push(fragment);
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "payload": { "code": "proofInvalid" } })))
                .into_response();
        }
        s.counter += 1;
        let claims = json!({ "role": "initiator", "contexts": ["custom"], "n": s.counter });
        let token =
            format!("h.{}.s{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string()), s.counter);
        s.sessions
            .insert(issuer.clone(), token.clone());
        s.signed_in
            .push((issuer, fragment));
        return Json(json!({ "session": { "id": "s" }, "tokens": { "accessToken": token, "expiresIn": 3600 } }))
            .into_response();
    }

    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_string();
    let current = state
        .lock()
        .expect("mock state")
        .sessions
        .get(&issuer)
        .cloned();
    if current.as_deref() != Some(bearer.as_str()) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized: token superseded" }))).into_response();
    }
    if task.contains("auth/whoami") {
        return Json(json!({ "payload": {
            "roles": ["initiator"], "scopes": ["ctx:custom"],
            "capabilities": ["context-create", "key-mint", "sign-jws", "sign-document"],
        } }))
        .into_response();
    }
    (StatusCode::BAD_REQUEST, Json(json!({ "error": "unexpected task" }))).into_response()
}

impl CustomTrustAgent {
    pub async fn start() -> Self {
        let state: Shared = Arc::default();
        let app = Router::new()
            .route("/health", get(health))
            .route("/trust-tasks", post(trust_tasks))
            .with_state(Arc::clone(&state));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the mock custom trust agent");
        let url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("local address")
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { url, state, server }
    }

    /// Where the agent reads the gateway's published DIDs from.
    pub fn read_dids_from(
        &self,
        gateway_root: &str,
    ) {
        self.state
            .lock()
            .expect("mock state")
            .gateway_root = Some(gateway_root.to_string());
    }

    /// The operator granted this DID on the trust agent.
    pub fn grant(
        &self,
        did: &str,
    ) {
        self.state
            .lock()
            .expect("mock state")
            .granted
            .insert(did.to_string());
    }

    /// Accept sign-ins only as this verification method fragment: a trust agent
    /// that does not take a new key.
    pub fn only_accept(
        &self,
        fragment: &str,
    ) {
        self.state
            .lock()
            .expect("mock state")
            .only_accepts = Some(fragment.to_string());
    }

    /// The fragment of the key the gateway last signed in with.
    pub fn last_signed_in_as(&self) -> Option<String> {
        self.state
            .lock()
            .expect("mock state")
            .signed_in
            .last()
            .map(|(_, f)| f.clone())
    }

    pub fn refused_fragments(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("mock state")
            .refused
            .clone()
    }

    /// Resolve the published DID of `did` now and list the fragments it
    /// declares for authentication.
    pub async fn published_fragments(
        &self,
        did: &str,
    ) -> Vec<String> {
        let root = self
            .state
            .lock()
            .expect("mock state")
            .gateway_root
            .clone()
            .unwrap_or_default();
        let log = fetch_log(&root, did)
            .await
            .unwrap_or_default();
        keys_declared(&log)
            .into_iter()
            .map(|(f, _)| f)
            .collect()
    }
}
