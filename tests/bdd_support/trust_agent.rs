//! A mock bundled trust agent, in the test process, for scenarios about the
//! gateway's first-start bootstrap.
//!
//! It answers what the gateway asks of a trust agent while connecting: a health
//! check, the authentication handshake, `auth/whoami`, and the key listing and
//! creation. It can behave as a sidecar that enrolled the gateway, one that
//! refuses it, or one that granted something other than the bundled grant. The
//! sidecar's published identity lives in a shared folder, as it does in a real
//! deployment.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub const TRUST_AGENT_DID: &str = "did:key:z6MkvnxZrB5vsAFb8AGaDVAqSYYNoz5y2Rgvhccn7xSvx3Aj";

/// What the mock does when the gateway talks to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// Enrolled the gateway with exactly the bundled grant.
    Enrolled,
    /// Never enrolled the gateway: authentication is refused.
    Refusing,
    /// Enrolled the gateway as an administrator that may export keys.
    OverPrivileged,
    /// Enrolled the gateway with exactly the bundled grant, but refuses to move
    /// its access entry to another key.
    RefusingSwap,
}

#[derive(Debug)]
struct AgentState {
    behaviour: Behaviour,
    keys: Vec<Value>,
    creates: usize,
    context_did: Option<String>,
    /// The one DID the gateway is enrolled as. The first DID to authenticate is
    /// taken to be the one the sidecar's start-up script enrolled.
    entry: Option<String>,
    swaps: Vec<(String, String)>,
    refused: usize,
}

#[derive(Debug)]
pub struct MockTrustAgent {
    pub url: String,
    pub bootstrap_dir: tempfile::TempDir,
    state: Arc<Mutex<AgentState>>,
    server: JoinHandle<()>,
}

impl Drop for MockTrustAgent {
    fn drop(&mut self) {
        self.server.abort();
    }
}

type Shared = Arc<Mutex<AgentState>>;

async fn health() -> &'static str {
    "ok"
}

async fn trust_tasks(
    State(state): State<Shared>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    let task = body["type"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let mut agent = state
        .lock()
        .expect("mock trust agent state");
    let issuer = body["issuer"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if task.contains("auth/challenge") {
        return Json(json!({ "challenge": "c", "sessionId": "s" })).into_response();
    }
    if task.contains("auth/authenticate") {
        if agent.behaviour == Behaviour::Refusing {
            return (StatusCode::FORBIDDEN, Json(json!({ "payload": { "code": "permissionDenied" } }))).into_response();
        }
        match &agent.entry {
            None => agent.entry = Some(issuer),
            Some(entry) if *entry != issuer => {
                agent.refused += 1;
                return (StatusCode::FORBIDDEN, Json(json!({ "payload": { "code": "permissionDenied" } })))
                    .into_response();
            }
            Some(_) => {}
        }
        return Json(json!({ "session": { "id": "s" }, "tokens": { "accessToken": "t", "expiresIn": 3600 } }))
            .into_response();
    }
    if task.contains("auth/whoami") {
        let (role, capabilities) = match agent.behaviour {
            Behaviour::OverPrivileged => {
                ("admin", vec!["context-create", "key-mint", "sign-jws", "sign-document", "key-export"])
            }
            _ => ("initiator", vec!["context-create", "key-mint", "sign-jws", "sign-document"]),
        };
        return Json(json!({ "payload": {
            "roles": [role], "scopes": ["ctx:gateway"], "capabilities": capabilities,
        } }))
        .into_response();
    }
    if task.contains("acl/swap-key") {
        let payload = &body["payload"];
        let current = payload["currentSubject"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let new = payload["newSubject"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let denied = || (StatusCode::FORBIDDEN, Json(json!({ "payload": { "code": "permissionDenied" } })));
        if agent.behaviour == Behaviour::RefusingSwap
            || agent.entry.as_deref() != Some(current.as_str())
            || issuer != current
            || body.get("proof").is_none()
            || link_proof_is_valid(
                payload["linkProof"]
                    .as_str()
                    .unwrap_or_default(),
                &new,
            )
            .is_err()
        {
            return denied().into_response();
        }
        agent.entry = Some(new.clone());
        agent
            .swaps
            .push((current.clone(), new.clone()));
        return Json(json!({ "payload": { "entry": { "subject": new }, "previousSubject": current } })).into_response();
    }
    if task.contains("keys/list") {
        return Json(json!({ "payload": { "keys": agent.keys } })).into_response();
    }
    if task.contains("contexts/get") {
        return Json(json!({ "payload": { "id": "gateway", "did": agent.context_did } })).into_response();
    }
    if task.contains("contexts/update-did") {
        agent.context_did = body["payload"]["did"]
            .as_str()
            .map(str::to_string);
        return Json(json!({ "payload": { "id": "gateway" } })).into_response();
    }
    if task.contains("keys/create") {
        if !body["payload"]["keyId"]
            .as_str()
            .is_some_and(|id| id.ends_with("-issuer"))
        {
            agent.creates += 1;
        }
        let record = json!({
            "keyId": body["payload"]["keyId"], "keyType": "ed25519", "status": "active",
            "publicKey": "z6MkBddMintedPublicKey",
        });
        agent
            .keys
            .push(record.clone());
        return Json(json!({ "payload": { "key": record } })).into_response();
    }
    (StatusCode::BAD_REQUEST, Json(json!({ "error": "unexpected task" }))).into_response()
}

/// What a real trust agent checks before it lets a key take over an access
/// entry: the proof is for this trust agent, is current, and is signed by the
/// new key itself.
fn link_proof_is_valid(
    proof: &str,
    new_subject: &str,
) -> Result<(), String> {
    use base64::Engine;
    use ed25519_dalek::Verifier;
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err("not a compact JWS".to_string());
    }
    let decode = |part: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|e| e.to_string())
    };
    let payload: Value = serde_json::from_slice(&decode(parts[1])?).map_err(|e| e.to_string())?;
    if payload["aud"] != TRUST_AGENT_DID {
        return Err("not for this trust agent".to_string());
    }
    let now = chrono::Utc::now().timestamp() as u64;
    if payload["exp"]
        .as_u64()
        .unwrap_or(0)
        <= now
    {
        return Err("expired".to_string());
    }
    if payload["iss"] != new_subject || payload["vp"]["holder"] != new_subject {
        return Err("not by the new subject".to_string());
    }
    let (_, key_bytes) = multibase::decode(
        new_subject
            .strip_prefix("did:key:")
            .ok_or("not a did:key")?,
    )
    .map_err(|e| e.to_string())?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(
        key_bytes[2..]
            .try_into()
            .map_err(|_| "key length".to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let signature = ed25519_dalek::Signature::from_slice(&decode(parts[2])?).map_err(|e| e.to_string())?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|e| e.to_string())
}

impl MockTrustAgent {
    pub async fn start(behaviour: Behaviour) -> Self {
        let state = Arc::new(Mutex::new(AgentState {
            behaviour,
            keys: Vec::new(),
            creates: 0,
            context_did: None,
            entry: None,
            swaps: Vec::new(),
            refused: 0,
        }));
        let app = Router::new()
            .route("/health", get(health))
            .route("/trust-tasks", post(trust_tasks))
            .with_state(Arc::clone(&state));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the mock trust agent");
        let url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("local address")
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            url,
            bootstrap_dir: tempfile::tempdir().expect("a bootstrap folder"),
            state,
            server,
        }
    }

    pub fn bootstrap_path(&self) -> PathBuf {
        self.bootstrap_dir
            .path()
            .to_path_buf()
    }

    /// The sidecar publishes its own DID for the gateway to pin.
    pub fn publish_identity(&self) {
        let text = format!("FORMAT=1\nVTA_DID={TRUST_AGENT_DID}\nBASE_URL=http://127.0.0.1:8100\n");
        std::fs::write(
            self.bootstrap_path()
                .join("vta-identity.env"),
            text,
        )
        .expect("publish the identity");
    }

    pub fn context_identity(&self) -> Option<String> {
        self.state
            .lock()
            .expect("mock trust agent state")
            .context_did
            .clone()
    }

    pub fn signing_keys_created(&self) -> usize {
        self.state
            .lock()
            .expect("mock trust agent state")
            .creates
    }

    /// The DID the trust agent currently knows the gateway by.
    pub fn gateway_entry(&self) -> Option<String> {
        self.state
            .lock()
            .expect("mock trust agent state")
            .entry
            .clone()
    }

    /// Every `(from, to)` move of the gateway's access entry.
    pub fn swaps(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .expect("mock trust agent state")
            .swaps
            .clone()
    }

    /// How many sign-ins were refused because they came from a DID that no
    /// longer holds the entry.
    pub fn refused_sign_ins(&self) -> usize {
        self.state
            .lock()
            .expect("mock trust agent state")
            .refused
    }
}
