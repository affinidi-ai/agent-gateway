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
}

#[derive(Debug)]
struct AgentState {
    behaviour: Behaviour,
    keys: Vec<Value>,
    creates: usize,
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
    if task.contains("auth/challenge") {
        return Json(json!({ "challenge": "c", "sessionId": "s" })).into_response();
    }
    if task.contains("auth/authenticate") {
        if agent.behaviour == Behaviour::Refusing {
            return (StatusCode::FORBIDDEN, Json(json!({ "payload": { "code": "permissionDenied" } }))).into_response();
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
    if task.contains("keys/list") {
        return Json(json!({ "payload": { "keys": agent.keys } })).into_response();
    }
    if task.contains("keys/create") {
        agent.creates += 1;
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

impl MockTrustAgent {
    pub async fn start(behaviour: Behaviour) -> Self {
        let state = Arc::new(Mutex::new(AgentState {
            behaviour,
            keys: Vec::new(),
            creates: 0,
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

    pub fn signing_keys_created(&self) -> usize {
        self.state
            .lock()
            .expect("mock trust agent state")
            .creates
    }
}
