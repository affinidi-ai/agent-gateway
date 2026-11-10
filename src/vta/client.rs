//! Thin REST/Trust-Task **client** of the VTA (`POST {base_url}/trust-tasks`).
//!
//! The gateway and VTA are separate services; this client speaks the VTA's HTTP
//! Trust-Task surface with the gateway's own `reqwest` stack — it does **not**
//! link `vta-sdk`. It performs the DI-signed auth handshake
//! (`auth/challenge/0.1` → `auth/authenticate/0.3`), caches the session tokens
//! **in memory only**, and dispatches further Trust Tasks with the bearer token.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::control_key::{ControlKeyReloader, SignerKeyProvider};
use super::di_proof::{PROOF_PURPOSE_AUTHENTICATION, sign_document};
use super::error::VtaError;
use super::onboarding::OnboardingState;
use super::resilience::Resilience;
use super::transport::{HttpsTransport, TrustTaskTransport};
use super::wire::{AuthenticateResponse, ChallengeResponse};
use zeroize::Zeroizing;

pub(crate) const TRUST_TASKS_PATH: &str = "/trust-tasks";
const TASK_AUTH_CHALLENGE: &str = "https://trusttasks.org/spec/auth/challenge/0.1";
const TASK_AUTH_AUTHENTICATE: &str = "https://trusttasks.org/spec/auth/authenticate/0.3";
const TASK_AUTH_WHOAMI: &str = "https://trusttasks.org/spec/auth/whoami/0.1";

/// A cached, memory-only session. Tokens never touch disk, are **zeroized** when
/// this value is dropped (re-auth replaces it), and carry no `Debug`.
struct Session {
    /// Zeroized on drop so a rotated token does not linger in freed heap.
    access_token: Zeroizing<String>,
    /// Monotonic instant after which the access token is treated as expired.
    expires_at: Instant,
    /// The control key this session was opened with, and which generation of
    /// the client's key that was: a call signs with the key its token belongs
    /// to, even if the key is replaced while the call is being built.
    generation: u64,
    key: Arc<dyn SignerKeyProvider>,
}

/// Thin VTA Trust-Task client. One per configured VTA.
///
/// Carrier-agnostic: the auth handshake, session caching, resilience and error
/// redaction all sit above [`TrustTaskTransport`], so a connection reached over
/// DIDComm behaves identically to one reached over HTTPS (VTA-27).
pub struct VtaRestClient {
    transport: Arc<dyn TrustTaskTransport>,
    vta_did: String,
    /// The current control key and its generation. Replaced when the gateway
    /// rotates its control key; never held across an `.await`.
    control: std::sync::RwLock<(u64, Arc<dyn SignerKeyProvider>)>,
    session: RwLock<Option<Session>>,
    /// Back-pressure + circuit breaker so a slow/hung VTA fails fast (VTA-04).
    resilience: Resilience,
    /// Customer-sovereign onboarding checks run after the first auth (VTA-05).
    onboarding: Option<OnboardingState>,
    /// Asked for a newer control key when the trust agent refuses this one.
    key_reloader: Option<Arc<dyn ControlKeyReloader>>,
    /// Treat the access token as expired this many seconds early, so a call
    /// started just before expiry does not race the VTA's own clock.
    expiry_skew: Duration,
}

impl VtaRestClient {
    /// Build a client for `base_url` with a per-call `timeout`, authenticating
    /// as `control_key` to the VTA identified by `vta_did`. `max_concurrent`
    /// bounds in-flight VTA calls; `onboarding` (optional) runs the VTA-05
    /// grant-scope + record checks after the first authentication.
    pub fn new(
        base_url: &str,
        vta_did: &str,
        control_key: Arc<dyn SignerKeyProvider>,
        timeout: Duration,
        max_concurrent: usize,
        onboarding: Option<OnboardingState>,
    ) -> Result<Self, VtaError> {
        Ok(Self::with_transport(
            Arc::new(HttpsTransport::new(base_url, timeout)?),
            vta_did,
            control_key,
            max_concurrent,
            onboarding,
        ))
    }

    /// Build a client over an explicit carrier (VTA-27). Everything above the
    /// carrier is identical, which is what makes transport a per-connection
    /// choice rather than a code path.
    pub fn with_transport(
        transport: Arc<dyn TrustTaskTransport>,
        vta_did: &str,
        control_key: Arc<dyn SignerKeyProvider>,
        max_concurrent: usize,
        onboarding: Option<OnboardingState>,
    ) -> Self {
        Self {
            transport,
            vta_did: vta_did.to_string(),
            control: std::sync::RwLock::new((0, control_key)),
            session: RwLock::new(None),
            resilience: Resilience::new(max_concurrent),
            onboarding,
            key_reloader: None,
            expiry_skew: Duration::from_secs(30),
        }
    }

    /// Ask `reloader` for the stored control key when the trust agent refuses
    /// the one this client holds, and try once more if it is a different one.
    pub fn with_key_reloader(
        mut self,
        reloader: Arc<dyn ControlKeyReloader>,
    ) -> Self {
        self.key_reloader = Some(reloader);
        self
    }

    /// The carrier this client is using, for metrics and diagnostics.
    pub fn carrier(&self) -> &'static str {
        self.transport.carrier()
    }

    fn current_control(&self) -> (u64, Arc<dyn SignerKeyProvider>) {
        let guard = self
            .control
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (guard.0, Arc::clone(&guard.1))
    }

    /// The DID this client currently authenticates as.
    pub fn control_did(&self) -> String {
        self.current_control()
            .1
            .did()
            .to_string()
    }

    /// Authenticate as `key` from now on.
    ///
    /// The cached session is dropped (its token is zeroized), so the next call
    /// opens a new one as the new DID, and the onboarding check runs again so
    /// the recorded control DID follows the key.
    pub async fn replace_control_key(
        &self,
        key: Arc<dyn SignerKeyProvider>,
    ) {
        {
            let mut guard = self
                .control
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.0 += 1;
            guard.1 = key;
        }
        *self.session.write().await = None;
        if let Some(onboarding) = &self.onboarding {
            onboarding.reset_verified();
        }
    }

    /// Build an unsigned Trust Task document (no `proof`).
    fn build_doc(
        &self,
        issuer: &str,
        type_uri: &str,
        payload: Value,
    ) -> Value {
        json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": type_uri,
            "issuer": issuer,
            "recipient": self.vta_did,
            "issuedAt": chrono::Utc::now().to_rfc3339(),
            "payload": payload,
        })
    }

    /// POST a Trust Task document through the resilience layer (bounded
    /// concurrency, circuit breaker, ≤1 idempotent retry, metrics). `operation`
    /// labels the metrics.
    async fn post_trust_task<T: DeserializeOwned>(
        &self,
        operation: &str,
        doc: &Value,
        bearer: Option<&str>,
    ) -> Result<T, VtaError> {
        self.resilience
            .run(operation, || self.post_trust_task_once(doc, bearer))
            .await
    }

    /// One carrier attempt, no back-pressure. Response parsing stays here
    /// rather than in the carrier: the flat-vs-envelope shape is a property of
    /// the Trust Task protocol, not of how the document travelled.
    async fn post_trust_task_once<T: DeserializeOwned>(
        &self,
        doc: &Value,
        bearer: Option<&str>,
    ) -> Result<T, VtaError> {
        let body = self
            .transport
            .deliver(doc, bearer)
            .await?;
        parse_response(&body)
    }

    /// Run the full DI-signed auth handshake and cache the session tokens.
    pub async fn authenticate(&self) -> Result<(), VtaError> {
        self.establish()
            .await
            .map(|_| ())
    }

    /// Open a session with the current control key and return its token with the
    /// key it belongs to.
    ///
    /// A refusal (`401`/`403`) with a reloader set asks it for the stored key; if
    /// that is a different DID the client moves to it and tries once more. Never
    /// more than once, and never anything but the control key: a trust agent that
    /// still refuses is reported as it always was.
    async fn establish(&self) -> Result<(String, Arc<dyn SignerKeyProvider>), VtaError> {
        let first = self.establish_once().await;
        let Err(VtaError::Http { status: 401 | 403, .. }) = &first else {
            return first;
        };
        let Some(reloader) = &self.key_reloader else {
            return first;
        };
        match reloader.reload().await {
            Some(stored) if stored.did() != self.control_did() => {
                self.replace_control_key(stored)
                    .await;
                self.establish_once().await
            }
            _ => first,
        }
    }

    async fn establish_once(&self) -> Result<(String, Arc<dyn SignerKeyProvider>), VtaError> {
        let (generation, key) = self.current_control();
        // 1. challenge (unsigned): payload = { subject: <control did> }.
        let challenge_doc = self.build_doc(key.did(), TASK_AUTH_CHALLENGE, json!({ "subject": key.did() }));
        let challenge: ChallengeResponse = self
            .post_trust_task("auth", &challenge_doc, None)
            .await?;

        // 2. authenticate (eddsa-jcs-2022 signed): payload = { challenge,
        //    sessionId, scope: [] }.
        let mut auth_doc = self.build_doc(
            key.did(),
            TASK_AUTH_AUTHENTICATE,
            json!({
                "challenge": challenge.challenge,
                "sessionId": challenge.session_id,
                "scope": [],
            }),
        );
        let proof = sign_document(&auth_doc, key.as_ref(), PROOF_PURPOSE_AUTHENTICATION).await?;
        auth_doc
            .as_object_mut()
            .expect("auth doc is an object")
            .insert("proof".to_string(), proof);

        let auth: AuthenticateResponse = self
            .post_trust_task("auth", &auth_doc, None)
            .await?;

        let expires_at = Instant::now() + Duration::from_secs(auth.tokens.expires_in).saturating_sub(self.expiry_skew);
        let access_token = auth.tokens.access_token;
        // VTA-05: verify the grant scope + persist the onboarding record once,
        // from the first session token (advisory — never fails the handshake).
        if let Some(onboarding) = &self.onboarding {
            onboarding
                .on_authenticated(key.did(), &access_token)
                .await;
        }
        let token = access_token.clone();
        *self.session.write().await = Some(Session {
            access_token: Zeroizing::new(access_token),
            expires_at,
            generation,
            key: Arc::clone(&key),
        });
        Ok((token, key))
    }

    /// A live session's token and the key it was opened with, authenticating
    /// when there is none, it has expired, or the control key was replaced.
    async fn session_token(&self) -> Result<(String, Arc<dyn SignerKeyProvider>), VtaError> {
        let generation = self.current_control().0;
        if let Some(session) = self
            .session
            .read()
            .await
            .as_ref()
            && session.generation == generation
            && Instant::now() < session.expires_at
        {
            return Ok((
                session
                    .access_token
                    .as_str()
                    .to_owned(),
                Arc::clone(&session.key),
            ));
        }
        self.establish().await
    }

    /// A valid access token, authenticating (or re-authenticating on expiry)
    /// as needed. Tokens are cloned out of the memory-only cache for the call.
    pub async fn access_token(&self) -> Result<String, VtaError> {
        self.session_token()
            .await
            .map(|(token, _)| token)
    }

    /// What the trust agent says this gateway may do right now
    /// (`auth/whoami/0.1`): its role, its context scopes and its **effective**
    /// capabilities, freshly resolved from the agent's access control entry.
    ///
    /// The task's specification declares its request proof mandatory, so this
    /// is dispatched signed; a bearer-only call is refused `proofRequired`.
    pub async fn whoami(&self) -> Result<super::onboarding::Whoami, VtaError> {
        self.dispatch_signed(TASK_AUTH_WHOAMI, json!({}))
            .await
    }

    /// Dispatch a session-authenticated Trust Task, returning its parsed
    /// response payload.
    pub async fn dispatch<T: DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Result<T, VtaError> {
        let generation = self.current_control().0;
        match self
            .dispatch_once(type_uri, payload.clone())
            .await
        {
            Err(e) if e.is_superseded() && self.current_control().0 != generation => {
                self.dispatch_once(type_uri, payload)
                    .await
            }
            other => other,
        }
    }

    async fn dispatch_once<T: DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Result<T, VtaError> {
        let (token, key) = self.session_token().await?;
        let doc = self.build_doc(key.did(), type_uri, payload);
        // Label metrics by the Trust Task slug (the path segment before the
        // version), e.g. `keys/sign-jws/0.1` → `sign-jws`.
        let operation = type_uri
            .trim_end_matches('/')
            .rsplit('/')
            .nth(1)
            .unwrap_or("dispatch");
        self.post_trust_task(operation, &doc, Some(&token))
            .await
    }

    /// Dispatch a Trust Task whose request document is **DI-signed** by the
    /// control key (proof-of-possession) in addition to carrying the session
    /// bearer — for write tasks whose specification requires a request proof.
    ///
    /// The bearer says a session exists; the proof says *this* request came
    /// from the key behind it. `keys/create` and `contexts/create` both answer
    /// `proofRequired` without one.
    ///
    /// Used in production by context provisioning (VTA-16): a gateway holding
    /// the narrow `context-create` capability creates its own per-surface
    /// contexts, so provisioning is no longer out-of-band. The signing path
    /// (`keys/sign-jws`) uses it too — that specification declares its request
    /// proof mandatory, so a bearer-only call is refused `proofRequired`.
    pub async fn dispatch_signed<T: DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Result<T, VtaError> {
        let generation = self.current_control().0;
        match self
            .dispatch_signed_once(type_uri, payload.clone())
            .await
        {
            Err(e) if e.is_superseded() && self.current_control().0 != generation => {
                self.dispatch_signed_once(type_uri, payload)
                    .await
            }
            other => other,
        }
    }

    async fn dispatch_signed_once<T: DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Result<T, VtaError> {
        let (token, key) = self.session_token().await?;
        let mut doc = self.build_doc(key.did(), type_uri, payload);
        let proof = sign_document(&doc, key.as_ref(), PROOF_PURPOSE_AUTHENTICATION).await?;
        doc.as_object_mut()
            .expect("doc is an object")
            .insert("proof".to_string(), proof);
        let operation = type_uri
            .trim_end_matches('/')
            .rsplit('/')
            .nth(1)
            .unwrap_or("dispatch");
        self.post_trust_task(operation, &doc, Some(&token))
            .await
    }
}
/// Parse a VTA response body: either the flat shape, or a Trust-Task
/// `#response` document whose `payload` is the body (the VTA emits the latter;
/// mocks may emit the former).
fn parse_response<T: DeserializeOwned>(body: &str) -> Result<T, VtaError> {
    if let Ok(flat) = serde_json::from_str::<T>(body) {
        return Ok(flat);
    }
    let envelope: Value =
        serde_json::from_str(body).map_err(|e| VtaError::Protocol(format!("response is not JSON: {e}")))?;
    let payload = envelope
        .get("payload")
        .ok_or_else(|| VtaError::Protocol("response has neither the expected shape nor a payload".to_string()))?;
    serde_json::from_value(payload.clone())
        .map_err(|e| VtaError::Protocol(format!("response payload has an unexpected shape: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vta::control_key::ControlKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{Json, Router, extract::State, routing::post};

    /// Mock-VTA state: counts authenticate calls and controls token lifetime.
    #[derive(Clone)]
    struct MockState {
        auth_count: Arc<AtomicUsize>,
        token_expires_in: u64,
        issuers: Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// Mock `POST /api/trust-tasks`: routes by the Trust Task `type`, asserts the
    /// authenticate document carries an `eddsa-jcs-2022` proof, and returns
    /// canned challenge / token responses.
    async fn trust_tasks(
        State(state): State<MockState>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let type_uri = body
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if type_uri.contains("auth/challenge") {
            return Json(json!({ "challenge": "chal-123", "sessionId": "sess-123" }));
        }
        if type_uri.contains("auth/authenticate") {
            let proof = body
                .get("proof")
                .expect("authenticate document must carry a proof");
            assert_eq!(proof["cryptosuite"], json!("eddsa-jcs-2022"), "eddsa-jcs-2022 proof");
            let proof_value = proof["proofValue"]
                .as_str()
                .expect("proofValue");
            assert!(proof_value.starts_with('z'), "multibase proofValue: {proof_value}");
            let n = state
                .auth_count
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            state
                .issuers
                .lock()
                .unwrap()
                .push(
                    body["issuer"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
            return Json(json!({
                "session": { "id": "s", "subject": body["issuer"] },
                "tokens": {
                    "accessToken": format!("access-token-{n}"),
                    "tokenType": "Bearer",
                    "expiresIn": state.token_expires_in,
                }
            }));
        }
        if type_uri.contains("auth/whoami") {
            assert!(body.get("proof").is_some(), "auth/whoami declares its request proof mandatory");
            return Json(json!({
                "type": "https://trusttasks.org/spec/auth/whoami/0.1#response",
                "payload": {
                    "session": { "id": "s", "subject": "did:key:z6MkGw" },
                    "roles": ["initiator"],
                    "scopes": ["ctx:gateway"],
                    "capabilities": ["context-create", "key-mint", "sign-jws", "sign-document"],
                }
            }));
        }
        Json(json!({ "error": "unexpected task" }))
    }

    async fn spawn_mock_vta(token_expires_in: u64) -> (String, Arc<AtomicUsize>) {
        let (base, auth_count, _) = spawn_recording_vta(token_expires_in).await;
        (base, auth_count)
    }

    /// Also records the DID each authentication was made as.
    async fn spawn_recording_vta(
        token_expires_in: u64
    ) -> (String, Arc<AtomicUsize>, Arc<std::sync::Mutex<Vec<String>>>) {
        let auth_count = Arc::new(AtomicUsize::new(0));
        let issuers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = MockState {
            auth_count: Arc::clone(&auth_count),
            token_expires_in,
            issuers: Arc::clone(&issuers),
        };
        let app = Router::new()
            .route(TRUST_TASKS_PATH, post(trust_tasks))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        (format!("http://{addr}"), auth_count, issuers)
    }

    fn test_client(
        base_url: &str,
        control_key: Arc<ControlKey>,
    ) -> VtaRestClient {
        VtaRestClient::new(base_url, "did:webvh:vta.example", control_key, Duration::from_secs(5), 8, None)
            .expect("build client")
    }

    #[tokio::test]
    async fn authenticates_and_returns_a_session_token() {
        let (base, auth_count) = spawn_mock_vta(3600).await;
        let key = Arc::new(ControlKey::from_seed([5u8; 32]));
        let client = test_client(&base, key);

        let token = client
            .access_token()
            .await
            .expect("authenticate");
        assert_eq!(token, "access-token-1");
        assert_eq!(auth_count.load(Ordering::SeqCst), 1, "one auth handshake");
    }

    #[tokio::test]
    async fn replacing_the_control_key_authenticates_as_the_new_did_on_the_next_call() {
        let (base, _, issuers) = spawn_recording_vta(3600).await;
        let old = Arc::new(ControlKey::from_seed([11u8; 32]));
        let new = Arc::new(ControlKey::from_seed([12u8; 32]));
        let (old_did, new_did) = (old.did().to_string(), new.did().to_string());
        let client = test_client(&base, old);
        client
            .access_token()
            .await
            .unwrap();

        client
            .replace_control_key(new)
            .await;
        client
            .access_token()
            .await
            .unwrap();

        assert_eq!(*issuers.lock().unwrap(), vec![old_did, new_did.clone()]);
        assert_eq!(client.control_did(), new_did);
    }

    #[tokio::test]
    async fn replacing_the_control_key_drops_the_cached_session() {
        let (base, auth_count, _) = spawn_recording_vta(3600).await;
        let client = test_client(&base, Arc::new(ControlKey::from_seed([13u8; 32])));
        let first = client
            .access_token()
            .await
            .unwrap();

        client
            .replace_control_key(Arc::new(ControlKey::from_seed([14u8; 32])))
            .await;
        let second = client
            .access_token()
            .await
            .unwrap();

        assert_ne!(first, second, "the old token is not reused for the new key");
        assert_eq!(auth_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_signed_call_after_replacement_is_made_as_the_new_did() {
        let (base, _, issuers) = spawn_recording_vta(3600).await;
        let client = test_client(&base, Arc::new(ControlKey::from_seed([15u8; 32])));
        client.whoami().await.unwrap();
        let new = Arc::new(ControlKey::from_seed([16u8; 32]));
        let new_did = new.did().to_string();

        client
            .replace_control_key(new)
            .await;
        client.whoami().await.unwrap();

        assert_eq!(issuers.lock().unwrap().last(), Some(&new_did));
    }

    #[tokio::test]
    async fn the_onboarding_check_runs_again_after_a_key_replacement() {
        let (base, _, _) = spawn_recording_vta(3600).await;
        let dir = tempfile::tempdir().unwrap();
        let record = dir
            .path()
            .join("vta_onboarding");
        let onboarding = OnboardingState::new(
            Some(record.clone()),
            "gateway".to_string(),
            "did:webvh:vta.example".to_string(),
            Duration::from_secs(0),
        );
        let old = Arc::new(ControlKey::from_seed([17u8; 32]));
        let new = Arc::new(ControlKey::from_seed([18u8; 32]));
        let new_did = new.did().to_string();
        let client =
            VtaRestClient::new(&base, "did:webvh:vta.example", old, Duration::from_secs(5), 8, Some(onboarding))
                .unwrap();
        client
            .authenticate()
            .await
            .unwrap();

        client
            .replace_control_key(new)
            .await;
        client
            .authenticate()
            .await
            .unwrap();

        let saved = crate::vta::onboarding::OnboardingRecord::load(&record)
            .await
            .unwrap()
            .expect("a record");
        assert_eq!(saved.control_did, new_did);
    }

    type Replacement = (Arc<tokio::sync::OnceCell<Arc<VtaRestClient>>>, Arc<ControlKey>);

    #[derive(Clone)]
    struct SupersedeState {
        calls: Arc<AtomicUsize>,
        status: u16,
        body: &'static str,
        replace_on_first: Arc<std::sync::Mutex<Option<Replacement>>>,
    }

    async fn echo(
        State(state): State<SupersedeState>,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let task = body["type"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if task.contains("auth/challenge") {
            return Json(json!({ "challenge": "c", "sessionId": "s" })).into_response();
        }
        if task.contains("auth/authenticate") {
            return Json(json!({ "session": { "id": "s" }, "tokens": { "accessToken": "t", "expiresIn": 3600 } }))
                .into_response();
        }
        let n = state
            .calls
            .fetch_add(1, Ordering::SeqCst);
        if n == 0 {
            let pending = state
                .replace_on_first
                .lock()
                .unwrap()
                .take();
            if let Some((cell, key)) = pending {
                cell.get()
                    .unwrap()
                    .replace_control_key(key)
                    .await;
            }
            return (axum::http::StatusCode::from_u16(state.status).unwrap(), state.body.to_string()).into_response();
        }
        Json(json!({ "payload": { "ok": true } })).into_response()
    }

    const SUPERSEDED: &str = r#"{"error":"unauthorized: token superseded"}"#;

    async fn supersede_client(
        status: u16,
        body: &'static str,
        replace_during_first: bool,
    ) -> (Arc<VtaRestClient>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let cell = Arc::new(tokio::sync::OnceCell::new());
        let replacement =
            replace_during_first.then(|| (Arc::clone(&cell), Arc::new(ControlKey::from_seed([22u8; 32]))));
        let state = SupersedeState {
            calls: Arc::clone(&calls),
            status,
            body,
            replace_on_first: Arc::new(std::sync::Mutex::new(replacement)),
        };
        let app = Router::new()
            .route(TRUST_TASKS_PATH, post(echo))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        let client = Arc::new(test_client(&format!("http://{addr}"), Arc::new(ControlKey::from_seed([21u8; 32]))));
        cell.set(Arc::clone(&client))
            .ok();
        (client, calls)
    }

    #[tokio::test]
    async fn a_call_superseded_by_the_clients_own_key_change_is_retried_once() {
        let (client, calls) = supersede_client(401, SUPERSEDED, true).await;

        let reply: Value = client
            .dispatch("https://trusttasks.org/spec/test/echo/0.1", json!({}))
            .await
            .expect("retried");

        assert_eq!(reply["payload"]["ok"], true);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "one refused, one retried");
    }

    #[tokio::test]
    async fn a_signed_call_superseded_by_the_clients_own_key_change_is_retried_once() {
        let (client, calls) = supersede_client(401, SUPERSEDED, true).await;

        let reply: Value = client
            .dispatch_signed("https://trusttasks.org/spec/test/echo/0.1", json!({}))
            .await
            .expect("retried");

        assert_eq!(reply["payload"]["ok"], true);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_superseded_call_without_a_key_change_is_not_retried() {
        let (client, calls) = supersede_client(401, SUPERSEDED, false).await;

        let err = client
            .dispatch::<Value>("https://trusttasks.org/spec/test/echo/0.1", json!({}))
            .await
            .expect_err("surfaced");

        assert!(err.is_superseded(), "{err:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry");
    }

    #[tokio::test]
    async fn a_refused_call_is_never_retried_even_after_a_key_change() {
        let (client, calls) = supersede_client(403, r#"{"error":"forbidden"}"#, true).await;

        let err = client
            .dispatch::<Value>("https://trusttasks.org/spec/test/echo/0.1", json!({}))
            .await
            .expect_err("refused");

        assert!(matches!(err, VtaError::Http { status: 403, .. }), "{err:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn whoami_reports_the_effective_grant() {
        let (base, _) = spawn_mock_vta(3600).await;
        let client = test_client(&base, Arc::new(ControlKey::from_seed([4u8; 32])));

        let who = client
            .whoami()
            .await
            .expect("whoami");

        assert_eq!(who.roles, ["initiator"]);
        assert_eq!(who.scopes, ["ctx:gateway"]);
        who.assert_bundled_grant("gateway")
            .expect("the mock holds exactly the bundled grant");
        assert!(
            who.assert_bundled_grant("other")
                .is_err(),
            "a different context is not the grant"
        );
    }

    #[tokio::test]
    async fn caches_a_live_token_without_reauthenticating() {
        let (base, auth_count) = spawn_mock_vta(3600).await;
        let key = Arc::new(ControlKey::from_seed([6u8; 32]));
        let client = test_client(&base, key);

        let first = client
            .access_token()
            .await
            .unwrap();
        let second = client
            .access_token()
            .await
            .unwrap();
        assert_eq!(first, second, "cached token reused");
        assert_eq!(auth_count.load(Ordering::SeqCst), 1, "no re-auth while the token is live");
    }

    #[tokio::test]
    async fn reauthenticates_once_the_token_has_expired() {
        // `expiresIn = 0` → the token is treated as already expired (minus the
        // skew), so every call re-runs the handshake.
        let (base, auth_count) = spawn_mock_vta(0).await;
        let key = Arc::new(ControlKey::from_seed([8u8; 32]));
        let client = test_client(&base, key);

        let _ = client
            .access_token()
            .await
            .unwrap();
        let _ = client
            .access_token()
            .await
            .unwrap();
        assert_eq!(auth_count.load(Ordering::SeqCst), 2, "expired token triggers re-auth");
    }

    #[tokio::test]
    async fn maps_http_error_without_leaking_body_into_display() {
        // No route for this path → 404; the error must be an Http variant whose
        // Display does not echo the VTA body.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, Router::new())
                .await
                .unwrap();
        });
        let key = Arc::new(ControlKey::from_seed([1u8; 32]));
        let client = test_client(&format!("http://{addr}"), key);
        let err = client
            .access_token()
            .await
            .expect_err("404 is an error");
        match err {
            VtaError::Http { status, .. } => assert_eq!(status, 404),
            other => panic!("expected Http error, got {other:?}"),
        }
        assert!(!format!("{err}").contains("payload"), "Display must not echo the body");
    }

    /// Live end-to-end against a real `vta-service`. Ignored by default (never
    /// runs in CI). Bring up the VTA, seed the printed control DID, then run:
    ///
    /// ```text
    /// VTA_LIVE_URL=http://localhost:3000 \
    /// VTA_LIVE_DID=did:webvh:<scid>:localhost%3A3000 \
    ///   cargo test --bin agent-trust-gateway \
    ///     vta::client::tests::live_authenticate_against_real_vta \
    ///     -- --ignored --nocapture
    /// ```
    ///
    /// Uses the fixed control-key seed `[42u8; 32]` so the printed `did:key` is
    /// stable across runs and can be seeded once with `vta import-did`.
    #[tokio::test]
    #[ignore = "requires a running vta-service; run manually (see doc comment)"]
    async fn live_authenticate_against_real_vta() {
        let key = Arc::new(ControlKey::from_seed([42u8; 32]));
        eprintln!("GATEWAY_CONTROL_DID={}", key.did());

        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID to the VTA did:webvh");

        let client = VtaRestClient::new(&url, &vta_did, key, Duration::from_secs(15), 8, None).expect("build client");
        let token = client
            .access_token()
            .await
            .expect("authenticate against the live VTA");
        eprintln!("LIVE_OK: received a session token of length {}", token.len());
        assert!(!token.is_empty());
    }

    /// Live check that a gateway enrolled by the bundled entrypoint holds
    /// exactly the bundled grant, as the VTA itself reports it.
    ///
    /// Enrol the DID printed by [`live_authenticate_against_real_vta`] with
    /// `vta-entrypoint.sh`, start the VTA, then run with `VTA_LIVE_URL` and
    /// `VTA_LIVE_DID` set to its address and `did:key`.
    #[tokio::test]
    #[ignore = "requires a running vta-service enrolled by vta-entrypoint.sh; run manually"]
    async fn live_whoami_reports_the_bundled_grant() {
        let key = Arc::new(ControlKey::from_seed([42u8; 32]));
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:8100".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID to the bundled VTA did:key");

        let client = VtaRestClient::new(&url, &vta_did, key, Duration::from_secs(15), 8, None).expect("build client");
        let who = client
            .whoami()
            .await
            .expect("whoami against the live VTA");
        eprintln!("LIVE_WHOAMI: {who:?}");
        who.assert_bundled_grant("gateway")
            .expect("the entrypoint enrols exactly the bundled grant");
    }

    /// Live check of how a trust agent refuses a control key it has no access
    /// entry for, which is how a revoked or never-enrolled gateway looks.
    #[tokio::test]
    #[ignore = "requires a running vta-service; run manually"]
    async fn live_an_unenrolled_key_is_refused() {
        let key = Arc::new(ControlKey::from_seed([7u8; 32]));
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:8100".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID to the VTA did:key");
        let client = VtaRestClient::new(&url, &vta_did, key, Duration::from_secs(15), 8, None).expect("build client");
        let err = client
            .authenticate()
            .await
            .expect_err("an unenrolled key must be refused");
        eprintln!("LIVE_REFUSED: {err:?}");
    }

    /// Live VTA-05 check: the real session token's grant scope parses, and the
    /// admin-seeded control key (`vta import-did --role admin`) is correctly
    /// detected as **over-privileged** (not least-privilege). Same manual setup
    /// as [`live_authenticate_against_real_vta`].
    #[tokio::test]
    #[ignore = "requires a running vta-service; run manually"]
    async fn live_grant_scope_is_parsed_from_the_real_token() {
        use crate::vta::onboarding::GrantScope;
        let key = Arc::new(ControlKey::from_seed([42u8; 32]));
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID to the VTA did:webvh");

        let client = VtaRestClient::new(&url, &vta_did, key, Duration::from_secs(15), 8, None).expect("build client");
        let token = client
            .access_token()
            .await
            .expect("authenticate");
        let scope = GrantScope::from_session_token(&token).expect("real token carries role/contexts claims");
        eprintln!("LIVE_SCOPE: role={} contexts={:?}", scope.role, scope.contexts);
        assert!(scope.is_super_admin(), "the admin-seeded control key is detected as over-privileged");
        assert!(scope.assert_scoped().is_err(), "an admin grant is refused as least-privilege");
    }
}
