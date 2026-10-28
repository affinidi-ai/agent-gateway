//! Thin REST/Trust-Task **client** of the VTA (`POST {base_url}/trust-tasks`).
//!
//! The gateway and VTA are separate services; this client speaks the VTA's HTTP
//! Trust-Task surface with the gateway's own `reqwest` stack — it does **not**
//! link `vta-sdk`. It performs the DI-signed auth handshake
//! (`auth/challenge/0.1` → `auth/authenticate/0.2`), caches the session tokens
//! **in memory only**, and dispatches further Trust Tasks with the bearer token.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::control_key::SignerKeyProvider;
use super::di_proof::{PROOF_PURPOSE_AUTHENTICATION, sign_document};
use super::error::VtaError;
use super::onboarding::OnboardingState;
use super::resilience::Resilience;
use super::transport::{HttpsTransport, TrustTaskTransport};
use super::wire::{AuthenticateResponse, ChallengeResponse};
use zeroize::Zeroizing;

pub(crate) const TRUST_TASKS_PATH: &str = "/trust-tasks";
const TASK_AUTH_CHALLENGE: &str = "https://trusttasks.org/spec/auth/challenge/0.1";
const TASK_AUTH_AUTHENTICATE: &str = "https://trusttasks.org/spec/auth/authenticate/0.2";

/// A cached, memory-only session. Tokens never touch disk, are **zeroized** when
/// this value is dropped (re-auth replaces it), and carry no `Debug`.
struct Session {
    /// Zeroized on drop so a rotated token does not linger in freed heap.
    access_token: Zeroizing<String>,
    /// Monotonic instant after which the access token is treated as expired.
    expires_at: Instant,
}

/// Thin VTA Trust-Task client. One per configured VTA.
///
/// Carrier-agnostic: the auth handshake, session caching, resilience and error
/// redaction all sit above [`TrustTaskTransport`], so a connection reached over
/// DIDComm behaves identically to one reached over HTTPS (VTA-27).
pub struct VtaRestClient {
    transport: Arc<dyn TrustTaskTransport>,
    vta_did: String,
    control_key: Arc<dyn SignerKeyProvider>,
    session: RwLock<Option<Session>>,
    /// Back-pressure + circuit breaker so a slow/hung VTA fails fast (VTA-04).
    resilience: Resilience,
    /// Customer-sovereign onboarding checks run after the first auth (VTA-05).
    onboarding: Option<OnboardingState>,
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
            control_key,
            session: RwLock::new(None),
            resilience: Resilience::new(max_concurrent),
            onboarding,
            expiry_skew: Duration::from_secs(30),
        }
    }

    /// The carrier this client is using, for metrics and diagnostics.
    pub fn carrier(&self) -> &'static str {
        self.transport.carrier()
    }

    /// Build an unsigned Trust Task document (no `proof`).
    fn build_doc(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Value {
        json!({
            "id": format!("urn:uuid:{}", Uuid::new_v4()),
            "type": type_uri,
            "issuer": self.control_key.did(),
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
        // 1. challenge (unsigned): payload = { subject: <control did> }.
        let challenge_doc = self.build_doc(TASK_AUTH_CHALLENGE, json!({ "subject": self.control_key.did() }));
        let challenge: ChallengeResponse = self
            .post_trust_task("auth", &challenge_doc, None)
            .await?;

        // 2. authenticate (eddsa-jcs-2022 signed): payload = { challenge,
        //    sessionId, scope: [] }.
        let mut auth_doc = self.build_doc(
            TASK_AUTH_AUTHENTICATE,
            json!({
                "challenge": challenge.challenge,
                "sessionId": challenge.session_id,
                "scope": [],
            }),
        );
        let proof = sign_document(&auth_doc, self.control_key.as_ref(), PROOF_PURPOSE_AUTHENTICATION).await?;
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
                .on_authenticated(self.control_key.did(), &access_token)
                .await;
        }
        *self.session.write().await = Some(Session {
            access_token: Zeroizing::new(access_token),
            expires_at,
        });
        Ok(())
    }

    /// A valid access token, authenticating (or re-authenticating on expiry)
    /// as needed. Tokens are cloned out of the memory-only cache for the call.
    pub async fn access_token(&self) -> Result<String, VtaError> {
        if let Some(session) = self
            .session
            .read()
            .await
            .as_ref()
            && Instant::now() < session.expires_at
        {
            return Ok(session
                .access_token
                .as_str()
                .to_owned());
        }
        self.authenticate().await?;
        self.session
            .read()
            .await
            .as_ref()
            .map(|s| {
                s.access_token
                    .as_str()
                    .to_owned()
            })
            .ok_or_else(|| VtaError::Protocol("no session after authenticate".to_string()))
    }

    /// Dispatch a session-authenticated Trust Task, returning its parsed
    /// response payload.
    pub async fn dispatch<T: DeserializeOwned>(
        &self,
        type_uri: &str,
        payload: Value,
    ) -> Result<T, VtaError> {
        let token = self.access_token().await?;
        let doc = self.build_doc(type_uri, payload);
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
        let token = self.access_token().await?;
        let mut doc = self.build_doc(type_uri, payload);
        let proof = sign_document(&doc, self.control_key.as_ref(), PROOF_PURPOSE_AUTHENTICATION).await?;
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
            return Json(json!({
                "session": { "id": "s", "subject": body["issuer"] },
                "tokens": {
                    "accessToken": format!("access-token-{n}"),
                    "tokenType": "Bearer",
                    "expiresIn": state.token_expires_in,
                }
            }));
        }
        Json(json!({ "error": "unexpected task" }))
    }

    async fn spawn_mock_vta(token_expires_in: u64) -> (String, Arc<AtomicUsize>) {
        let auth_count = Arc::new(AtomicUsize::new(0));
        let state = MockState {
            auth_count: Arc::clone(&auth_count),
            token_expires_in,
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
        (format!("http://{addr}"), auth_count)
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
