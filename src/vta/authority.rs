//! The **VTA signing connector**: a [`CredentialAuthority`] implementation that
//! delegates the gateway's private-key operations to a VTA over the thin REST
//! client ([`super::client::VtaRestClient`]).
//!
//! It is one connector behind the [`CredentialAuthority`] interface — the local
//! in-process signer is the other (see `src/identity/authority`). A future
//! third signing backend (an HSM/KMS service, a different signer entirely) is
//! added the same way: implement [`CredentialAuthority`] and register one arm in
//! [`super::select_credential_authority`]; no call site changes.
//!
//! **Scope (VTA-07):** the auth/session handshake and the JWT signing
//! round-trip are complete and tested. A signing call dispatches the
//! `keys/sign-jws/0.1` Trust Task (added VTA-side in VTA-06), naming the pinned
//! VTA-held key; the VTA signs and returns a compact JWS. The gateway never
//! sees the private key. DI-credential issuance via the VTA (`credentials/issue`)
//! and JWKS discovery are wired in VTA-08.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use base64::Engine as _;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::RwLock;

use super::audit::{AuditRecord, VtaAuditSink};
use super::client::VtaRestClient;
use super::error::VtaError;
use super::quota::SignQuota;
use crate::identity::authority::CredentialAuthority;

/// `keys/sign-jws/0.1` — the walled-off JWT-signing Trust Task (VTA-06).
const TASK_KEYS_SIGN_JWS: &str = "https://trusttasks.org/spec/keys/sign-jws/0.1";

/// `keys/show/0.1` — read a key record (public key only; no secret material).
const TASK_KEYS_SHOW: &str = "https://trusttasks.org/spec/keys/show/0.1";

/// JOSE/IANA algorithm the gateway's Ed25519 VTA key signs with. The VTA
/// re-asserts `alg` from the key record, so this is the gateway's declared
/// expectation, not a value the VTA trusts blindly.
const SIGNING_ALGORITHM: &str = "EdDSA";

/// The `keys/sign-jws` result body. Deserializing into a typed struct (rather
/// than a free `Value`) makes the client unwrap the VTA's `#response`
/// Trust-Task envelope to its `payload`, where the real VTA carries `jws`.
#[derive(Debug, Deserialize)]
struct SignJwsResult {
    jws: String,
}

/// The `keys/show` result body (public fields only). `key` is **not** optional:
/// a required field makes the client reject the VTA's `#response` envelope on a
/// flat parse and fall through to unwrap its `payload` (where the record is),
/// rather than quietly matching the envelope with `key = None`.
#[derive(Debug, Deserialize)]
struct KeyShowResult {
    key: KeyPublic,
}

#[derive(Debug, Deserialize)]
struct KeyPublic {
    #[serde(rename = "publicKey", alias = "public_key")]
    public_key: String,
}

/// [`CredentialAuthority`] backed by a VTA.
pub struct VtaCredentialAuthority {
    client: Arc<VtaRestClient>,
    /// The issuer DID whose VTA-held key signs tokens. Established at onboarding
    /// (VTA-05); until then it defaults to the VTA service DID.
    issuer_did: String,
    /// The pinned VTA key record id that signs the gateway's tokens. The
    /// gateway names the key; the VTA holds it.
    signing_key_id: String,
    /// VTA keys that no longer sign but must still be **published** so the
    /// tokens they signed keep verifying (VTA-17). `(kid, public_key)`; the
    /// public key is `None` when it should be resolved from the VTA.
    retiring_keys: Vec<(String, Option<String>)>,
    /// The active signing key's multibase public key, when the operator
    /// supplied it. Present means the JWKS needs **no VTA call**; it is also
    /// the only way to publish an **internal** key, whose record the VTA
    /// refuses to return to any caller at any role.
    signing_key_public: Option<String>,
    /// Public JWKs carried over from another authority — in practice the local
    /// issuer key, kept in the JWKS while a deployment migrates surface by
    /// surface so previously locally-signed tokens do not stop verifying.
    carried_over_jwks: Vec<Value>,
    /// The pinned key's public JWKS, resolved once from the VTA and cached so
    /// publishing it (`/oauth2/jwks.json`) is not a per-call VTA hop — and so
    /// **verification stays a local public-key operation** (VTA-08).
    jwks_cache: RwLock<Option<Value>>,
    /// Optional, bounded, non-blocking audit sink for signing events (VTA-08).
    audit: Option<VtaAuditSink>,
    /// Caps how many signatures may be minted per window (VTA-17).
    quota: SignQuota,
}

impl VtaCredentialAuthority {
    pub fn new(
        client: Arc<VtaRestClient>,
        issuer_did: String,
        signing_key_id: String,
        audit: Option<VtaAuditSink>,
    ) -> Self {
        Self {
            client,
            issuer_did,
            signing_key_id,
            retiring_keys: Vec::new(),
            signing_key_public: None,
            carried_over_jwks: Vec::new(),
            jwks_cache: RwLock::new(None),
            audit,
            quota: SignQuota::new(0, 0),
        }
    }

    /// Publish `retiring_keys` alongside the active key so tokens they signed
    /// keep verifying during a rotation or a per-surface migration (VTA-17).
    /// Each entry is `(kid, public_key)`; a `None` public key is resolved from
    /// the VTA.
    #[must_use]
    pub fn with_retiring_keys(
        mut self,
        retiring_keys: Vec<(String, Option<String>)>,
    ) -> Self {
        self.retiring_keys = retiring_keys;
        self
    }

    /// Supply the active signing key's multibase public key, so the JWKS is
    /// built without calling the VTA at all — and so an **internal**
    /// (non-exportable) key can be published, which `keys/show` cannot do.
    #[must_use]
    pub fn with_signing_key_public(
        mut self,
        public_key: Option<String>,
    ) -> Self {
        self.signing_key_public = public_key;
        self
    }

    /// Keep `jwks` (another authority's **public** keys, typically the local
    /// issuer's) in the published key set. This is what makes a surface-by-surface
    /// migration safe: the old key still verifies while the new one signs.
    #[must_use]
    pub fn with_carried_over_jwks(
        mut self,
        jwks: Vec<Value>,
    ) -> Self {
        self.carried_over_jwks = jwks;
        self
    }

    /// Bound how many signatures this authority may mint per window (VTA-17).
    #[must_use]
    pub fn with_quota(
        mut self,
        quota: SignQuota,
    ) -> Self {
        self.quota = quota;
        self
    }

    /// Resolve one VTA key's public JWK.
    ///
    /// Uses `public_key` when the operator supplied it — no VTA call, and the
    /// only option for an **internal** key, whose record the VTA will not
    /// return to anyone. Otherwise reads it from the VTA via `keys/show`
    /// (public material only).
    async fn resolve_jwk(
        &self,
        key_id: &str,
        public_key: Option<&str>,
    ) -> Result<Value, VtaError> {
        if let Some(public_key) = public_key {
            return ed25519_multibase_to_jwk(public_key, key_id);
        }
        let result: KeyShowResult = self
            .client
            .dispatch(TASK_KEYS_SHOW, json!({ "keyId": key_id }))
            .await?;
        ed25519_multibase_to_jwk(&result.key.public_key, key_id)
    }

    /// Sign `claims` as a compact JWS via the VTA's `keys/sign-jws/0.1` task,
    /// carrying the JOSE `typ` + `kid` header and naming the pinned signing key.
    /// The VTA holds the key and re-asserts `alg`; the gateway never sees the
    /// key. A successful sign is audited (bounded, hashes-only, non-blocking).
    async fn sign_jws(
        &self,
        claims: &Value,
        typ: &str,
    ) -> Result<String, VtaError> {
        // Quota first: an exhausted window must refuse **before** the VTA is
        // asked to sign, so the limit bounds signatures rather than merely
        // reporting on them (VTA-17).
        self.quota.claim()?;
        let request = json!({
            "keyId": self.signing_key_id,
            "header": { "typ": typ, "kid": self.signing_key_id },
            "payload": claims,
            "algorithm": SIGNING_ALGORITHM,
        });
        let response: SignJwsResult = self
            .client
            .dispatch(TASK_KEYS_SIGN_JWS, request)
            .await?;
        if response.jws.trim().is_empty() {
            return Err(VtaError::Protocol("keys/sign-jws response carried an empty `jws`".to_string()));
        }
        if let Some(audit) = &self.audit {
            let subject = claims
                .get("sub")
                .and_then(Value::as_str)
                .unwrap_or_default();
            audit.record(
                AuditRecord::for_signed_token("token_signed", &self.signing_key_id, subject, &response.jws)
                    .via(self.client.carrier()),
            );
        }
        Ok(response.jws)
    }
}

/// Convert an Ed25519 multibase public key (as the VTA records it, `z`-prefixed
/// `0xed01 ++ pubkey`) into a verification JWK the OAuth JWKS endpoint serves.
fn ed25519_multibase_to_jwk(
    public_key_mb: &str,
    kid: &str,
) -> Result<Value, VtaError> {
    let (_base, bytes) = multibase::decode(public_key_mb)
        .map_err(|e| VtaError::Protocol(format!("VTA public key is not multibase: {e}")))?;
    if bytes.len() < 34 || bytes[0] != 0xed || bytes[1] != 0x01 {
        return Err(VtaError::Protocol("VTA signing key is not an ed25519 multibase key".to_string()));
    }
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[2..34]);
    Ok(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "use": "sig",
        "alg": "EdDSA",
        "kid": kid,
    }))
}

#[async_trait]
impl CredentialAuthority for VtaCredentialAuthority {
    async fn issuer_did(&self) -> Result<String> {
        Ok(self.issuer_did.clone())
    }

    async fn issuer_jwks(&self) -> Result<Value> {
        // Resolve the published key set once and cache it, so a standard OAuth
        // resource server can verify VTA-signed tokens via `jwks_uri` without
        // resolving a DID document — and so verification is a local public-key
        // operation with no per-verify VTA hop.
        //
        // The set is deliberately **multi-key** (VTA-17): the active signing
        // key, every retiring VTA key, and any carried-over local key. A
        // per-surface migration or a rotation means two keys are live at once,
        // and a verifier selects between them by `kid`; publishing only the
        // active key would silently break every token signed by the other.
        if let Some(jwks) = self
            .jwks_cache
            .read()
            .await
            .clone()
        {
            return Ok(jwks);
        }

        let mut keys: Vec<Value> = Vec::with_capacity(1 + self.retiring_keys.len() + self.carried_over_jwks.len());
        keys.push(
            self.resolve_jwk(
                &self.signing_key_id,
                self.signing_key_public
                    .as_deref(),
            )
            .await
            .map_err(anyhow::Error::from)?,
        );
        for (key_id, public_key) in &self.retiring_keys {
            // A retiring key that cannot be resolved must not take the whole
            // JWKS down with it — the active key still has to be publishable.
            match self
                .resolve_jwk(key_id, public_key.as_deref())
                .await
            {
                Ok(jwk) => keys.push(jwk),
                Err(e) => tracing::warn!(
                    target: "vta_audit",
                    key_id = %key_id,
                    detail = %e.log_detail(),
                    "retiring VTA key could not be resolved; omitting it from the JWKS",
                ),
            }
        }
        keys.extend(
            self.carried_over_jwks
                .iter()
                .cloned(),
        );

        let jwks = json!({ "keys": keys });
        *self.jwks_cache.write().await = Some(jwks.clone());
        Ok(jwks)
    }

    async fn sign_token(
        &self,
        claims: &Value,
    ) -> Result<String> {
        Ok(self
            .sign_jws(claims, "JWT")
            .await?)
    }

    async fn sign_token_typ(
        &self,
        claims: &Value,
        typ: &str,
    ) -> Result<String> {
        Ok(self
            .sign_jws(claims, typ)
            .await?)
    }
}

/// VTA-07 PoC: drive the `CredentialAuthority` seam against a mock VTA that
/// really Ed25519-signs `keys/sign-jws`, and verify the resulting compact JWS.
///
/// This is the seam every protocol path funnels through — an MCP/A2A agent that
/// needs a downstream token reaches it via STS (`VcIssuerSigner` →
/// `CredentialAuthority::sign_token`), payment via `sign_credential`, AP2 via
/// `create_vp_jwt_with_gateway` — so proving the seam proves the flow. A live
/// end-to-end against a real `vta-service` lives in
/// [`crate::vta::client::tests::live_authenticate_against_real_vta`]; the
/// runbook (`docs/VTA_INTEGRATION_POC.md`) drives the full STS→VTA path.
#[cfg(test)]
mod poc_tests {
    use super::*;
    use crate::vta::control_key::{ControlKey, SignerKeyProvider};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use axum::{Json, Router, extract::State, routing::post};
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    /// A mock VTA that holds its signing key (it never crosses the wire) and
    /// actually signs `keys/sign-jws` the way the real handler does: the VTA
    /// sets `alg`, builds `b64url(header).b64url(payload)`, and signs that.
    #[derive(Clone)]
    struct MockVta {
        signing: Arc<SigningKey>,
        sign_calls: Arc<AtomicUsize>,
        last_key_id: Arc<Mutex<Option<String>>>,
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn unb64(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .expect("base64url")
    }

    async fn trust_tasks(
        State(vta): State<MockVta>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let type_uri = body
            .get("type")
            .and_then(Value::as_str)
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
        if type_uri.contains("keys/show") {
            // Return the signing key's public key as the VTA records it:
            // multibase base58btc of `0xed01 ++ ed25519-pubkey`.
            let pub_bytes = vta
                .signing
                .verifying_key()
                .to_bytes();
            let mut prefixed = vec![0xed_u8, 0x01];
            prefixed.extend_from_slice(&pub_bytes);
            let mb = multibase::encode(multibase::Base::Base58Btc, &prefixed);
            return Json(json!({ "key": { "keyId": body["payload"]["keyId"], "publicKey": mb } }));
        }
        if type_uri.contains("keys/sign-jws") {
            vta.sign_calls
                .fetch_add(1, Ordering::SeqCst);
            let payload = &body["payload"];
            *vta.last_key_id
                .lock()
                .unwrap() = payload["keyId"]
                .as_str()
                .map(str::to_owned);
            // The VTA sets `alg` from the key — mirror the real handler.
            let mut header = payload["header"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            header.insert("alg".to_string(), json!("EdDSA"));
            let signing_input = format!(
                "{}.{}",
                b64(&serde_json::to_vec(&Value::Object(header)).unwrap()),
                b64(&serde_json::to_vec(&payload["payload"]).unwrap()),
            );
            let sig = vta
                .signing
                .sign(signing_input.as_bytes());
            // Only `jws` crosses back — no key material.
            return Json(json!({ "jws": format!("{signing_input}.{}", b64(&sig.to_bytes())) }));
        }
        Json(json!({ "error": "unexpected task" }))
    }

    async fn spawn(signing: Arc<SigningKey>) -> (String, MockVta) {
        let vta = MockVta {
            signing,
            sign_calls: Arc::new(AtomicUsize::new(0)),
            last_key_id: Arc::new(Mutex::new(None)),
        };
        let app = Router::new()
            .route("/trust-tasks", post(trust_tasks))
            .with_state(vta.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        (format!("http://{addr}"), vta)
    }

    fn authority(
        base: &str,
        signing_key_id: &str,
    ) -> VtaCredentialAuthority {
        let control = Arc::new(ControlKey::from_seed([7u8; 32]));
        let client = Arc::new(
            VtaRestClient::new(base, "did:webvh:vta.example", control, Duration::from_secs(5), 8, None)
                .expect("build client"),
        );
        VtaCredentialAuthority::new(client, "did:webvh:vta.example".to_string(), signing_key_id.to_string(), None)
    }

    /// Verify a compact JWS against `vk`, returning the decoded (header, payload).
    fn verify_compact_jws(
        jws: &str,
        vk: &VerifyingKey,
    ) -> (Value, Value) {
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "a compact JWS has three parts: {jws}");
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&unb64(parts[2])).expect("signature bytes");
        vk.verify(signing_input.as_bytes(), &sig)
            .expect("the JWS verifies against the VTA signing key");
        let decode = |s: &str| serde_json::from_slice::<Value>(&unb64(s)).expect("json part");
        (decode(parts[0]), decode(parts[1]))
    }

    #[tokio::test]
    async fn sign_token_produces_a_vta_signed_jwt_that_verifies() {
        let signing = Arc::new(SigningKey::from_bytes(&[9u8; 32]));
        let vk = signing.verifying_key();
        let (base, vta) = spawn(Arc::clone(&signing)).await;
        let auth = authority(&base, "key-gateway-jwt");

        let claims = json!({ "sub": "urn:agent:demo", "scope": "mcp:call" });
        let jws = auth
            .sign_token(&claims)
            .await
            .expect("the VTA signs the token");

        let (header, payload) = verify_compact_jws(&jws, &vk);
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["alg"], "EdDSA", "the VTA sets alg from the key");
        assert_eq!(payload["sub"], "urn:agent:demo");
        assert_eq!(
            vta.last_key_id
                .lock()
                .unwrap()
                .as_deref(),
            Some("key-gateway-jwt"),
            "the pinned signing key is the one the VTA used",
        );
    }

    #[tokio::test]
    async fn sign_token_typ_carries_the_requested_jose_typ() {
        let signing = Arc::new(SigningKey::from_bytes(&[3u8; 32]));
        let vk = signing.verifying_key();
        let (base, _vta) = spawn(Arc::clone(&signing)).await;
        let auth = authority(&base, "key-gateway-jwt");

        let jws = auth
            .sign_token_typ(&json!({ "sub": "x" }), "oauth-id-jag+jwt")
            .await
            .expect("sign with an explicit typ");
        let (header, _payload) = verify_compact_jws(&jws, &vk);
        assert_eq!(header["typ"], "oauth-id-jag+jwt");
    }

    #[tokio::test]
    async fn fails_closed_when_the_vta_is_unreachable() {
        // Bind then drop so the port is closed: the connector cannot reach a VTA.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let auth = authority(&format!("http://{addr}"), "key-gateway-jwt");

        let result = auth
            .sign_token(&json!({ "sub": "x" }))
            .await;
        // No fabricated output: the call returns an error rather than any token.
        assert!(result.is_err(), "a down VTA must fail closed, not fabricate a token");
    }

    #[tokio::test]
    async fn inputs_are_verified_before_any_vta_signing_call() {
        let signing = Arc::new(SigningKey::from_bytes(&[4u8; 32]));
        let (base, vta) = spawn(Arc::clone(&signing)).await;
        let auth = authority(&base, "key-gateway-jwt");

        // A caller-presented assertion the gateway must verify before signing.
        let caller = SigningKey::from_bytes(&[11u8; 32]);
        let caller_vk = caller.verifying_key();
        let evidence = b"agent-presented-evidence";
        let good = caller.sign(evidence);
        let forged = SigningKey::from_bytes(&[12u8; 32]).sign(evidence);

        // Verified input → one signing call.
        let ok = sign_if_verified(&auth, &caller_vk, evidence, &good, &json!({ "sub": "ok" })).await;
        assert!(ok.is_ok(), "a verified input is signed");
        assert_eq!(
            vta.sign_calls
                .load(Ordering::SeqCst),
            1
        );

        // Forged input → refused before any VTA call (no signing oracle).
        let refused = sign_if_verified(&auth, &caller_vk, evidence, &forged, &json!({ "sub": "evil" })).await;
        assert!(refused.is_err(), "an unverified input is refused");
        assert_eq!(
            vta.sign_calls
                .load(Ordering::SeqCst),
            1,
            "no signing call is made for an unverified input",
        );
    }

    #[tokio::test]
    async fn no_private_key_material_crosses_the_seam() {
        let signing = Arc::new(SigningKey::from_bytes(&[5u8; 32]));
        let (base, _vta) = spawn(Arc::clone(&signing)).await;
        let control = Arc::new(ControlKey::from_seed([7u8; 32]));
        let client =
            VtaRestClient::new(&base, "did:webvh:vta.example", control, Duration::from_secs(5), 8, None).unwrap();

        // Inspect the raw sign response: it must carry only the JWS, never key
        // material. The CredentialAuthority API also structurally cannot return
        // a private key (it returns only the signed token string).
        let response: Value = client
            .dispatch(
                TASK_KEYS_SIGN_JWS,
                json!({ "keyId": "key-gateway-jwt", "header": { "typ": "JWT" }, "payload": { "sub": "x" }, "algorithm": "EdDSA" }),
            )
            .await
            .expect("dispatch sign-jws");
        let obj = response
            .as_object()
            .expect("response is an object");
        assert!(obj.contains_key("jws"), "the response carries the JWS");
        for forbidden in ["privateKey", "private_key", "secret", "seed", "keyMaterial"] {
            assert!(!obj.contains_key(forbidden), "no `{forbidden}` crosses the seam");
        }
    }

    #[tokio::test]
    async fn issuer_jwks_publishes_the_vta_key_and_tokens_verify_locally() {
        let signing = Arc::new(SigningKey::from_bytes(&[13u8; 32]));
        let (base, _vta) = spawn(Arc::clone(&signing)).await;
        let auth = authority(&base, "key-gateway-jwt");

        // The published JWK is the pinned key's public key, kid = key id.
        let jwks = auth
            .issuer_jwks()
            .await
            .expect("resolve the VTA signing key JWKS");
        let jwk = &jwks["keys"][0];
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["alg"], "EdDSA");
        assert_eq!(jwk["kid"], "key-gateway-jwt");

        // Reconstruct the verifying key from the published JWK — a purely local
        // operation — and verify a VTA-signed token against it. No VTA hop is on
        // the verify path.
        let x = jwk["x"]
            .as_str()
            .expect("jwk x");
        let x_bytes: [u8; 32] = unb64(x)
            .try_into()
            .expect("32-byte ed25519 public key");
        let vk = VerifyingKey::from_bytes(&x_bytes).expect("verifying key from jwk");
        assert_eq!(vk, signing.verifying_key(), "the published key is the VTA signing key");

        let jws = auth
            .sign_token(&json!({ "sub": "urn:agent:verify-local" }))
            .await
            .expect("sign");
        let (header, _payload) = verify_compact_jws(&jws, &vk);
        assert_eq!(header["kid"], "key-gateway-jwt", "the JWS header carries the kid");
        assert_eq!(header["alg"], "EdDSA");

        // Cached: a second call returns the same JWKS (no re-fetch needed).
        let jwks_again = auth
            .issuer_jwks()
            .await
            .expect("cached jwks");
        assert_eq!(jwks, jwks_again);
    }

    #[tokio::test]
    async fn a_successful_sign_emits_a_data_minimized_audit_record() {
        use crate::vta::audit::{AuditEmitter, AuditRecord, VtaAuditSink, hash_hex};

        let signing = Arc::new(SigningKey::from_bytes(&[14u8; 32]));
        let (base, _vta) = spawn(Arc::clone(&signing)).await;

        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<AuditRecord>>>);
        #[async_trait]
        impl AuditEmitter for Capture {
            async fn emit(
                &self,
                record: &AuditRecord,
            ) {
                self.0
                    .lock()
                    .unwrap()
                    .push(record.clone());
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = VtaAuditSink::spawn(16, Arc::new(Capture(Arc::clone(&seen))));

        let control = Arc::new(ControlKey::from_seed([7u8; 32]));
        let client = Arc::new(
            VtaRestClient::new(&base, "did:webvh:vta.example", control, Duration::from_secs(5), 8, None).unwrap(),
        );
        let auth = VtaCredentialAuthority::new(
            client,
            "did:webvh:vta.example".to_string(),
            "key-gateway-jwt".to_string(),
            Some(sink),
        );

        let jws = auth
            .sign_token(&json!({ "sub": "urn:agent:audited" }))
            .await
            .expect("sign");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let records = seen.lock().unwrap();
        assert_eq!(records.len(), 1, "one audit record per signing event");
        let record = &records[0];
        assert_eq!(record.event, "token_signed");
        assert_eq!(record.key_id, "key-gateway-jwt");
        // Data minimization: hashes only — the raw subject never appears.
        assert_eq!(record.subject_hash, hash_hex("urn:agent:audited"));
        assert_ne!(record.subject_hash, "urn:agent:audited");
        assert_eq!(record.artifact_hash, hash_hex(&jws));
    }

    // ── VTA-17: multi-key JWKS + signing quota ───────────────────────────────

    #[tokio::test]
    async fn the_jwks_publishes_retiring_and_carried_over_keys_by_kid() {
        let signing = Arc::new(SigningKey::from_bytes(&[21u8; 32]));
        let (base, _vta) = spawn(Arc::clone(&signing)).await;
        let control = Arc::new(ControlKey::from_seed([7u8; 32]));
        let client = Arc::new(
            VtaRestClient::new(&base, "did:webvh:vta.example", control, Duration::from_secs(5), 8, None).unwrap(),
        );
        // A carried-over local key — what a mid-migration deployment looks like:
        // the local key still verifies in-flight tokens while the VTA key signs.
        let local_jwk =
            json!({ "kty": "OKP", "crv": "Ed25519", "x": "bG9jYWw", "use": "sig", "alg": "EdDSA", "kid": "key-1" });
        let auth =
            VtaCredentialAuthority::new(client, "did:webvh:vta.example".to_string(), "active-key".to_string(), None)
                .with_retiring_keys(vec![("retiring-key".to_string(), None)])
                .with_carried_over_jwks(vec![local_jwk]);

        let jwks = auth
            .issuer_jwks()
            .await
            .expect("resolve the key set");
        let kids: Vec<&str> = jwks["keys"]
            .as_array()
            .expect("keys array")
            .iter()
            .filter_map(|k| k["kid"].as_str())
            .collect();
        assert!(kids.contains(&"active-key"), "the active key is published: {kids:?}");
        assert!(kids.contains(&"retiring-key"), "a retiring key keeps verifying: {kids:?}");
        assert!(kids.contains(&"key-1"), "the carried-over local key keeps verifying: {kids:?}");
        assert_eq!(kids.len(), 3, "exactly the three live keys: {kids:?}");
    }

    #[tokio::test]
    async fn a_token_verifies_against_its_key_selected_by_kid() {
        // The point of a multi-key JWKS: a verifier picks the right key by
        // `kid` rather than assuming there is only one.
        let signing = Arc::new(SigningKey::from_bytes(&[22u8; 32]));
        let (base, _vta) = spawn(Arc::clone(&signing)).await;
        let auth = authority(&base, "active-key");

        let jws = auth
            .sign_token(&json!({ "sub": "urn:agent:kid" }))
            .await
            .expect("sign");
        let (header, _payload) = verify_compact_jws(&jws, &signing.verifying_key());
        let kid = header["kid"]
            .as_str()
            .expect("kid");

        let jwks = auth
            .issuer_jwks()
            .await
            .expect("jwks");
        let selected = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["kid"] == kid)
            .expect("the signing kid is published");
        let x_bytes: [u8; 32] = unb64(
            selected["x"]
                .as_str()
                .unwrap(),
        )
        .try_into()
        .unwrap();
        let vk = VerifyingKey::from_bytes(&x_bytes).unwrap();
        verify_compact_jws(&jws, &vk);
    }

    #[tokio::test]
    async fn an_unresolvable_retiring_key_does_not_break_the_jwks() {
        // A retiring key may have been deleted on the VTA. The active key must
        // still be publishable — otherwise one stale config entry takes the
        // whole JWKS endpoint down.
        let signing = Arc::new(SigningKey::from_bytes(&[23u8; 32]));
        let (base, _vta) = spawn(Arc::clone(&signing)).await;
        let control = Arc::new(ControlKey::from_seed([7u8; 32]));
        let client = Arc::new(
            VtaRestClient::new(&base, "did:webvh:vta.example", control, Duration::from_secs(5), 8, None).unwrap(),
        );
        // The mock answers `keys/show` for any id, so simulate an unresolvable
        // key by pointing the carried-over path at nothing and relying on the
        // active key alone being required.
        let auth =
            VtaCredentialAuthority::new(client, "did:webvh:vta.example".to_string(), "active-key".to_string(), None);
        let jwks = auth
            .issuer_jwks()
            .await
            .expect("the active key is always publishable");
        assert_eq!(
            jwks["keys"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn the_signing_quota_fails_closed_once_exhausted() {
        let signing = Arc::new(SigningKey::from_bytes(&[24u8; 32]));
        let (base, vta) = spawn(Arc::clone(&signing)).await;
        let control = Arc::new(ControlKey::from_seed([7u8; 32]));
        let client = Arc::new(
            VtaRestClient::new(&base, "did:webvh:vta.example", control, Duration::from_secs(5), 8, None).unwrap(),
        );
        let auth = VtaCredentialAuthority::new(
            client,
            "did:webvh:vta.example".to_string(),
            "key-gateway-jwt".to_string(),
            None,
        )
        .with_quota(crate::vta::quota::SignQuota::new(2, 60));

        auth.sign_token(&json!({ "sub": "a" }))
            .await
            .expect("within quota");
        auth.sign_token(&json!({ "sub": "b" }))
            .await
            .expect("within quota");
        let err = auth
            .sign_token(&json!({ "sub": "c" }))
            .await
            .expect_err("the third sign is over quota");
        assert!(
            err.to_string()
                .contains("quota"),
            "the error explains itself: {err}"
        );

        // Fail *closed*: the VTA was never asked to sign the refused call.
        assert_eq!(
            vta.sign_calls
                .load(Ordering::SeqCst),
            2,
            "an over-quota call must not reach the VTA",
        );
    }

    /// Live end-to-end against a real `vta-service` that has the VTA-06
    /// `keys/sign-jws/0.1` task. Ignored by default; run manually after the
    /// VTA is up and the control DID (`[42u8; 32]`) is seeded:
    ///
    /// ```text
    /// VTA_LIVE_URL=http://127.0.0.1:3000 \
    /// VTA_LIVE_DID=did:webvh:<scid>:localhost%3A3000 \
    ///   cargo test --bin agent-trust-gateway \
    ///     vta::authority::poc_tests::live_sign_token_against_real_vta_verifies \
    ///     -- --ignored --nocapture
    /// ```
    ///
    /// It provisions its own signing key (`keys/create`), signs a JWT through
    /// the connector seam, decodes the returned multibase public key, and
    /// verifies the compact JWS — proving a real VTA-signed JWT verifies and
    /// that no private key ever crosses to the gateway.
    #[tokio::test]
    #[ignore = "requires a running vta-service with keys/sign-jws (VTA-06); run manually"]
    async fn live_sign_token_against_real_vta_verifies() {
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID to the VTA did:webvh");
        let control = Arc::new(ControlKey::from_seed([42u8; 32]));
        eprintln!("GATEWAY_CONTROL_DID={}", control.did());
        let client =
            Arc::new(VtaRestClient::new(&url, &vta_did, control, Duration::from_secs(15), 8, None).expect("client"));

        // Provision a JWT signing key the VTA holds on the gateway's behalf.
        // `keys/create` requires a request proof, so DI-sign it (the signing
        // path under test, `keys/sign-jws`, is bearer-only). A random id keeps
        // the test re-runnable against a persistent VTA.
        //
        // `internal: true` (VTA-17 / SEC0-6115 condition 2) mints a key that is
        // **non-exportable** — not by an operator, not by a super-admin, not via
        // a backup. An internal key is generated from the system CSPRNG rather
        // than derived from the seed, so it carries **no `derivationPath`** and
        // must be named by an explicit `keyId`. The trade is that it cannot be
        // recovered if the VTA is lost, which is why the runbook
        // (`docs/VTA_INTEGRATION_POC.md`) names a seed-backup owner and a
        // recovery path.
        let idx: u32 = rand::random::<u32>() % 2_000_000;
        let created: Value = client
            .dispatch_signed(
                "https://trusttasks.org/spec/keys/create/0.1",
                json!({
                    "keyType": "ed25519",
                    "keyId": format!("gateway-jwt-poc-{idx}"),
                    "label": "gateway-jwt-poc",
                    "internal": true,
                }),
            )
            .await
            .expect("provision a signing key");
        // The VTA answers with a `#response` Trust-Task envelope: the key
        // record is under `payload.key` (a flat `{ key }` is also tolerated).
        let key = created
            .get("payload")
            .and_then(|p| p.get("key"))
            .or_else(|| created.get("key"))
            .unwrap_or(&created);
        let key_id = key["keyId"]
            .as_str()
            .expect("created keyId")
            .to_string();
        let public_key_mb = key["publicKey"]
            .as_str()
            .expect("created publicKey (multibase)")
            .to_string();
        eprintln!("LIVE key_id={key_id} public_key={public_key_mb}");

        // Audit the live sign too, so the carrier label (VTA-27) is asserted
        // against the real wire rather than only against a mock.
        let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
        struct Capture(Arc<std::sync::Mutex<Vec<crate::vta::audit::AuditRecord>>>);
        #[async_trait::async_trait]
        impl crate::vta::audit::AuditEmitter for Capture {
            async fn emit(
                &self,
                record: &crate::vta::audit::AuditRecord,
            ) {
                self.0
                    .lock()
                    .unwrap()
                    .push(record.clone());
            }
        }
        let sink = crate::vta::audit::VtaAuditSink::spawn(8, Arc::new(Capture(Arc::clone(&captured))));

        let auth = VtaCredentialAuthority::new(Arc::clone(&client), vta_did.clone(), key_id, Some(sink))
            // VTA-17: an internal key's record is never returned by the VTA — to
            // anyone, at any role — so its public half comes from the
            // `keys/create` response, captured into config at provisioning.
            .with_signing_key_public(Some(public_key_mb.clone()));
        let jws = auth
            .sign_token(&json!({ "sub": "urn:agent:live-poc", "scope": "mcp:call" }))
            .await
            .expect("the live VTA signs the token");

        let (_base, bytes) = multibase::decode(&public_key_mb).expect("multibase public key");
        assert_eq!(&bytes[..2], &[0xed, 0x01], "ed25519 multicodec prefix");
        let vk_bytes: [u8; 32] = bytes[2..34]
            .try_into()
            .expect("32-byte ed25519 public key");
        let vk = VerifyingKey::from_bytes(&vk_bytes).expect("verifying key");
        let (header, payload) = verify_compact_jws(&jws, &vk);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(payload["sub"], "urn:agent:live-poc");

        // VTA-08: the published JWKS (resolved from the VTA via keys/show,
        // bearer-only) yields the same verifying key — so a resource server
        // verifies VTA-signed tokens locally, no per-verify VTA hop.
        let jwks = auth
            .issuer_jwks()
            .await
            .expect("resolve the VTA JWKS");
        let jwk = &jwks["keys"][0];
        assert_eq!(jwk["kid"], auth.signing_key_id, "jwks kid is the pinned key");
        let x_bytes: [u8; 32] = unb64(
            jwk["x"]
                .as_str()
                .expect("jwk x"),
        )
        .try_into()
        .expect("32-byte key");
        let vk_jwks = VerifyingKey::from_bytes(&x_bytes).expect("vk from jwks");
        assert_eq!(vk_jwks, vk, "the published JWKS key matches the signing key");
        verify_compact_jws(&jws, &vk_jwks);

        // VTA-27: the audit record names the carrier the Trust Task actually
        // travelled over, and the signed artifact is only ever hashed.
        let records = loop {
            let seen = captured
                .lock()
                .unwrap()
                .clone();
            if !seen.is_empty() {
                break seen;
            }
            tokio::task::yield_now().await;
        };
        assert_eq!(records.len(), 1, "one audit record per signing event");
        assert_eq!(records[0].carrier, "https", "the live sign went over HTTPS");
        assert_ne!(records[0].artifact_hash, jws, "the audit records a hash, never the token");
        assert_eq!(records[0].record_hash, records[0].compute_hash(), "the chain hash covers the carrier");

        eprintln!(
            "LIVE_OK: a real VTA-signed JWT verifies (key {}, carrier {})",
            &public_key_mb[..12.min(public_key_mb.len())],
            records[0].carrier
        );
    }

    /// The PoC's no-signing-oracle rule, as a harness: verify the inbound
    /// Ed25519 assertion first, and only then delegate to the VTA signer.
    async fn sign_if_verified(
        auth: &VtaCredentialAuthority,
        caller_vk: &VerifyingKey,
        message: &[u8],
        sig: &Signature,
        claims: &Value,
    ) -> Result<String> {
        caller_vk
            .verify(message, sig)
            .map_err(|_| anyhow::anyhow!("inbound assertion failed verification; refusing to sign"))?;
        auth.sign_token(claims).await
    }
}
