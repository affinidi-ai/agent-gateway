//! Rotating the gateway's control key on a trust agent with `acl/swap-key/0.1`.
//!
//! The control key is the credential the gateway authenticates with, and for a
//! `did:key` the identifier *is* the key, so replacing it means moving the
//! gateway's access entry to a new DID. The trust agent does that in one atomic
//! step: the gateway, authenticated with its **current** key, names the new DID
//! and sends a short proof, signed by the **new** key, that the new key agrees
//! to take the entry over. The agent copies the entry exactly (role, contexts,
//! capabilities, expiry), so a swap can never widen access, and writes the new
//! entry before deleting the old one, so a failure part-way never locks the
//! gateway out.
//!
//! The same risk as any key rotation applies: whoever holds the current key can
//! rotate it to one of their own. Recovery is an operator re-granting the
//! gateway on the trust agent, and the agent audits every swap.
//!
//! ## Order matters
//!
//! The new key is persisted as *pending* before the swap is sent, so a crash
//! between the swap and the promotion loses nothing: [`settle_pending`] finds
//! the pending key at the next start and finishes the job. Both keys exist
//! until the new one has authenticated once.
//!
//! ## Why this is a command, not a live endpoint
//!
//! A trust agent supersedes a DID's session when that DID authenticates again,
//! and the running gateway's connector holds the old key in memory. Run it with
//! the gateway stopped (`agent-gateway --vta-rotate-control-key --yes`); the
//! next start reads the new key.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde_json::{Value, json};

use super::client::VtaRestClient;
use super::control_key::{ControlKey, SignerKeyProvider};
use super::error::VtaError;
use crate::config::vta::VtaConfig;

const TASK_ACL_SWAP_KEY: &str = "https://trusttasks.org/spec/acl/swap-key/0.1";

/// How long the new key's proof of consent is valid. Short: it is used at once.
const LINK_PROOF_TTL_SECS: u64 = 120;

/// The pending key, beside the current one so it inherits encryption at rest.
pub fn pending_key_path(control_key_path: &Path) -> PathBuf {
    let mut name = control_key_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".next");
    control_key_path.with_file_name(name)
}

/// The proof, signed by the **new** key, that it agrees to take over the
/// gateway's access entry: a compact EdDSA JWS carrying a presentation of the
/// type the trust agent expects, bound to that agent by `aud` and to a short
/// lifetime by `exp`.
pub async fn build_link_proof(
    new_key: &dyn SignerKeyProvider,
    vta_did: &str,
    now: u64,
    ttl_secs: u64,
) -> Result<String, VtaError> {
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": new_key.verification_method() });
    let payload = json!({
        "iss": new_key.did(),
        "aud": vta_did,
        "exp": now + ttl_secs,
        "vp": {
            "type": ["VerifiablePresentation", "AclSwapRequest"],
            "holder": new_key.did(),
        },
    });
    let encode = |value: &Value| -> Result<String, VtaError> {
        serde_json::to_vec(value)
            .map(|bytes| B64URL.encode(bytes))
            .map_err(|e| VtaError::Signing(format!("could not encode the link proof: {e}")))
    };
    let signing_input = format!("{}.{}", encode(&header)?, encode(&payload)?);
    let signature = new_key
        .sign(signing_input.as_bytes())
        .await?;
    Ok(format!("{signing_input}.{}", B64URL.encode(signature)))
}

/// What a rotation changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotated {
    pub previous_did: String,
    pub new_did: String,
}

async fn read_seed(path: &Path) -> Result<Option<[u8; 32]>, VtaError> {
    match crate::encryption::secret_file::read_secret_file(path)
        .await
        .map_err(|e| VtaError::Config(format!("could not read a control key: {e}")))?
    {
        Some(hex) => Ok(Some(super::decode_hex_seed(hex.trim())?)),
        None => Ok(None),
    }
}

/// The DID of the control key stored at `path`, if there is one. Public data:
/// what an operator re-grants after restoring a backup taken before a rotation.
pub async fn stored_control_did(path: &Path) -> Result<Option<String>, VtaError> {
    Ok(read_seed(path)
        .await?
        .map(|seed| {
            ControlKey::from_seed(seed)
                .did()
                .to_string()
        }))
}

async fn write_seed(
    path: &Path,
    key: &ControlKey,
) -> Result<(), VtaError> {
    crate::encryption::secret_file::write_secret_file(path, &key.seed_hex())
        .await
        .map_err(|e| VtaError::Config(format!("could not persist a control key: {e}")))
}

async fn remove_secret(path: &Path) {
    for candidate in [path.to_path_buf(), crate::encryption::secret_file::secret_enc_path(path)] {
        let _ = tokio::fs::remove_file(candidate).await;
    }
}

fn client_for(
    config: &VtaConfig,
    vta_did: &str,
    key: ControlKey,
) -> Result<VtaRestClient, VtaError> {
    let base_url = config
        .base_url
        .as_deref()
        .ok_or_else(|| VtaError::Config("[vta] base_url is required".to_string()))?;
    VtaRestClient::new(
        base_url,
        vta_did,
        Arc::new(key) as Arc<dyn SignerKeyProvider>,
        Duration::from_millis(config.timeout_ms),
        config.max_concurrent,
        None,
    )
}

/// Promote the pending key to the current one and drop the old.
async fn promote(
    control_key_path: &Path,
    new_key: &ControlKey,
) -> Result<(), VtaError> {
    write_seed(control_key_path, new_key).await?;
    remove_secret(&pending_key_path(control_key_path)).await;
    Ok(())
}

/// Why a live rotation did not happen.
#[derive(Debug)]
pub enum RotateLiveError {
    /// Another rotation is already running in this process.
    InProgress,
    Failed(VtaError),
}

impl From<VtaError> for RotateLiveError {
    fn from(e: VtaError) -> Self {
        Self::Failed(e)
    }
}

static ROTATING: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<PathBuf>>> = std::sync::OnceLock::new();

fn rotating() -> &'static std::sync::Mutex<std::collections::HashSet<PathBuf>> {
    ROTATING.get_or_init(Default::default)
}

/// Marks the control key at a path as being rotated, until dropped.
struct Rotating(PathBuf);

impl Rotating {
    fn begin(path: &Path) -> Option<Self> {
        let mut running = rotating()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        running
            .insert(path.to_path_buf())
            .then(|| Self(path.to_path_buf()))
    }
}

impl Drop for Rotating {
    fn drop(&mut self) {
        rotating()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.0);
    }
}

/// Move the access entry that `client` authenticates as to a new key, through
/// `client` itself. The old DID is never authenticated a second time, which
/// would supersede the session the caller is using.
async fn swap_to_new_key(
    client: &VtaRestClient,
    config: &VtaConfig,
    vta_did: &str,
    control_key_path: &Path,
    previous_did: &str,
) -> Result<(Rotated, ControlKey), VtaError> {
    let new_key = ControlKey::generate();
    let new_did = new_key.did().to_string();
    // Before the swap, never after: a crash in between must lose nothing.
    write_seed(&pending_key_path(control_key_path), &new_key).await?;

    let now = chrono::Utc::now()
        .timestamp()
        .max(0) as u64;
    let link_proof = build_link_proof(&new_key, vta_did, now, LINK_PROOF_TTL_SECS).await?;
    let response: Value = match client
        .dispatch_signed(
            TASK_ACL_SWAP_KEY,
            json!({
                "currentSubject": previous_did,
                "newSubject": new_did,
                "linkProof": link_proof,
            }),
        )
        .await
    {
        Ok(response) => response,
        Err(e) => {
            // A definitive refusal means nothing moved, so the pending key is
            // dead weight. Anything else (a timeout) leaves it for
            // `settle_pending`, which asks the trust agent which key is live.
            if matches!(e, VtaError::Http { status: 400..=499, .. }) {
                remove_secret(&pending_key_path(control_key_path)).await;
            }
            return Err(e);
        }
    };
    let body = super::context_identity::payload_of(&response);
    let moved_to = body
        .get("entry")
        .and_then(|e| e.get("subject"))
        .and_then(Value::as_str);
    if moved_to != Some(new_did.as_str()) {
        return Err(VtaError::Protocol(format!(
            "the trust agent answered the swap with subject {moved_to:?}, not the new DID"
        )));
    }

    let proof_of_life = client_for(config, vta_did, ControlKey::from_seed(new_key.seed_bytes()))?;
    proof_of_life
        .authenticate()
        .await?;
    promote(control_key_path, &new_key).await?;
    Ok((
        Rotated {
            previous_did: previous_did.to_string(),
            new_did,
        },
        new_key,
    ))
}

/// Finds the control key stored for the bundled trust agent, finishing a
/// rotation that a crash interrupted first.
pub struct StoredKeyReloader {
    config: VtaConfig,
    vta_did: String,
    control_key_path: PathBuf,
}

impl StoredKeyReloader {
    pub fn new(
        config: VtaConfig,
        vta_did: String,
        control_key_path: PathBuf,
    ) -> Self {
        Self {
            config,
            vta_did,
            control_key_path,
        }
    }
}

#[async_trait::async_trait]
impl super::control_key::ControlKeyReloader for StoredKeyReloader {
    async fn reload(&self) -> Option<Arc<dyn SignerKeyProvider>> {
        // A rotation running right now settles its own pending key.
        let _quiet = Rotating::begin(&self.control_key_path)?;
        if let Err(e) = settle_pending(&self.config, &self.vta_did, &self.control_key_path).await {
            tracing::warn!(target: "vta_audit", "could not settle a pending control key: {}", e.log_detail());
        }
        let seed = read_seed(&self.control_key_path)
            .await
            .ok()??;
        Some(Arc::new(ControlKey::from_seed(seed)))
    }
}

/// Rotate the control key at `control_key_path` on the trust agent `vta_did`,
/// with nothing else running (the offline command).
pub async fn rotate(
    config: &VtaConfig,
    vta_did: &str,
    control_key_path: &Path,
) -> Result<Rotated, VtaError> {
    let current_seed = read_seed(control_key_path)
        .await?
        .ok_or_else(|| VtaError::Config("there is no control key to rotate".to_string()))?;
    let current = ControlKey::from_seed(current_seed);
    let previous_did = current.did().to_string();
    let client = client_for(config, vta_did, current)?;
    swap_to_new_key(&client, config, vta_did, control_key_path, &previous_did)
        .await
        .map(|(rotated, _)| rotated)
}

/// Rotate the control key while the gateway runs, through its shared `client`,
/// which authenticates as the new DID from then on.
///
/// A pending key left by an interrupted rotation is settled first rather than
/// overwritten: if its swap happened it is the only key the trust agent
/// accepts. Only one rotation runs at a time.
pub async fn rotate_live(
    client: &VtaRestClient,
    config: &VtaConfig,
    vta_did: &str,
    control_key_path: &Path,
) -> Result<Rotated, RotateLiveError> {
    let _running = Rotating::begin(control_key_path).ok_or(RotateLiveError::InProgress)?;

    if let Some(settled) = settle_pending(config, vta_did, control_key_path).await? {
        let seed = read_seed(control_key_path)
            .await?
            .ok_or_else(|| VtaError::Config("the settled control key is missing".to_string()))?;
        client
            .replace_control_key(Arc::new(ControlKey::from_seed(seed)))
            .await;
        return Ok(settled);
    }

    let seed = read_seed(control_key_path)
        .await?
        .ok_or_else(|| VtaError::Config("there is no control key to rotate".to_string()))?;
    let on_disk = ControlKey::from_seed(seed);
    if on_disk.did() != client.control_did() {
        client
            .replace_control_key(Arc::new(on_disk))
            .await;
    }
    let previous_did = client.control_did();
    let (rotated, new_key) = swap_to_new_key(client, config, vta_did, control_key_path, &previous_did).await?;
    client
        .replace_control_key(Arc::new(new_key))
        .await;
    Ok(rotated)
}

/// Finish, or abandon, a rotation that a crash interrupted.
///
/// If the pending key can authenticate, the swap happened: promote it. If the
/// trust agent refuses it, the swap never happened: the current key is still
/// the one, so drop the pending key. If the agent cannot be reached the answer
/// is unknown, and the error says so rather than guessing.
pub async fn settle_pending(
    config: &VtaConfig,
    vta_did: &str,
    control_key_path: &Path,
) -> Result<Option<Rotated>, VtaError> {
    let pending_path = pending_key_path(control_key_path);
    let Some(pending_seed) = read_seed(&pending_path).await? else {
        return Ok(None);
    };
    let pending = ControlKey::from_seed(pending_seed);
    let client = client_for(config, vta_did, ControlKey::from_seed(pending_seed))?;
    match client.authenticate().await {
        Ok(()) => {
            let previous_did = match read_seed(control_key_path).await? {
                Some(seed) => ControlKey::from_seed(seed)
                    .did()
                    .to_string(),
                None => String::new(),
            };
            promote(control_key_path, &pending).await?;
            Ok(Some(Rotated {
                previous_did,
                new_did: pending.did().to_string(),
            }))
        }
        Err(VtaError::Http { status: 401 | 403, .. }) => {
            remove_secret(&pending_path).await;
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    const VTA: &str = "did:key:z6MkvnxZrB5vsAFb8AGaDVAqSYYNoz5y2Rgvhccn7xSvx3Aj";

    fn segments(proof: &str) -> (Value, Value, Vec<u8>, String) {
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "a compact JWS has three segments");
        let decode = |s: &str| {
            B64URL
                .decode(s)
                .expect("base64url")
        };
        (
            serde_json::from_slice(&decode(parts[0])).expect("header"),
            serde_json::from_slice(&decode(parts[1])).expect("payload"),
            decode(parts[2]),
            format!("{}.{}", parts[0], parts[1]),
        )
    }

    #[tokio::test]
    async fn the_link_proof_has_the_shape_the_trust_agent_verifies() {
        let key = ControlKey::from_seed([9u8; 32]);

        let proof = build_link_proof(&key, VTA, 1_000, 120)
            .await
            .expect("proof");

        let (header, payload, _, _) = segments(&proof);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], key.verification_method(), "the kid names the new did:key's own method");
        assert_eq!(payload["iss"], key.did());
        assert_eq!(payload["aud"], VTA, "bound to this trust agent");
        assert_eq!(payload["exp"], 1_120, "short-lived");
        assert_eq!(payload["vp"]["holder"], key.did());
        assert_eq!(payload["vp"]["type"], json!(["VerifiablePresentation", "AclSwapRequest"]));
    }

    #[tokio::test]
    async fn the_link_proof_is_signed_by_the_new_key_and_by_nothing_else() {
        let key = ControlKey::from_seed([9u8; 32]);
        let other = ControlKey::from_seed([10u8; 32]);
        let proof = build_link_proof(&key, VTA, 1_000, 120)
            .await
            .expect("proof");
        let (_, _, signature, input) = segments(&proof);
        let signature = Signature::from_slice(&signature).expect("64 bytes");

        let verifying = |seed: [u8; 32]| ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        assert!(
            verifying([9u8; 32])
                .verify(input.as_bytes(), &signature)
                .is_ok()
        );
        assert!(
            verifying(other.seed_bytes())
                .verify(input.as_bytes(), &signature)
                .is_err(),
            "another key's signature must not verify"
        );
    }

    #[test]
    fn the_pending_key_sits_beside_the_current_one() {
        let path = Path::new("/store/vta_appliance_control_key");
        assert_eq!(pending_key_path(path), Path::new("/store/vta_appliance_control_key.next"));
    }

    use std::sync::Mutex;

    use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};

    #[derive(Clone)]
    struct Mock(Arc<Mutex<MockVta>>);

    struct MockVta {
        allowed: Vec<String>,
        refuse_swap: bool,
        swaps: Vec<(String, String)>,
        auths: Vec<String>,
        challenges: Vec<String>,
        wrong_subject: bool,
    }

    /// The new subject's public key, read out of its did:key as the trust agent
    /// does, to check the link proof's signature.
    fn verifying_key(did: &str) -> ed25519_dalek::VerifyingKey {
        let (_, bytes) = multibase::decode(
            did.strip_prefix("did:key:")
                .expect("did:key"),
        )
        .expect("multibase");
        ed25519_dalek::VerifyingKey::from_bytes(
            bytes[2..]
                .try_into()
                .expect("32 bytes"),
        )
        .expect("key")
    }

    fn check_link_proof(
        proof: &str,
        new_subject: &str,
    ) -> Result<(), String> {
        let (header, payload, signature, input) = segments(proof);
        let now = chrono::Utc::now().timestamp() as u64;
        if payload["aud"] != VTA {
            return Err("audience is not this trust agent".into());
        }
        if payload["exp"]
            .as_u64()
            .unwrap_or(0)
            <= now
        {
            return Err("the proof has expired".into());
        }
        if payload["iss"] != new_subject || payload["vp"]["holder"] != new_subject {
            return Err("the proof is not by the new subject".into());
        }
        if header["kid"]
            .as_str()
            .is_none_or(|k| !k.starts_with(new_subject))
        {
            return Err("the kid is not the new subject's".into());
        }
        let signature = Signature::from_slice(&signature).map_err(|e| e.to_string())?;
        verifying_key(new_subject)
            .verify(input.as_bytes(), &signature)
            .map_err(|e| e.to_string())
    }

    async fn trust_tasks(
        State(mock): State<Mock>,
        Json(body): Json<Value>,
    ) -> axum::response::Response {
        let task = body["type"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let mut vta = mock.0.lock().unwrap();
        let issuer = body["issuer"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let denied =
            || (StatusCode::FORBIDDEN, Json(json!({ "payload": { "code": "permissionDenied" } }))).into_response();
        if task.contains("auth/challenge") {
            vta.challenges.push(
                body["payload"]["subject"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
            return Json(json!({ "challenge": "c", "sessionId": "s" })).into_response();
        }
        if task.contains("auth/authenticate") {
            if !vta.allowed.contains(&issuer) {
                return denied();
            }
            vta.auths.push(issuer.clone());
            return Json(json!({ "session": { "id": "s" }, "tokens": { "accessToken": "t", "expiresIn": 3600 } }))
                .into_response();
        }
        if task.contains("acl/swap-key") {
            let payload = &body["payload"];
            let (current, new) = (
                payload["currentSubject"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                payload["newSubject"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
            if vta.refuse_swap || current != issuer || !vta.allowed.contains(&current) || body.get("proof").is_none() {
                return denied();
            }
            if check_link_proof(
                payload["linkProof"]
                    .as_str()
                    .unwrap_or_default(),
                &new,
            )
            .is_err()
            {
                return denied();
            }
            vta.allowed
                .retain(|d| d != &current);
            vta.allowed.push(new.clone());
            vta.swaps
                .push((current.clone(), new.clone()));
            let reported = if vta.wrong_subject {
                current.clone()
            } else {
                new
            };
            return Json(json!({ "payload": { "entry": { "subject": reported }, "previousSubject": current } }))
                .into_response();
        }
        (StatusCode::BAD_REQUEST, Json(json!({ "error": "unexpected task" }))).into_response()
    }

    async fn serve(mock: &Mock) -> String {
        let app = Router::new()
            .route("/trust-tasks", post(trust_tasks))
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap()
        });
        format!("http://{addr}")
    }

    fn config(base_url: &str) -> VtaConfig {
        VtaConfig {
            base_url: Some(base_url.to_string()),
            ..VtaConfig::default()
        }
    }

    async fn enrolled_gateway(
        mock: &Mock,
        dir: &Path,
    ) -> (PathBuf, ControlKey) {
        let key = ControlKey::generate();
        mock.0
            .lock()
            .unwrap()
            .allowed
            .push(key.did().to_string());
        let path = dir.join("vta_appliance_control_key");
        write_seed(&path, &key)
            .await
            .unwrap();
        (path, key)
    }

    fn new_mock() -> Mock {
        Mock(Arc::new(Mutex::new(MockVta {
            allowed: Vec::new(),
            refuse_swap: false,
            swaps: Vec::new(),
            auths: Vec::new(),
            challenges: Vec::new(),
            wrong_subject: false,
        })))
    }

    #[tokio::test]
    async fn a_rotation_moves_the_access_entry_and_the_gateway_signs_in_as_the_new_key() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;
        let url = serve(&mock).await;

        let rotated = rotate(&config(&url), VTA, &path)
            .await
            .expect("rotate");

        assert_eq!(rotated.previous_did, old.did());
        assert_ne!(rotated.new_did, old.did());
        assert_eq!(
            mock.0.lock().unwrap().allowed,
            std::slice::from_ref(&rotated.new_did),
            "the entry moved; the old DID is gone"
        );
        assert_eq!(mock.0.lock().unwrap().swaps, [(old.did().to_string(), rotated.new_did.clone())]);
        let current = ControlKey::from_seed(
            read_seed(&path)
                .await
                .unwrap()
                .expect("current"),
        );
        assert_eq!(current.did(), rotated.new_did, "the current key is the new one");
        assert!(
            read_seed(&pending_key_path(&path))
                .await
                .unwrap()
                .is_none(),
            "nothing is left pending"
        );
    }

    fn running_client(
        url: &str,
        key: &ControlKey,
    ) -> VtaRestClient {
        client_for(&config(url), VTA, ControlKey::from_seed(key.seed_bytes())).expect("client")
    }

    fn auths_as(
        mock: &Mock,
        did: &str,
    ) -> usize {
        mock.0
            .lock()
            .unwrap()
            .auths
            .iter()
            .filter(|d| d.as_str() == did)
            .count()
    }

    #[tokio::test]
    async fn a_live_rotation_moves_the_entry_without_authenticating_the_old_did_again() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;
        let url = serve(&mock).await;
        let client = running_client(&url, &old);
        client
            .authenticate()
            .await
            .unwrap();

        let rotated = rotate_live(&client, &config(&url), VTA, &path)
            .await
            .expect("rotate");

        assert_eq!(rotated.previous_did, old.did());
        assert_eq!(auths_as(&mock, old.did()), 1, "the old DID signed in once, before the rotation");
        assert_eq!(mock.0.lock().unwrap().allowed, std::slice::from_ref(&rotated.new_did));
    }

    #[tokio::test]
    async fn a_live_rotation_switches_the_running_client_to_the_new_did() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;
        let url = serve(&mock).await;
        let client = running_client(&url, &old);
        client
            .authenticate()
            .await
            .unwrap();

        let rotated = rotate_live(&client, &config(&url), VTA, &path)
            .await
            .expect("rotate");

        assert_eq!(client.control_did(), rotated.new_did);
        client
            .access_token()
            .await
            .expect("the client signs in as the new DID");
        assert_eq!(auths_as(&mock, &rotated.new_did), 2, "the proof of life, then the running client");
        assert_eq!(
            ControlKey::from_seed(
                read_seed(&path)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .did(),
            rotated.new_did,
            "the new key is the one on disk"
        );
    }

    fn reloading_client(
        url: &str,
        held: &ControlKey,
        path: &Path,
    ) -> VtaRestClient {
        running_client(url, held).with_key_reloader(Arc::new(StoredKeyReloader::new(
            config(url),
            VTA.to_string(),
            path.to_path_buf(),
        )))
    }

    #[tokio::test]
    async fn a_refused_authentication_reloads_a_rotated_key_and_retries_once() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, _enrolled) = enrolled_gateway(&mock, dir.path()).await;
        let url = serve(&mock).await;
        let held_by_the_client = ControlKey::generate();

        let client = reloading_client(&url, &held_by_the_client, &path);
        client
            .authenticate()
            .await
            .expect("the stored key signs in");

        let stored = ControlKey::from_seed(
            read_seed(&path)
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(client.control_did(), stored.did());
        assert_eq!(auths_as(&mock, stored.did()), 1);
        assert_eq!(
            mock.0
                .lock()
                .unwrap()
                .challenges,
            [
                held_by_the_client
                    .did()
                    .to_string(),
                stored.did().to_string()
            ],
            "one try with the held key, one with the stored one"
        );
    }

    #[tokio::test]
    async fn a_refused_authentication_with_the_same_key_on_disk_fails_as_before() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("vta_appliance_control_key");
        let refused = ControlKey::generate();
        write_seed(&path, &refused)
            .await
            .unwrap();
        let url = serve(&mock).await;
        let client = reloading_client(&url, &refused, &path);

        let err = client
            .authenticate()
            .await
            .expect_err("refused");

        assert!(matches!(err, VtaError::Http { status: 403, .. }), "{err:?}");
        assert_eq!(
            mock.0
                .lock()
                .unwrap()
                .challenges
                .len(),
            1,
            "no second attempt with the same key"
        );
    }

    #[tokio::test]
    async fn a_pending_key_found_on_refusal_is_settled_first() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("vta_appliance_control_key");
        let old = ControlKey::generate();
        let pending = ControlKey::generate();
        write_seed(&path, &old)
            .await
            .unwrap();
        write_seed(&pending_key_path(&path), &pending)
            .await
            .unwrap();
        mock.0.lock().unwrap().allowed = vec![pending.did().to_string()];
        let url = serve(&mock).await;
        let client = reloading_client(&url, &old, &path);

        client
            .authenticate()
            .await
            .expect("the pending key was settled and used");

        assert_eq!(client.control_did(), pending.did());
        assert!(
            read_seed(&pending_key_path(&path))
                .await
                .unwrap()
                .is_none(),
            "promoted"
        );
        assert_eq!(
            read_seed(&path)
                .await
                .unwrap()
                .unwrap(),
            pending.seed_bytes()
        );
    }

    #[tokio::test]
    async fn the_stored_control_did_is_the_one_on_disk_and_only_that() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, key) = enrolled_gateway(&mock, dir.path()).await;

        assert_eq!(
            stored_control_did(&path)
                .await
                .unwrap()
                .as_deref(),
            Some(key.did())
        );
        assert_eq!(
            stored_control_did(&dir.path().join("absent"))
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn a_refused_live_swap_keeps_the_old_key_and_removes_the_pending_one() {
        let mock = new_mock();
        mock.0
            .lock()
            .unwrap()
            .refuse_swap = true;
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;
        let url = serve(&mock).await;
        let client = running_client(&url, &old);

        let err = rotate_live(&client, &config(&url), VTA, &path)
            .await
            .expect_err("refused");

        assert!(matches!(err, RotateLiveError::Failed(VtaError::Http { status: 403, .. })), "{err:?}");
        assert_eq!(client.control_did(), old.did());
        assert!(
            read_seed(&pending_key_path(&path))
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(mock.0.lock().unwrap().allowed, [old.did().to_string()]);
    }

    #[tokio::test]
    async fn a_timed_out_live_swap_keeps_the_pending_key_for_the_next_start() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;
        let client = running_client("http://127.0.0.1:1", &old);

        let err = rotate_live(&client, &config("http://127.0.0.1:1"), VTA, &path)
            .await
            .expect_err("unreachable");

        assert!(matches!(err, RotateLiveError::Failed(VtaError::Transport(_))), "{err:?}");
        assert_eq!(client.control_did(), old.did());
        assert!(
            read_seed(&pending_key_path(&path))
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn a_present_pending_key_is_settled_not_overwritten() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;
        let url = serve(&mock).await;
        let pending = ControlKey::generate();
        {
            let mut vta = mock.0.lock().unwrap();
            vta.allowed = vec![pending.did().to_string()];
        }
        write_seed(&pending_key_path(&path), &pending)
            .await
            .unwrap();
        let client = running_client(&url, &old);

        let rotated = rotate_live(&client, &config(&url), VTA, &path)
            .await
            .expect("settled");

        assert_eq!(rotated.new_did, pending.did());
        assert_eq!(client.control_did(), pending.did());
        assert!(
            mock.0
                .lock()
                .unwrap()
                .swaps
                .is_empty(),
            "no second swap was sent"
        );
        assert!(
            read_seed(&pending_key_path(&path))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn two_rotations_at_once_are_refused() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;
        let url = serve(&mock).await;
        let client = running_client(&url, &old);
        let _running = Rotating::begin(&path).expect("first");

        let err = rotate_live(&client, &config(&url), VTA, &path)
            .await
            .expect_err("busy");

        assert!(matches!(err, RotateLiveError::InProgress), "{err:?}");
        assert!(
            mock.0
                .lock()
                .unwrap()
                .swaps
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_answer_must_name_the_new_did() {
        let mock = new_mock();
        mock.0
            .lock()
            .unwrap()
            .wrong_subject = true;
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;
        let url = serve(&mock).await;
        let client = running_client(&url, &old);

        let err = rotate_live(&client, &config(&url), VTA, &path)
            .await
            .expect_err("wrong subject");

        assert!(matches!(err, RotateLiveError::Failed(VtaError::Protocol(_))), "{err:?}");
        assert_eq!(client.control_did(), old.did(), "the running client did not move");
        assert!(
            read_seed(&pending_key_path(&path))
                .await
                .unwrap()
                .is_some(),
            "left for the next start to settle"
        );
    }

    #[tokio::test]
    async fn a_refused_swap_changes_nothing_and_leaves_no_pending_key() {
        let mock = new_mock();
        mock.0
            .lock()
            .unwrap()
            .refuse_swap = true;
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;
        let url = serve(&mock).await;

        let err = rotate(&config(&url), VTA, &path)
            .await
            .expect_err("refused");

        assert!(matches!(err, VtaError::Http { status: 403, .. }), "{err:?}");
        assert_eq!(
            ControlKey::from_seed(
                read_seed(&path)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .did(),
            old.did(),
            "still the old key"
        );
        assert!(
            read_seed(&pending_key_path(&path))
                .await
                .unwrap()
                .is_none(),
            "a definitive refusal clears the pending key"
        );
        assert_eq!(mock.0.lock().unwrap().allowed, [old.did().to_string()]);
    }

    #[tokio::test]
    async fn an_unreachable_trust_agent_keeps_the_current_key_and_leaves_the_pending_one_for_later() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, old) = enrolled_gateway(&mock, dir.path()).await;

        let err = rotate(&config("http://127.0.0.1:1"), VTA, &path)
            .await
            .expect_err("unreachable");

        assert!(matches!(err, VtaError::Transport(_)), "{err:?}");
        assert_eq!(
            ControlKey::from_seed(
                read_seed(&path)
                    .await
                    .unwrap()
                    .unwrap()
            )
            .did(),
            old.did()
        );
        assert!(
            read_seed(&pending_key_path(&path))
                .await
                .unwrap()
                .is_some(),
            "an unknown outcome is settled at the next start"
        );
    }

    #[tokio::test]
    async fn settling_with_the_trust_agent_unreachable_reports_it_rather_than_guessing() {
        let mock = new_mock();
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = enrolled_gateway(&mock, dir.path()).await;
        write_seed(&pending_key_path(&path), &ControlKey::generate())
            .await
            .unwrap();

        let err = settle_pending(&config("http://127.0.0.1:1"), VTA, &path)
            .await
            .expect_err("cannot decide");

        assert!(matches!(err, VtaError::Transport(_)), "{err:?}");
        assert!(
            read_seed(&pending_key_path(&path))
                .await
                .unwrap()
                .is_some(),
            "nothing was discarded"
        );
    }

    #[tokio::test]
    async fn a_link_proof_for_another_trust_agent_or_signed_by_another_key_is_refused() {
        let new_key = ControlKey::from_seed([5u8; 32]);
        let now = chrono::Utc::now().timestamp() as u64;
        let good = build_link_proof(&new_key, VTA, now, 120)
            .await
            .unwrap();
        check_link_proof(&good, new_key.did()).expect("the mock's own check accepts a good proof");

        let elsewhere = build_link_proof(&new_key, "did:key:z6MkOther", now, 120)
            .await
            .unwrap();
        assert!(check_link_proof(&elsewhere, new_key.did()).is_err(), "another audience");
        let expired = build_link_proof(&new_key, VTA, now - 1_000, 120)
            .await
            .unwrap();
        assert!(check_link_proof(&expired, new_key.did()).is_err(), "expired");
        let other = ControlKey::from_seed([6u8; 32]);
        assert!(check_link_proof(&good, other.did()).is_err(), "claims a different subject");
    }
}
