//! First-start bootstrap of the bundled sidecar trust agent.
//!
//! The gateway and its sidecar meet through a small folder both can see
//! (`bootstrap_dir`). Public data only ever crosses it:
//!
//! - the gateway writes `gateway-enrolment.env`: its own control DID, for the
//!   sidecar's entrypoint to enrol offline with a fixed, narrow grant;
//! - the sidecar writes `vta-identity.env`: its own DID, which the gateway pins.
//!
//! Nothing here enrols anything. The gateway asks for no rights: the role, the
//! context and the capabilities are fixed by the sidecar's entrypoint, and the
//! gateway then checks it was given **exactly** that ([`Whoami::assert_bundled_grant`]).
//! More than expected is a failure, not a bonus.
//!
//! ## What is never done automatically
//!
//! Re-enrolment, and re-creation of a sidecar that was lost. A revoked gateway
//! stays revoked, and a replaced or emptied sidecar is reported, because a new
//! sidecar means new keys and DIDs and would silently break everything signed
//! before. Both need an operator.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::client::VtaRestClient;
use super::control_key::SignerKeyProvider;
use super::error::VtaError;
use super::onboarding::Whoami;
use crate::config::vta::{BUNDLED_CONTEXT_ID, VtaConfig};

/// The file the gateway writes for the sidecar to enrol.
pub const ENROLMENT_FILE: &str = "gateway-enrolment.env";

/// The file the sidecar writes for the gateway to pin.
pub const IDENTITY_FILE: &str = "vta-identity.env";

/// The gateway's record of a completed bootstrap, beside its other key
/// material so it is encrypted at rest with it.
pub const STATE_FILE: &str = "vta_bundled_state.json";

/// Keys retired by a re-bootstrap, waiting to be carried into the next state.
pub const RETIRED_FILE: &str = "vta_bundled_retired.json";

/// The id of the signing key for a generation. Fixed per generation, so a retry
/// after a timeout adopts the key it already made instead of creating another,
/// and distinct across generations, so a retired key's `kid` is never reused.
pub fn signing_key_id(generation: usize) -> String {
    format!("gateway-jwt-{generation}")
}

const KEY_LABEL: &str = "agent-gateway signing key";
const FORMAT: u32 = 1;
const POLL_FIRST: Duration = Duration::from_millis(250);
const POLL_MAX: Duration = Duration::from_secs(2);
const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

const TASK_KEYS_CREATE: &str = "https://trusttasks.org/spec/keys/create/0.1";

/// Where a bundled bootstrap stands. Anything other than `Connected` is
/// reported, never papered over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapState {
    /// Authenticated, holds exactly the expected grant, and the signing key exists.
    Connected,
    /// The sidecar has not published its identity, or did not answer, in time.
    WaitingForVta,
    /// The sidecar answered but refused the gateway, or granted it the wrong thing.
    EnrolmentRefused,
    /// The sidecar at this address is not the one that was pinned.
    VtaReplaced,
    /// The pinned sidecar answers but no longer holds the gateway's signing key.
    VtaLost,
    /// The gateway used to be connected and the sidecar now refuses it.
    Revoked,
    /// Something on this side is wrong: the control key, the shared folder, or
    /// the identity file.
    Misconfigured,
}

impl BootstrapState {
    /// What an operator should do about it.
    pub fn advice(self) -> &'static str {
        match self {
            Self::Connected => "nothing to do",
            Self::WaitingForVta => "start the bundled trust agent, then restart the gateway",
            Self::EnrolmentRefused => {
                "the bundled trust agent did not enrol this gateway with the expected grant; check its entrypoint log"
            }
            Self::VtaReplaced => {
                "the trust agent at this address is not the one this gateway pinned; investigate before re-bootstrapping"
            }
            Self::VtaLost => {
                "the trust agent lost this gateway's signing key; re-bootstrap with --vta-rebootstrap --yes"
            }
            Self::Revoked => "re-grant this gateway on the trust agent (vta acl create, run offline), then restart",
            Self::Misconfigured => "fix the problem named in the detail and restart the gateway",
        }
    }
}

/// What the gateway recorded when the bootstrap completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledState {
    pub format: u32,
    /// The sidecar's DID, pinned at first contact and never overwritten.
    pub vta_did: String,
    pub base_url: String,
    pub context_id: String,
    /// The DID the gateway enrolled as.
    pub control_did: String,
    pub signing_key_id: String,
    /// Captured when the key was created: the trust agent will not return an
    /// internal key's record afterwards, and without it the key cannot be
    /// published for verification.
    pub signing_key_public: String,
    /// Signing keys of earlier bootstraps, published beside the active one so
    /// tokens they signed still verify.
    #[serde(default)]
    pub retired_keys: Vec<RetiredKey>,
    pub bootstrapped_at: DateTime<Utc>,
}

/// A signing key an earlier bootstrap made, no longer signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredKey {
    pub key_id: String,
    pub public_key: String,
    pub retired_at: DateTime<Utc>,
}

impl BootstrapState {
    /// How an operator reads the state, in a sentence: never the internal name.
    pub fn label(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::WaitingForVta => "waiting for the trust agent",
            Self::EnrolmentRefused => "refusing the gateway",
            Self::VtaReplaced => "not the trust agent this gateway pinned",
            Self::VtaLost => "missing the gateway's signing key",
            Self::Revoked => "no longer granting the gateway access",
            Self::Misconfigured => "not reachable because of a problem on this side",
        }
    }
}

/// The result of one bootstrap, for the status API.
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapStatus {
    pub state: BootstrapState,
    pub advice: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vta_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_did: Option<String>,
    pub context_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrapped_at: Option<DateTime<Utc>>,
    /// A completed bootstrap was recorded before this start. Decides whether a
    /// problem falls back to local signing (never connected) or refuses to sign
    /// (tokens were already issued by the sidecar's key).
    pub previously_connected: bool,
    /// The owner of the sidecar. Always `unclaimed` until a person claims it.
    pub owner: &'static str,
}

static STATUS: OnceLock<RwLock<Option<BootstrapStatus>>> = OnceLock::new();

fn slot() -> &'static RwLock<Option<BootstrapStatus>> {
    STATUS.get_or_init(|| RwLock::new(None))
}

/// The latest bootstrap result, if this gateway runs one.
pub fn status() -> Option<BootstrapStatus> {
    slot()
        .read()
        .ok()
        .and_then(|s| s.clone())
}

fn record(status: BootstrapStatus) {
    if let Ok(mut slot) = slot().write() {
        *slot = Some(status);
    }
}

pub fn state_path(storage: &Path) -> PathBuf {
    storage.join(STATE_FILE)
}

async fn load_state(storage: &Path) -> Result<Option<BundledState>, String> {
    match crate::encryption::secret_file::read_secret_file(&state_path(storage)).await {
        Ok(Some(text)) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| format!("the bundled state record is unreadable: {e}")),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("could not read the bundled state record: {e}")),
    }
}

async fn save_state(
    storage: &Path,
    state: &BundledState,
) -> Result<(), String> {
    let text = serde_json::to_string_pretty(state).map_err(|e| format!("could not encode the bundled state: {e}"))?;
    crate::encryption::secret_file::write_secret_file(&state_path(storage), &text)
        .await
        .map_err(|e| format!("could not persist the bundled state: {e}"))
}

pub fn retired_path(storage: &Path) -> PathBuf {
    storage.join(RETIRED_FILE)
}

async fn load_retired(storage: &Path) -> Result<Vec<RetiredKey>, String> {
    match crate::encryption::secret_file::read_secret_file(&retired_path(storage)).await {
        Ok(Some(text)) => serde_json::from_str(&text).map_err(|e| format!("the retired-key record is unreadable: {e}")),
        Ok(None) => Ok(Vec::new()),
        Err(e) => Err(format!("could not read the retired-key record: {e}")),
    }
}

async fn remove_secret(path: &Path) {
    for candidate in [path.to_path_buf(), crate::encryption::secret_file::secret_enc_path(path)] {
        let _ = tokio::fs::remove_file(candidate).await;
    }
}

/// The enrolment note: public data only.
pub fn enrolment_contents(control_did: &str) -> String {
    format!("FORMAT={FORMAT}\nGATEWAY_CONTROL_DID={control_did}\n")
}

async fn write_enrolment(
    dir: &Path,
    control_did: &str,
) -> Result<(), String> {
    let contents = enrolment_contents(control_did);
    let path = dir.join(ENROLMENT_FILE);
    if tokio::fs::read_to_string(&path)
        .await
        .is_ok_and(|existing| existing == contents)
    {
        return Ok(());
    }
    let temporary = dir.join(format!("{ENROLMENT_FILE}.tmp"));
    tokio::fs::write(&temporary, &contents)
        .await
        .map_err(|e| format!("could not write {}: {e}", temporary.display()))?;
    tokio::fs::rename(&temporary, &path)
        .await
        .map_err(|e| format!("could not publish {}: {e}", path.display()))
}

const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Parse the sidecar's identity file, strictly.
///
/// Only the DID is used. The file also names a base URL, which is deliberately
/// ignored: the gateway talks to the address its own configuration names, so a
/// file anyone with the shared folder could rewrite cannot redirect it.
pub fn parse_identity(text: &str) -> Result<String, String> {
    let mut format = None;
    let mut vta_did = None;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("`{line}` is not KEY=VALUE"));
        };
        match key {
            "FORMAT" => format = Some(value),
            "VTA_DID" => vta_did = Some(value),
            _ => {}
        }
    }
    if format != Some("1") {
        return Err(format!("unsupported identity file format {format:?}"));
    }
    let did = vta_did.ok_or("the identity file has no VTA_DID")?;
    let key = did
        .strip_prefix("did:key:z6Mk")
        .ok_or_else(|| format!("`{did}` is not an Ed25519 did:key"))?;
    if !(40..=60).contains(&key.len())
        || !key
            .chars()
            .all(|c| BASE58.contains(c))
    {
        return Err(format!("`{did}` is not a well-formed did:key"));
    }
    Ok(did.to_string())
}

/// Whether the identity the sidecar publishes may be pinned: the first one seen
/// is, and afterwards only that one is.
pub fn check_pin(
    state: Option<&BundledState>,
    published: &str,
    configured: Option<&str>,
) -> Result<(), String> {
    if let Some(configured) = configured
        && configured != published
    {
        return Err(format!("the sidecar published `{published}` but `[vta] vta_did` names `{configured}`"));
    }
    match state {
        Some(state) if state.vta_did != published => {
            Err(format!("the sidecar now publishes `{published}`, but this gateway pinned `{}`", state.vta_did))
        }
        _ => Ok(()),
    }
}

/// A transport problem or a server that is still starting; anything else is the
/// sidecar saying no.
fn is_not_up_yet(error: &VtaError) -> bool {
    match error {
        VtaError::Transport(_) => true,
        VtaError::Http { status, .. } => *status >= 500,
        _ => false,
    }
}

/// What a sidecar refusing the gateway means: a revocation when the gateway
/// had been connected, otherwise an enrolment that never happened.
fn refusal(previously_connected: bool) -> BootstrapState {
    if previously_connected {
        BootstrapState::Revoked
    } else {
        BootstrapState::EnrolmentRefused
    }
}

struct Failure {
    state: BootstrapState,
    detail: String,
}

impl Failure {
    fn new(
        state: BootstrapState,
        detail: impl Into<String>,
    ) -> Self {
        Self { state, detail: detail.into() }
    }

    fn from_vta(
        error: &VtaError,
        step: &str,
        previously_connected: bool,
    ) -> Self {
        let state = if is_not_up_yet(error) {
            BootstrapState::WaitingForVta
        } else if matches!(error, VtaError::Http { status: 401 | 403, .. }) {
            refusal(previously_connected)
        } else {
            BootstrapState::EnrolmentRefused
        };
        tracing::debug!(target: "vta_audit", step, detail = error.log_detail(), "the trust agent refused a bootstrap step");
        // The terse form only: the response body can name internals and is not
        // for the status API. It is in the debug log above.
        Self::new(state, format!("{step}: {error}"))
    }
}

async fn wait_for_identity(
    dir: &Path,
    base_url: &str,
    wait: Duration,
) -> Result<String, Failure> {
    let deadline = Instant::now() + wait;
    let health_url = format!("{}/health", base_url.trim_end_matches('/'));
    let http = reqwest::Client::builder()
        .timeout(HEALTH_TIMEOUT)
        .build()
        .map_err(|e| Failure::new(BootstrapState::Misconfigured, format!("could not build a health client: {e}")))?;
    let mut delay = POLL_FIRST;
    let mut published: Option<String> = None;
    loop {
        if published.is_none() {
            match tokio::fs::read_to_string(dir.join(IDENTITY_FILE)).await {
                Ok(text) => {
                    published = Some(parse_identity(&text).map_err(|e| {
                        Failure::new(BootstrapState::Misconfigured, format!("{IDENTITY_FILE} is not acceptable: {e}"))
                    })?)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Failure::new(
                        BootstrapState::Misconfigured,
                        format!("could not read {IDENTITY_FILE}: {e}"),
                    ));
                }
            }
        }
        if let Some(did) = &published
            && http
                .get(&health_url)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
        {
            return Ok(did.clone());
        }
        if Instant::now() >= deadline {
            let what = if published.is_some() {
                "the trust agent did not answer its health check"
            } else {
                "the trust agent has not published its identity"
            };
            return Err(Failure::new(BootstrapState::WaitingForVta, format!("{what} within {}s", wait.as_secs())));
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(POLL_MAX);
    }
}

/// The signing key's public half, and whether it already existed.
struct SigningKey {
    public: String,
}

fn key_public(record: &Value) -> Option<String> {
    record
        .get("publicKey")
        .or_else(|| record.get("publicKeyMultibase"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

async fn find_signing_key(
    client: &VtaRestClient,
    context_id: &str,
    key_id: &str,
) -> Result<Option<SigningKey>, Failure> {
    let keys = super::context_identity::list_context_keys(client, context_id, None)
        .await
        .map_err(|e| Failure::new(BootstrapState::WaitingForVta, format!("listing keys: {e}")))?;
    let Some(record) = keys.iter().find(|k| {
        k.get("keyId")
            .and_then(Value::as_str)
            == Some(key_id)
    }) else {
        return Ok(None);
    };
    if record
        .get("keyType")
        .and_then(Value::as_str)
        != Some("ed25519")
        || record
            .get("status")
            .and_then(Value::as_str)
            != Some("active")
    {
        return Err(Failure::new(
            BootstrapState::EnrolmentRefused,
            format!("key `{key_id}` exists but is not an active Ed25519 key"),
        ));
    }
    let public = key_public(record)
        .ok_or_else(|| Failure::new(BootstrapState::EnrolmentRefused, format!("key `{key_id}` has no public key")))?;
    Ok(Some(SigningKey { public }))
}

async fn create_signing_key(
    client: &VtaRestClient,
    key_id: &str,
) -> Result<SigningKey, Failure> {
    let created: Value = client
        .dispatch_signed(
            TASK_KEYS_CREATE,
            json!({
                "keyType": "ed25519",
                "keyId": key_id,
                "label": KEY_LABEL,
                "internal": true,
            }),
        )
        .await
        .map_err(|e| Failure::from_vta(&e, "creating the signing key", false))?;
    let key = created
        .get("payload")
        .and_then(|p| p.get("key"))
        .or_else(|| created.get("key"))
        .unwrap_or(&created);
    let public = key_public(key).ok_or_else(|| {
        Failure::new(
            BootstrapState::EnrolmentRefused,
            "the trust agent created the signing key but returned no public key, which cannot be read later",
        )
    })?;
    Ok(SigningKey { public })
}

/// Everything one bootstrap produced.
pub struct Outcome {
    pub status: BootstrapStatus,
    pub state: Option<BundledState>,
}

/// Run the bootstrap once.
pub async fn run(
    config: &VtaConfig,
    storage: &Path,
) -> Outcome {
    let context_id = config
        .context_id
        .clone()
        .unwrap_or_else(|| BUNDLED_CONTEXT_ID.to_string());
    let mut status = BootstrapStatus {
        state: BootstrapState::Misconfigured,
        advice: BootstrapState::Misconfigured.advice(),
        detail: None,
        vta_did: None,
        control_did: None,
        context_id: context_id.clone(),
        bootstrapped_at: None,
        previously_connected: false,
        owner: "unclaimed",
    };

    let state = match load_state(storage).await {
        Ok(state) => state,
        Err(detail) => {
            status.detail = Some(detail);
            return Outcome { status, state: None };
        }
    };
    status.previously_connected = state.is_some();
    if let Some(state) = &state {
        status.vta_did = Some(state.vta_did.clone());
        status.control_did = Some(state.control_did.clone());
        status.bootstrapped_at = Some(state.bootstrapped_at);
    }

    let result = connect(config, storage, &context_id, state.as_ref(), &mut status).await;
    match result {
        Ok(connected) => {
            status.state = BootstrapState::Connected;
            status.advice = BootstrapState::Connected.advice();
            status.vta_did = Some(connected.vta_did.clone());
            status.control_did = Some(connected.control_did.clone());
            status.bootstrapped_at = Some(connected.bootstrapped_at);
            Outcome { status, state: Some(connected) }
        }
        Err(failure) => {
            status.state = failure.state;
            status.advice = failure.state.advice();
            status.detail = Some(failure.detail);
            Outcome { status, state }
        }
    }
}

async fn connect(
    config: &VtaConfig,
    storage: &Path,
    context_id: &str,
    state: Option<&BundledState>,
    status: &mut BootstrapStatus,
) -> Result<BundledState, Failure> {
    let misconfigured = |detail: String| Failure::new(BootstrapState::Misconfigured, detail);
    let previously_connected = state.is_some();

    let base_url = config
        .base_url
        .as_deref()
        .ok_or_else(|| misconfigured("[vta] base_url is required".to_string()))?;
    let dir = PathBuf::from(&config.bootstrap_dir);

    let control_key = super::ensure_appliance_control_key(storage)
        .await
        .map_err(|e| misconfigured(format!("the gateway's control key: {}", e.log_detail())))?;
    let control_did = control_key.did().to_string();
    status.control_did = Some(control_did.clone());
    write_enrolment(&dir, &control_did)
        .await
        .map_err(misconfigured)?;

    let published = wait_for_identity(&dir, base_url, Duration::from_secs(config.bootstrap_wait_secs)).await?;
    check_pin(state, &published, config.vta_did.as_deref()).map_err(|detail| {
        let state = if state.is_some() {
            BootstrapState::VtaReplaced
        } else {
            BootstrapState::Misconfigured
        };
        Failure::new(state, detail)
    })?;
    status.vta_did = Some(published.clone());

    // A rotation that a crash interrupted is finished (or abandoned) before the
    // key is used, so the gateway authenticates with the one that is current.
    let control_key_path = super::appliance_control_key_path(storage);
    let settled = super::control_rotation::settle_pending(config, &published, &control_key_path)
        .await
        .map_err(|e| Failure::from_vta(&e, "settling an interrupted control-key rotation", previously_connected))?;
    if settled.is_some() {
        tracing::info!(target: "vta_audit", "finished an interrupted control-key rotation");
    }
    let control_key = super::ensure_appliance_control_key(storage)
        .await
        .map_err(|e| misconfigured(format!("the gateway's control key: {}", e.log_detail())))?;
    let control_did = control_key.did().to_string();
    status.control_did = Some(control_did.clone());
    write_enrolment(&dir, &control_did)
        .await
        .map_err(misconfigured)?;

    let client = Arc::new(
        VtaRestClient::new(
            base_url,
            &published,
            Arc::new(control_key) as Arc<dyn SignerKeyProvider>,
            Duration::from_millis(config.timeout_ms),
            config.max_concurrent,
            None,
        )
        .map_err(|e| misconfigured(format!("could not build the trust agent client: {}", e.log_detail())))?,
    );

    client
        .authenticate()
        .await
        .map_err(|e| Failure::from_vta(&e, "authenticating", previously_connected))?;
    let who: Whoami = client
        .whoami()
        .await
        .map_err(|e| Failure::from_vta(&e, "reading the grant", previously_connected))?;
    who.assert_bundled_grant(context_id)
        .map_err(|e| Failure::new(refusal(previously_connected), e.log_detail().to_string()))?;

    let retired = match state {
        Some(state) => state.retired_keys.clone(),
        None => load_retired(storage)
            .await
            .map_err(misconfigured)?,
    };
    let key_id = state
        .map(|s| s.signing_key_id.clone())
        .unwrap_or_else(|| signing_key_id(retired.len() + 1));

    let existing = find_signing_key(&client, context_id, &key_id).await?;
    let signing_key_public = match (state, existing) {
        (Some(state), Some(key)) if key.public == state.signing_key_public => key.public,
        (Some(_), Some(_)) => {
            return Err(Failure::new(
                BootstrapState::VtaReplaced,
                format!("key `{key_id}` now has a different public key than the one this gateway recorded"),
            ));
        }
        (Some(_), None) => {
            return Err(Failure::new(
                BootstrapState::VtaLost,
                format!("the trust agent holds no key `{key_id}` in context `{context_id}`"),
            ));
        }
        (None, Some(key)) => key.public,
        (None, None) => {
            create_signing_key(&client, &key_id)
                .await?
                .public
        }
    };

    // The sidecar's context is created by hand, so it has no DID, and a
    // credential issued as it would have no issuer. Giving it one is what makes
    // the context usable as an issuing authority; it is a no-op once set.
    super::context_creator::ensure_context_can_issue(&client, context_id).await;

    if let Some(state) = state {
        if state.control_did == control_did {
            return Ok(state.clone());
        }
        let mut updated = state.clone();
        updated.control_did = control_did;
        save_state(storage, &updated)
            .await
            .map_err(misconfigured)?;
        return Ok(updated);
    }
    let fresh = BundledState {
        format: FORMAT,
        vta_did: published,
        base_url: base_url.to_string(),
        context_id: context_id.to_string(),
        control_did,
        signing_key_id: key_id,
        signing_key_public,
        retired_keys: retired,
        bootstrapped_at: Utc::now(),
    };
    save_state(storage, &fresh)
        .await
        .map_err(misconfigured)?;
    remove_secret(&retired_path(storage)).await;
    Ok(fresh)
}

/// What `--vta-rebootstrap` does, as an operator-facing report.
///
/// The recovery for a trust agent that was replaced or lost its key, which is
/// never done automatically: a new trust agent means new keys and DIDs. It
/// forgets the pinned trust agent and retires the current signing key, which
/// stays published so tokens it signed still verify. Nothing is deleted from a
/// trust agent, and no key is exported or re-created here; the next start
/// bootstraps again as on first start, under a new key id.
pub async fn rebootstrap(
    storage: &Path,
    confirmed: bool,
) -> Result<String, String> {
    let state = load_state(storage)
        .await?
        .ok_or("nothing to re-bootstrap: no bundled bootstrap is recorded on this gateway")?;
    let mut retired = state.retired_keys.clone();
    if !retired
        .iter()
        .any(|k| k.key_id == state.signing_key_id)
    {
        retired.push(RetiredKey {
            key_id: state.signing_key_id.clone(),
            public_key: state
                .signing_key_public
                .clone(),
            retired_at: Utc::now(),
        });
    }
    let plan = format!(
        "This forgets the pinned trust agent `{}` and retires signing key `{}`, which stays published so tokens it \
         signed still verify. The next start bootstraps again under key `{}`.",
        state.vta_did,
        state.signing_key_id,
        signing_key_id(retired.len() + 1)
    );
    if !confirmed {
        return Ok(format!("{plan}\nNothing was changed. Run again with --yes to do it."));
    }
    let text = serde_json::to_string_pretty(&retired).map_err(|e| format!("could not encode the retired keys: {e}"))?;
    crate::encryption::secret_file::write_secret_file(&retired_path(storage), &text)
        .await
        .map_err(|e| format!("could not persist the retired keys: {e}"))?;
    remove_secret(&state_path(storage)).await;
    Ok(format!("{plan}\nDone. Start the gateway again to bootstrap."))
}

/// What `--vta-rotate-control-key` does, as an operator-facing report.
///
/// Moves the gateway's access entry on the bundled trust agent to a new control
/// `did:key`, using `acl/swap-key`. Run it with the gateway **stopped**: a trust
/// agent supersedes a DID's session when it authenticates again, and the running
/// connector holds the old key in memory.
pub async fn rotate_control_key(
    config: &VtaConfig,
    storage: &Path,
    confirmed: bool,
) -> Result<String, String> {
    let state = load_state(storage)
        .await?
        .ok_or("nothing to rotate: no bundled bootstrap is recorded on this gateway")?;
    let plan = format!(
        "This moves this gateway's access entry on the trust agent `{}` from `{}` to a new did:key, with the same \
         grant. Anyone holding the current key could do the same, so a rotation is hygiene, not recovery from a \
         leak; the trust agent audits every swap. Stop the gateway first.",
        state.vta_did, state.control_did
    );
    if !confirmed {
        return Ok(format!("{plan}\nNothing was changed. Run again with --yes to do it."));
    }
    let rotated = super::control_rotation::rotate(config, &state.vta_did, &super::appliance_control_key_path(storage))
        .await
        .map_err(|e| {
            format!("the rotation failed: {e}. Nothing is lost: if the swap did happen, the next start finishes it.")
        })?;
    let mut updated = state;
    updated.control_did = rotated.new_did.clone();
    save_state(storage, &updated).await?;
    write_enrolment(Path::new(&config.bootstrap_dir), &rotated.new_did).await?;
    Ok(format!("{plan}\nDone. The control key is now `{}`. Start the gateway again.", rotated.new_did))
}

/// Fold a bootstrap result into the `[vta]` block the rest of startup reads.
///
/// With a recorded state the block always carries it, so a sidecar that is down
/// or has refused the gateway fails closed at signing rather than quietly
/// signing with something else. With none, an unusable sidecar turns the block
/// off and the gateway signs locally, as it did before: nothing was ever signed
/// by the sidecar, so nothing is affected.
pub fn apply(
    config: &mut VtaConfig,
    outcome: &Outcome,
) {
    match &outcome.state {
        Some(state) => {
            config.vta_did = Some(state.vta_did.clone());
            config.context_id = Some(state.context_id.clone());
            config.signing_key_id = Some(state.signing_key_id.clone());
            config.signing_key_public = Some(
                state
                    .signing_key_public
                    .clone(),
            );
            config.retiring_keys = state
                .retired_keys
                .iter()
                .map(|k| crate::config::vta::RetiringKey {
                    key_id: k.key_id.clone(),
                    public_key: Some(k.public_key.clone()),
                })
                .collect();
            config.auto_provision_contexts = true;
        }
        None => config.enabled = false,
    }
}

/// Run the bootstrap for a `[vta]` block that asks for one, apply it, and
/// record the result for the status API. Returns the status, or `None` when the
/// block does not ask for a bootstrap.
pub async fn bootstrap(
    config: &mut VtaConfig,
    storage: &Path,
) -> Option<BootstrapStatus> {
    if !config.enabled || !config.auto_bootstrap {
        return None;
    }
    if config
        .auth_key_source
        .as_deref()
        .is_none_or(|s| s.trim().is_empty())
    {
        config.auth_key_source = Some(format!("file://{}", super::appliance_control_key_path(storage).display()));
    }
    let outcome = run(config, storage).await;
    apply(config, &outcome);
    let status = outcome.status;
    match status.state {
        BootstrapState::Connected => {
            tracing::info!(
                target: "vta_audit",
                vta_did = status.vta_did.as_deref().unwrap_or_default(),
                control_did = status.control_did.as_deref().unwrap_or_default(),
                "the bundled trust agent is connected",
            );
        }
        state => {
            tracing::warn!(
                target: "vta_audit",
                state = ?state,
                detail = status.detail.as_deref().unwrap_or_default(),
                advice = state.advice(),
                previously_connected = status.previously_connected,
                "the bundled trust agent is not connected",
            );
        }
    }
    record(status.clone());
    Some(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VTA: &str = "did:key:z6MkvnxZrB5vsAFb8AGaDVAqSYYNoz5y2Rgvhccn7xSvx3Aj";

    fn state(vta_did: &str) -> BundledState {
        BundledState {
            format: FORMAT,
            vta_did: vta_did.to_string(),
            base_url: "http://127.0.0.1:8100".to_string(),
            context_id: "gateway".to_string(),
            control_did: "did:key:z6MkGw".to_string(),
            signing_key_id: signing_key_id(1),
            signing_key_public: "z6MkKey".to_string(),
            retired_keys: Vec::new(),
            bootstrapped_at: Utc::now(),
        }
    }

    #[test]
    fn the_identity_file_is_parsed_strictly() {
        let ok = format!("FORMAT=1\nVTA_DID={VTA}\nBASE_URL=http://elsewhere.example\n");
        assert_eq!(parse_identity(&ok).expect("valid"), VTA);

        for bad in [
            format!("VTA_DID={VTA}\n"),
            format!("FORMAT=2\nVTA_DID={VTA}\n"),
            "FORMAT=1\n".to_string(),
            "FORMAT=1\nVTA_DID=did:webvh:Qm:evil.example\n".to_string(),
            "FORMAT=1\nVTA_DID=did:key:z6Mkshort\n".to_string(),
            format!("FORMAT=1\nVTA_DID={VTA};rm -rf /\n"),
            "FORMAT=1\nno equals sign\n".to_string(),
        ] {
            assert!(parse_identity(&bad).is_err(), "must refuse: {bad:?}");
        }
    }

    #[test]
    fn the_base_url_in_the_identity_file_is_never_used() {
        let text = format!("FORMAT=1\nVTA_DID={VTA}\nBASE_URL=http://attacker.example\n");
        assert_eq!(parse_identity(&text).expect("valid"), VTA, "only the DID is returned");
    }

    #[test]
    fn the_first_published_identity_is_pinned_and_a_different_one_later_is_refused() {
        check_pin(None, VTA, None).expect("first contact pins");
        check_pin(Some(&state(VTA)), VTA, None).expect("the same identity again");

        let err = check_pin(Some(&state(VTA)), "did:key:z6MkOther", None).expect_err("a different VTA");
        assert!(err.contains("pinned"), "{err}");
    }

    #[test]
    fn a_configured_vta_did_is_an_extra_check() {
        check_pin(None, VTA, Some(VTA)).expect("agrees");
        assert!(check_pin(None, VTA, Some("did:key:z6MkOther")).is_err());
    }

    #[test]
    fn the_enrolment_note_carries_the_control_did_and_nothing_else() {
        let note = enrolment_contents("did:key:z6MkGw");
        assert_eq!(note, "FORMAT=1\nGATEWAY_CONTROL_DID=did:key:z6MkGw\n");
    }

    #[test]
    fn a_refusal_is_a_revocation_only_if_the_gateway_had_been_connected() {
        let denied = VtaError::Http {
            status: 403,
            body: "{}".to_string(),
        };
        assert_eq!(Failure::from_vta(&denied, "x", false).state, BootstrapState::EnrolmentRefused);
        assert_eq!(Failure::from_vta(&denied, "x", true).state, BootstrapState::Revoked);
    }

    #[test]
    fn a_refusal_detail_never_carries_the_trust_agents_response_body() {
        let denied = VtaError::Http {
            status: 403,
            body: r#"{"payload":{"code":"permissionDenied"},"secret":"INTERNAL-DETAIL"}"#.to_string(),
        };
        let failure = Failure::from_vta(&denied, "authenticating", false);
        assert!(
            !failure
                .detail
                .contains("INTERNAL-DETAIL"),
            "{}",
            failure.detail
        );
        assert!(
            failure.detail.contains("403")
                && failure
                    .detail
                    .contains("permissionDenied"),
            "{}",
            failure.detail
        );
    }

    #[test]
    fn a_trust_agent_that_is_not_up_yet_is_waiting_not_refusing() {
        for error in [
            VtaError::Transport("connection refused".to_string()),
            VtaError::Http {
                status: 503,
                body: String::new(),
            },
        ] {
            assert_eq!(Failure::from_vta(&error, "x", true).state, BootstrapState::WaitingForVta);
        }
    }

    #[test]
    fn a_recorded_state_is_carried_into_the_block_so_signing_fails_closed() {
        let mut config = VtaConfig {
            enabled: true,
            auto_bootstrap: true,
            ..VtaConfig::default()
        };
        let outcome = Outcome {
            status: BootstrapStatus {
                state: BootstrapState::Revoked,
                advice: "",
                detail: None,
                vta_did: None,
                control_did: None,
                context_id: "gateway".to_string(),
                bootstrapped_at: None,
                previously_connected: true,
                owner: "unclaimed",
            },
            state: Some(state(VTA)),
        };
        apply(&mut config, &outcome);
        assert!(config.enabled, "the block stays on, so signing errors instead of falling back");
        assert_eq!(config.vta_did.as_deref(), Some(VTA));
        assert_eq!(
            config
                .signing_key_public
                .as_deref(),
            Some("z6MkKey")
        );
        assert!(config.auto_provision_contexts);
    }

    #[test]
    fn with_no_recorded_state_an_unusable_trust_agent_turns_the_block_off() {
        let mut config = VtaConfig {
            enabled: true,
            auto_bootstrap: true,
            ..VtaConfig::default()
        };
        let outcome = Outcome {
            status: BootstrapStatus {
                state: BootstrapState::WaitingForVta,
                advice: "",
                detail: None,
                vta_did: None,
                control_did: None,
                context_id: "gateway".to_string(),
                bootstrapped_at: None,
                previously_connected: false,
                owner: "unclaimed",
            },
            state: None,
        };
        apply(&mut config, &outcome);
        assert!(!config.enabled, "nothing was ever signed by the sidecar, so local signing is safe");
    }

    use std::sync::Mutex;

    use axum::{
        Json, Router,
        extract::State,
        http::StatusCode,
        response::IntoResponse,
        routing::{get, post},
    };

    #[derive(Clone)]
    struct Mock(Arc<Mutex<MockVta>>);

    struct MockVta {
        enrolled: bool,
        roles: Vec<&'static str>,
        capabilities: Vec<&'static str>,
        keys: Vec<Value>,
        creates: usize,
        issuer_creates: usize,
        context_did: Option<String>,
        did_updates: usize,
        allowed: Option<Vec<String>>,
    }

    impl Mock {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(MockVta {
                enrolled: true,
                roles: vec!["initiator"],
                capabilities: super::super::onboarding::GRANT_CAPABILITIES.to_vec(),
                keys: Vec::new(),
                creates: 0,
                issuer_creates: 0,
                context_did: None,
                did_updates: 0,
                allowed: None,
            })))
        }

        fn creates(&self) -> usize {
            self.0.lock().unwrap().creates
        }

        fn issuer_creates(&self) -> usize {
            self.0
                .lock()
                .unwrap()
                .issuer_creates
        }

        fn context_did(&self) -> Option<String> {
            self.0
                .lock()
                .unwrap()
                .context_did
                .clone()
        }

        fn did_updates(&self) -> usize {
            self.0
                .lock()
                .unwrap()
                .did_updates
        }
    }

    async fn health() -> &'static str {
        "ok"
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
        if task.contains("auth/challenge") {
            return Json(json!({ "challenge": "c", "sessionId": "s" })).into_response();
        }
        if task.contains("auth/authenticate") {
            let issuer = body["issuer"]
                .as_str()
                .unwrap_or_default();
            let permitted = vta
                .allowed
                .as_ref()
                .is_none_or(|a| a.iter().any(|d| d == issuer));
            if !vta.enrolled || !permitted {
                return (StatusCode::FORBIDDEN, Json(json!({ "payload": { "code": "permissionDenied" } })))
                    .into_response();
            }
            return Json(json!({ "session": { "id": "s" }, "tokens": { "accessToken": "t", "expiresIn": 3600 } }))
                .into_response();
        }
        if task.contains("auth/whoami") {
            return Json(json!({ "payload": {
                "roles": vta.roles,
                "scopes": ["ctx:gateway"],
                "capabilities": vta.capabilities,
            } }))
            .into_response();
        }
        if task.contains("keys/list") {
            return Json(json!({ "payload": { "keys": vta.keys } })).into_response();
        }
        if task.contains("contexts/get") {
            return Json(json!({ "payload": { "id": "gateway", "did": vta.context_did } })).into_response();
        }
        if task.contains("contexts/update-did") {
            vta.did_updates += 1;
            vta.context_did = body["payload"]["did"]
                .as_str()
                .map(str::to_string);
            return Json(json!({ "payload": { "id": "gateway" } })).into_response();
        }
        if task.contains("keys/create") {
            if body["payload"]["keyId"]
                .as_str()
                .is_some_and(|id| id.ends_with("-issuer"))
            {
                vta.issuer_creates += 1;
            } else {
                vta.creates += 1;
            }
            let record = json!({
                "keyId": body["payload"]["keyId"],
                "keyType": "ed25519",
                "status": "active",
                "publicKey": "z6MkMintedPublicKey",
            });
            vta.keys.push(record.clone());
            return Json(json!({ "payload": { "key": record } })).into_response();
        }
        (StatusCode::BAD_REQUEST, Json(json!({ "error": "unexpected task" }))).into_response()
    }

    async fn serve(mock: &Mock) -> String {
        let app = Router::new()
            .route("/health", get(health))
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

    struct Fixture {
        storage: tempfile::TempDir,
        boot: tempfile::TempDir,
        config: VtaConfig,
    }

    impl Fixture {
        fn new(base_url: &str) -> Self {
            let storage = tempfile::tempdir().unwrap();
            let boot = tempfile::tempdir().unwrap();
            let config = VtaConfig {
                enabled: true,
                auto_bootstrap: true,
                mode: crate::config::vta::VtaMode::Bundled,
                base_url: Some(base_url.to_string()),
                bootstrap_dir: boot
                    .path()
                    .display()
                    .to_string(),
                bootstrap_wait_secs: 2,
                ..VtaConfig::default()
            };
            Self { storage, boot, config }
        }

        fn publish_identity(
            &self,
            did: &str,
        ) {
            std::fs::write(
                self.boot
                    .path()
                    .join(IDENTITY_FILE),
                format!("FORMAT=1\nVTA_DID={did}\n"),
            )
            .unwrap();
        }

        async fn run(&self) -> Outcome {
            run(&self.config, self.storage.path()).await
        }
    }

    #[tokio::test]
    async fn a_fresh_install_gives_the_gateway_context_the_identity_it_issues_as() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);

        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::Connected, "{:?}", outcome.status.detail);
        assert_eq!(mock.issuer_creates(), 1, "one issuer key is minted in the context");
        assert_eq!(
            mock.context_did().as_deref(),
            Some("did:key:z6MkMintedPublicKey"),
            "the context's DID is the did:key of that key, so a credential it issues has an issuer"
        );
    }

    #[tokio::test]
    async fn a_restart_leaves_the_gateway_context_identity_alone() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);

        fixture.run().await;
        let second = fixture.run().await;

        assert_eq!(second.status.state, BootstrapState::Connected, "{:?}", second.status.detail);
        assert_eq!(mock.issuer_creates(), 1, "no second issuer key");
        assert_eq!(mock.did_updates(), 1, "the DID is written once");
    }

    #[tokio::test]
    async fn a_fresh_install_connects_creates_the_key_and_records_the_pin() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);

        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::Connected, "{:?}", outcome.status.detail);
        let state = outcome
            .state
            .expect("recorded");
        assert_eq!(state.vta_did, VTA);
        assert_eq!(state.context_id, "gateway");
        assert_eq!(state.signing_key_id, "gateway-jwt-1");
        assert_eq!(state.signing_key_public, "z6MkMintedPublicKey", "captured at creation");
        assert_eq!(mock.creates(), 1);
        assert_eq!(outcome.status.owner, "unclaimed");

        let note = std::fs::read_to_string(
            fixture
                .boot
                .path()
                .join(ENROLMENT_FILE),
        )
        .unwrap();
        assert_eq!(note, enrolment_contents(&state.control_did), "the note names the gateway's own did:key");
        assert!(
            state
                .control_did
                .starts_with("did:key:")
        );
        assert!(
            !note
                .to_lowercase()
                .contains("seed"),
            "no secret material in the shared folder"
        );
        assert!(
            load_state(fixture.storage.path())
                .await
                .unwrap()
                .is_some(),
            "persisted"
        );
    }

    #[tokio::test]
    async fn a_restart_keeps_the_same_identity_and_creates_nothing() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);

        let first = fixture
            .run()
            .await
            .state
            .expect("first");
        let second = fixture.run().await;

        assert_eq!(second.status.state, BootstrapState::Connected);
        let second = second.state.expect("second");
        assert_eq!(second.vta_did, first.vta_did);
        assert_eq!(second.control_did, first.control_did, "one identity across restarts");
        assert_eq!(second.signing_key_public, first.signing_key_public);
        assert_eq!(mock.creates(), 1, "the restart did not mint another key");
        assert!(second.bootstrapped_at == first.bootstrapped_at, "the record is not rewritten");
    }

    #[tokio::test]
    async fn a_key_made_before_a_crash_is_adopted_not_duplicated() {
        let mock = Mock::new();
        mock.0
            .lock()
            .unwrap()
            .keys
            .push(json!({
                "keyId": "gateway-jwt-1", "keyType": "ed25519", "status": "active", "publicKey": "z6MkEarlier",
            }));
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);

        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::Connected, "{:?}", outcome.status.detail);
        assert_eq!(
            outcome
                .state
                .unwrap()
                .signing_key_public,
            "z6MkEarlier"
        );
        assert_eq!(mock.creates(), 0);
    }

    #[tokio::test]
    async fn a_trust_agent_that_never_enrolled_the_gateway_is_refused_and_signing_stays_local() {
        let mock = Mock::new();
        mock.0
            .lock()
            .unwrap()
            .enrolled = false;
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);

        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::EnrolmentRefused);
        assert!(outcome.state.is_none());
        assert_eq!(mock.creates(), 0, "nothing is created for a gateway that was refused");
        assert!(
            load_state(fixture.storage.path())
                .await
                .unwrap()
                .is_none()
        );
        let mut config = fixture.config.clone();
        apply(&mut config, &outcome);
        assert!(!config.enabled);
    }

    #[tokio::test]
    async fn a_gateway_that_was_connected_and_is_now_refused_is_revoked_and_never_re_enrols() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);
        assert_eq!(
            fixture
                .run()
                .await
                .status
                .state,
            BootstrapState::Connected
        );

        mock.0
            .lock()
            .unwrap()
            .enrolled = false;
        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::Revoked);
        assert!(
            outcome
                .status
                .previously_connected
        );
        let mut config = fixture.config.clone();
        apply(&mut config, &outcome);
        assert!(config.enabled, "the block stays on, so signing fails closed");
        assert_eq!(mock.creates(), 1, "no second enrolment attempt, no second key");
    }

    #[tokio::test]
    async fn a_different_trust_agent_at_the_pinned_address_is_refused() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);
        assert_eq!(
            fixture
                .run()
                .await
                .status
                .state,
            BootstrapState::Connected
        );

        fixture.publish_identity("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::VtaReplaced);
        assert_eq!(
            outcome
                .status
                .vta_did
                .as_deref(),
            Some(VTA),
            "the pin is not overwritten"
        );
    }

    #[tokio::test]
    async fn a_trust_agent_that_lost_the_signing_key_is_reported_not_recreated() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);
        assert_eq!(
            fixture
                .run()
                .await
                .status
                .state,
            BootstrapState::Connected
        );

        mock.0
            .lock()
            .unwrap()
            .keys
            .clear();
        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::VtaLost);
        assert_eq!(mock.creates(), 1, "a lost key is never silently re-created");
    }

    #[tokio::test]
    async fn a_grant_wider_than_the_bundled_one_is_a_failure_not_a_bonus() {
        let mock = Mock::new();
        {
            let mut vta = mock.0.lock().unwrap();
            vta.roles = vec!["admin"];
            vta.capabilities
                .push("key-export");
        }
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);

        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::EnrolmentRefused);
        assert_eq!(mock.creates(), 0);
    }

    #[tokio::test]
    async fn no_published_identity_means_waiting_for_the_trust_agent() {
        let mock = Mock::new();
        let mut fixture = Fixture::new(&serve(&mock).await);
        fixture
            .config
            .bootstrap_wait_secs = 1;

        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::WaitingForVta);
        assert!(outcome.state.is_none());
        assert!(
            fixture
                .boot
                .path()
                .join(ENROLMENT_FILE)
                .exists(),
            "the note is written first, so the sidecar can enrol while the gateway waits"
        );
    }

    #[tokio::test]
    async fn a_malformed_identity_file_is_reported_as_misconfiguration() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        std::fs::write(
            fixture
                .boot
                .path()
                .join(IDENTITY_FILE),
            "FORMAT=1\nVTA_DID=did:webvh:Qm:evil.example\n",
        )
        .unwrap();

        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::Misconfigured);
        assert_eq!(mock.creates(), 0);
    }

    #[tokio::test]
    async fn a_rebootstrap_without_confirmation_changes_nothing() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);
        fixture.run().await;

        let report = rebootstrap(fixture.storage.path(), false)
            .await
            .expect("dry run");

        assert!(report.contains("Nothing was changed"), "{report}");
        assert!(
            load_state(fixture.storage.path())
                .await
                .unwrap()
                .is_some(),
            "the state is untouched"
        );
        assert!(
            load_retired(fixture.storage.path())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_confirmed_rebootstrap_retires_the_key_and_the_next_start_mints_under_a_new_kid() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);
        let first = fixture
            .run()
            .await
            .state
            .expect("first");

        rebootstrap(fixture.storage.path(), true)
            .await
            .expect("rebootstrap");
        assert!(
            load_state(fixture.storage.path())
                .await
                .unwrap()
                .is_none(),
            "the pin is forgotten"
        );

        let second = fixture.run().await;

        assert_eq!(second.status.state, BootstrapState::Connected, "{:?}", second.status.detail);
        let state = second.state.expect("second");
        assert_eq!(state.signing_key_id, "gateway-jwt-2", "a retired kid is never reused");
        assert_eq!(state.retired_keys.len(), 1);
        assert_eq!(state.retired_keys[0].key_id, first.signing_key_id);
        assert_eq!(state.retired_keys[0].public_key, first.signing_key_public);
        assert_eq!(mock.creates(), 2);
        assert!(
            load_retired(fixture.storage.path())
                .await
                .unwrap()
                .is_empty(),
            "carried into the state, so cleared"
        );

        let mut config = fixture.config.clone();
        apply(
            &mut config,
            &Outcome {
                status: second.status,
                state: Some(state),
            },
        );
        assert_eq!(
            config
                .signing_key_id
                .as_deref(),
            Some("gateway-jwt-2")
        );
        assert_eq!(config.retiring_keys.len(), 1, "the old key is still published");
        assert_eq!(config.retiring_keys[0].key_id, "gateway-jwt-1");
        assert_eq!(
            config.retiring_keys[0]
                .public_key
                .as_deref(),
            Some(
                first
                    .signing_key_public
                    .as_str()
            )
        );
    }

    #[tokio::test]
    async fn a_second_rebootstrap_keeps_every_earlier_key() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);
        fixture.run().await;
        rebootstrap(fixture.storage.path(), true)
            .await
            .unwrap();
        fixture.run().await;
        rebootstrap(fixture.storage.path(), true)
            .await
            .unwrap();

        let third = fixture
            .run()
            .await
            .state
            .expect("third");

        assert_eq!(third.signing_key_id, "gateway-jwt-3");
        let retired: Vec<_> = third
            .retired_keys
            .iter()
            .map(|k| k.key_id.as_str())
            .collect();
        assert_eq!(retired, ["gateway-jwt-1", "gateway-jwt-2"]);
    }

    #[tokio::test]
    async fn rebootstrapping_a_gateway_that_never_bootstrapped_is_refused() {
        let storage = tempfile::tempdir().unwrap();
        let err = rebootstrap(storage.path(), true)
            .await
            .expect_err("nothing to do");
        assert!(err.contains("nothing to re-bootstrap"), "{err}");
    }

    #[tokio::test]
    async fn a_rotation_the_trust_agent_finished_before_a_crash_is_completed_at_the_next_start() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);
        let first = fixture
            .run()
            .await
            .state
            .expect("first");

        // The swap happened on the trust agent, then the gateway died before it
        // promoted the new key: only the new DID is enrolled, the key is pending.
        let new_key = super::super::control_key::ControlKey::generate();
        mock.0.lock().unwrap().allowed = Some(vec![new_key.did().to_string()]);
        let current = super::super::appliance_control_key_path(fixture.storage.path());
        crate::encryption::secret_file::write_secret_file(
            &super::super::control_rotation::pending_key_path(&current),
            &new_key.seed_hex(),
        )
        .await
        .unwrap();

        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::Connected, "{:?}", outcome.status.detail);
        let state = outcome.state.expect("state");
        assert_eq!(state.control_did, new_key.did(), "the record follows the key that is now current");
        assert_ne!(state.control_did, first.control_did);
        assert_eq!(mock.creates(), 1, "no second signing key");
        let note = std::fs::read_to_string(
            fixture
                .boot
                .path()
                .join(ENROLMENT_FILE),
        )
        .unwrap();
        assert_eq!(note, enrolment_contents(new_key.did()), "a future re-enrolment names the current key");
        assert!(
            !super::super::control_rotation::pending_key_path(&current).exists()
                && !crate::encryption::secret_file::secret_enc_path(&super::super::control_rotation::pending_key_path(
                    &current
                ))
                .exists(),
            "the pending key is gone"
        );
    }

    #[tokio::test]
    async fn a_pending_key_the_trust_agent_never_accepted_is_dropped_and_the_current_key_kept() {
        let mock = Mock::new();
        let fixture = Fixture::new(&serve(&mock).await);
        fixture.publish_identity(VTA);
        let first = fixture
            .run()
            .await
            .state
            .expect("first");

        // The gateway died before the swap was sent: only the current DID is enrolled.
        mock.0.lock().unwrap().allowed = Some(vec![first.control_did.clone()]);
        let never_used = super::super::control_key::ControlKey::generate();
        let current = super::super::appliance_control_key_path(fixture.storage.path());
        crate::encryption::secret_file::write_secret_file(
            &super::super::control_rotation::pending_key_path(&current),
            &never_used.seed_hex(),
        )
        .await
        .unwrap();

        let outcome = fixture.run().await;

        assert_eq!(outcome.status.state, BootstrapState::Connected, "{:?}", outcome.status.detail);
        assert_eq!(
            outcome
                .state
                .unwrap()
                .control_did,
            first.control_did,
            "unchanged"
        );
    }

    #[test]
    fn the_status_json_is_the_shape_the_dashboard_reads() {
        let status = BootstrapStatus {
            state: BootstrapState::VtaReplaced,
            advice: BootstrapState::VtaReplaced.advice(),
            detail: Some("the sidecar now publishes another DID".to_string()),
            vta_did: Some(VTA.to_string()),
            control_did: Some("did:key:z6MkGw".to_string()),
            context_id: "gateway".to_string(),
            bootstrapped_at: None,
            previously_connected: true,
            owner: "unclaimed",
        };

        let json = serde_json::to_value(&status).expect("serialise");

        assert_eq!(json["state"], "vta_replaced", "snake_case, as the dashboard's VtaBootstrapState");
        assert_eq!(json["owner"], "unclaimed");
        assert_eq!(json["previously_connected"], true);
        assert_eq!(json["context_id"], "gateway");
        assert!(
            json["advice"]
                .as_str()
                .is_some_and(|a| a.contains("investigate"))
        );
        assert!(
            json.get("bootstrapped_at")
                .is_none(),
            "an absent time is omitted, not null"
        );
        for every_state in [
            BootstrapState::Connected,
            BootstrapState::WaitingForVta,
            BootstrapState::EnrolmentRefused,
            BootstrapState::VtaReplaced,
            BootstrapState::VtaLost,
            BootstrapState::Revoked,
            BootstrapState::Misconfigured,
        ] {
            let name = serde_json::to_value(every_state).unwrap();
            assert!(
                name.as_str()
                    .is_some_and(|n| n
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_')),
                "{name}"
            );
            assert!(
                !every_state
                    .advice()
                    .is_empty()
            );
        }
    }
}
