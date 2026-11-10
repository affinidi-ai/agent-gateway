//! The gateway's own `did:webvh`, used **only** to authenticate to a
//! Verifiable Trust Agent.
//!
//! Authenticating as a bare `did:key` works, and is what the gateway falls
//! back to, but it has no rotation story: the identifier *is* the public key,
//! so replacing the key produces a different identifier, the trust agent's
//! access entry no longer matches, and an operator has to re-grant — losing the
//! continuity of the audit trail with it.
//!
//! A `did:webvh` separates the two. The identifier stays put while the key
//! rotates inside the document, so the grant and the audit trail survive a
//! rotation.
//!
//! ## What this DID is, and is not
//!
//! It is the gateway's **authentication** identity and nothing else. What the
//! gateway *signs as* — credentials, presentations, the attestation it sends a
//! peer — is the trust agent's context DID. Keeping them apart is what lets
//! this one be cheap: it has exactly one relying party.
//!
//! ## It has to be resolvable, and that is a real constraint
//!
//! The trust agent resolves this document on **every** authentication, so the
//! URL it is served at must be reachable from wherever the agent runs. That is
//! not merely a networking detail: a trust agent's DID resolver blocks
//! loopback and private hosts by default as an SSRF guard, so a gateway whose
//! domain is not publicly resolvable cannot publish an auth DID the agent will
//! accept — it refuses before any signature is checked.
//!
//! A deployment in that position either exposes the one path publicly, or
//! keeps the plain `did:key` and accepts that rotation needs a re-grant.
//! (Development setups can opt in with `VTA_ALLOW_PRIVATE_ENDPOINTS`, which is
//! what the live test does — deliberately an opt-in, not a default.)
//!
//! ## Why the update key is allowed to live here
//!
//! The update key is the control key itself, on this host, which means a
//! compromise can rewrite this document. That is a deliberate, bounded trade:
//!
//! - the **sole relying party** is the trust agent, and the operator holds a
//!   kill switch over it — revoking the access entry ends the access whatever
//!   the document says;
//! - so the authority is the entry, not the DID.
//!
//! The consequence, which is the part worth knowing: **key rotation stops
//! being a compromise-recovery mechanism for this DID**, since an attacker
//! holding the key can rotate too. Recovery is revoke-and-re-grant. Planned
//! rotation (hygiene, scheduled replacement) still works, because nobody is
//! racing.
//!
//! None of that reasoning transfers to the gateway's `proxy_did`, whose
//! relying parties are peer gateways scattered across a network with no central
//! revocation. Same mechanism, completely different blast radius.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::identity::didwebvh::base_url_for_domain;
use crate::vta::VtaError;
use crate::vta::control_key::ControlKey;

/// Path segment the auth DID lives under, in both the identifier and the URL.
pub const AUTH_DID_PATH_SEGMENT: &str = "vta-auth";

/// Directory under the issuer's storage where the logs are kept.
const AUTH_DID_DIR: &str = "vta_auth";

/// Subdirectory holding one log per managed connection.
const CONNECTION_DIR: &str = "connections";

/// Where the appliance's own auth DID log lives, given the issuer storage root.
pub fn auth_did_dir(issuer_storage: &Path) -> PathBuf {
    issuer_storage.join(AUTH_DID_DIR)
}

/// Where a managed connection's auth DID log lives.
///
/// `connection_id` is used as a path segment, so anything that is not a plain
/// identifier is refused rather than joined.
pub fn connection_auth_did_dir(
    issuer_storage: &Path,
    connection_id: &str,
) -> Result<PathBuf, VtaError> {
    if !is_plain_identifier(connection_id) {
        return Err(VtaError::Config(format!("[vta] connection id `{connection_id}` cannot name an auth DID")));
    }
    Ok(auth_did_dir(issuer_storage)
        .join(CONNECTION_DIR)
        .join(connection_id))
}

/// A non-empty run of ASCII letters, digits, `-` and `_`.
pub fn is_plain_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Create the gateway's auth `did:webvh`, or adopt the one already there.
///
/// Idempotent by reading the log back first: the DID is this gateway's identity
/// to its trust agent, so minting a second one would silently invalidate a
/// grant the operator had already made.
pub async fn ensure_auth_did(
    issuer_storage: &Path,
    domain: &str,
    control_key: &ControlKey,
) -> Result<String, VtaError> {
    ensure_did_at(auth_did_dir(issuer_storage), domain, AUTH_DID_PATH_SEGMENT.to_string(), control_key).await
}

/// Create the auth `did:webvh` of one managed connection, or adopt the one
/// already there.
///
/// Each connection authenticates with its **own** key (revoking one must not
/// strand the others), so each gets its own identifier, served at
/// `/vta-auth/{connection_id}/did.jsonl`. Idempotent for the same reason as
/// [`ensure_auth_did`]: the operator's grant names this DID.
pub async fn ensure_connection_auth_did(
    issuer_storage: &Path,
    domain: &str,
    connection_id: &str,
    control_key: &ControlKey,
) -> Result<String, VtaError> {
    let dir = connection_auth_did_dir(issuer_storage, connection_id)?;
    ensure_did_at(dir, domain, format!("{AUTH_DID_PATH_SEGMENT}:{connection_id}"), control_key).await
}

/// Publishes managed connections' auth DIDs under this gateway's domain.
///
/// Held by the connection admin API. Absent when the gateway has no domain to
/// publish under, in which case a connection authenticates as its `did:key`.
#[derive(Debug, Clone)]
pub struct ConnectionDidPublisher {
    issuer_storage: PathBuf,
    domain: String,
}

impl ConnectionDidPublisher {
    pub fn new(
        issuer_storage: PathBuf,
        domain: String,
    ) -> Self {
        Self { issuer_storage, domain }
    }

    /// Create (or adopt) `connection_id`'s `did:webvh`, declaring `key`.
    pub async fn publish(
        &self,
        connection_id: &str,
        key: &ControlKey,
    ) -> Result<String, VtaError> {
        ensure_connection_auth_did(&self.issuer_storage, &self.domain, connection_id, key).await
    }
}

async fn ensure_did_at(
    dir: PathBuf,
    domain: &str,
    path_segments: String,
    control_key: &ControlKey,
) -> Result<String, VtaError> {
    if let Some(existing) = read_existing_did(&dir).await? {
        return Ok(existing);
    }

    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| VtaError::Config(format!("[vta] create auth DID directory: {e}")))?;

    let domain_encoded = domain.replace(':', "%3A");
    let placeholder = format!("did:webvh:{{SCID}}:{domain_encoded}:{path_segments}");
    let document = auth_did_document(&placeholder, &control_key.public_key_multibase());

    let private_jwk = control_key_jwk(control_key);
    let base_url = base_url_for_domain(domain);
    let created = crate::identity::didwebvh::create::create_webvh_did(&private_jwk, document, &base_url)
        .await
        .map_err(|e| VtaError::Config(format!("[vta] create auth DID: {e}")))?;

    crate::storage::did_artifacts::write_did_log_raw(&dir, &created.log_entry_json)
        .await
        .map_err(|e| VtaError::Config(format!("[vta] persist auth DID log: {e}")))?;

    // The trust agent resolves this on every authentication, so where it must
    // be reachable from is the one thing an operator needs to act on. Logged
    // explicitly because a startup self-resolution check cannot answer it:
    // this runs before the listener is up, so it always fails here and says
    // nothing about whether the agent can reach it.
    tracing::info!(
        did = %created.final_did,
        url = %format!("{}{}/did.jsonl", base_url, path_segments.replace(':', "/")),
        "published the gateway's trust-agent auth DID; this URL must be reachable from the agent"
    );

    Ok(created.final_did)
}

/// The control key as an Ed25519 JWK.
///
/// `create_webvh_did` needs the private half to sign the birth entry, and it
/// takes a JWK. The seed is the Ed25519 private scalar seed, which is exactly
/// what the JWK `d` member carries.
fn control_key_jwk(control_key: &ControlKey) -> Value {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let seed = control_key.seed_bytes();
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public = signing
        .verifying_key()
        .to_bytes();
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(public),
        "d": URL_SAFE_NO_PAD.encode(seed),
    })
}

/// The DID of the log already on disk, if there is one.
async fn read_existing_did(dir: &Path) -> Result<Option<String>, VtaError> {
    let Some(raw) = crate::storage::did_artifacts::read_did_log_raw(dir)
        .await
        .map_err(|e| VtaError::Config(format!("[vta] read auth DID log: {e}")))?
    else {
        return Ok(None);
    };
    Ok(did_from_log(&raw))
}

/// Read the DID out of a webvh log's first entry.
///
/// Takes the **first** line deliberately: the identifier is fixed at birth and
/// later entries are rotations of the keys inside it, so reading the newest
/// would be no more correct and would break on a partially written append.
fn did_from_log(raw: &str) -> Option<String> {
    let first = raw
        .lines()
        .find(|line| !line.trim().is_empty())?;
    let entry: Value = serde_json::from_str(first).ok()?;
    entry
        .get("state")
        .and_then(|state| state.get("id"))
        .and_then(|id| id.as_str())
        .map(str::to_string)
}

/// The document published for the auth DID.
///
/// One verification method, under `authentication` only. It deliberately does
/// not declare `assertionMethod`: this key authenticates and signs nothing
/// else, and a document that claimed otherwise would invite exactly the reuse
/// this split exists to prevent.
fn auth_did_document(
    did: &str,
    public_key_multibase: &str,
) -> Value {
    json!({
        "id": did,
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "verificationMethod": [{
            "id": format!("{did}#key-1"),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "authentication": [format!("{did}#key-1")]
    })
}

/// A key a published auth DID declares for authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredKey {
    /// The fragment of its verification method id, for example `key-1`.
    pub fragment: String,
    pub multibase: String,
}

fn log_entries(raw: &str) -> Vec<Value> {
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn fragment_of(id: &str) -> &str {
    id.rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .unwrap_or(id)
}

/// The keys the newest entry of a log declares for authentication.
pub fn declared_keys(raw_log: &str) -> Vec<DeclaredKey> {
    let Some(last) = log_entries(raw_log).pop() else {
        return Vec::new();
    };
    let authenticating: Vec<String> = last["state"]["authentication"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(|id| fragment_of(id).to_string())
                .collect()
        })
        .unwrap_or_default();
    last["state"]["verificationMethod"]
        .as_array()
        .map(|methods| {
            methods
                .iter()
                .filter_map(|m| {
                    let fragment = fragment_of(m["id"].as_str()?).to_string();
                    let multibase = m["publicKeyMultibase"]
                        .as_str()?
                        .to_string();
                    authenticating
                        .contains(&fragment)
                        .then_some(DeclaredKey { fragment, multibase })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The fragment for the next key: one past the highest `key-N` any entry of
/// the log ever declared, so a retired id is never reused.
pub fn next_key_fragment(raw_log: &str) -> String {
    let highest = log_entries(raw_log)
        .iter()
        .flat_map(|entry| {
            entry["state"]["verificationMethod"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|m| {
            fragment_of(m["id"].as_str()?)
                .strip_prefix("key-")?
                .parse::<u32>()
                .ok()
        })
        .max()
        .unwrap_or(0);
    format!("key-{}", highest + 1)
}

/// Wait until the clock is in a whole second later than `previous`: a webvh
/// entry's `versionTime` has whole-second resolution and must strictly increase.
async fn after_version_time(previous: &Value) {
    let Some(last) = previous["versionTime"]
        .as_str()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
    else {
        return;
    };
    while chrono::Utc::now().timestamp() <= last.timestamp() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Append an entry that makes the document declare exactly `keys` for
/// authentication, lets exactly `update_keys` update it next, and is signed by
/// `signer` (one of the previous entry's update keys). Returns `false`, and
/// writes nothing, when the log already says that.
async fn append_key_entry(
    dir: &Path,
    did: &str,
    signer: &ControlKey,
    keys: &[DeclaredKey],
    update_keys: &[String],
) -> Result<bool, VtaError> {
    let config = |what: &str, e: String| VtaError::Config(format!("[vta] auth DID {what}: {e}"));
    let raw = crate::storage::did_artifacts::read_did_log_raw(dir)
        .await
        .map_err(|e| config("read the log", e.to_string()))?
        .ok_or_else(|| config("read the log", "there is no log".to_string()))?;
    let entries = log_entries(&raw);
    let last = entries
        .last()
        .ok_or_else(|| config("read the log", "it has no entries".to_string()))?;

    if declared_keys(&raw) == keys
        && last["parameters"]["updateKeys"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
            })
            .as_deref()
            == Some(
                update_keys
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
    {
        return Ok(false);
    }

    let lines: Vec<String> = raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect();
    let state = crate::identity::didwebvh::handlers::build_webvh_state(did, &lines)
        .await
        .map_err(|e| config("load the log", e))?;

    let mut document = last["state"].clone();
    document["verificationMethod"] = json!(
        keys.iter()
            .map(|key| json!({
                "id": format!("{did}#{}", key.fragment),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": key.multibase,
            }))
            .collect::<Vec<_>>()
    );
    document["authentication"] = json!(
        keys.iter()
            .map(|key| format!("{did}#{}", key.fragment))
            .collect::<Vec<_>>()
    );

    let multibase = signer.public_key_multibase();
    let key_id = format!("did:key:{multibase}#{multibase}");
    let mut secret = didwebvh_rs::prelude::Secret::from_str(&key_id, &control_key_jwk(signer))
        .map_err(|e| config("build the signing key", e.to_string()))?;
    secret.id = key_id;

    after_version_time(last).await;
    let updated = didwebvh_rs::prelude::update_did(
        didwebvh_rs::prelude::UpdateDIDConfig::builder()
            .state(state)
            .signing_key(secret)
            .update_keys(
                update_keys
                    .iter()
                    .cloned()
                    .map(didwebvh_rs::Multibase::new)
                    .collect(),
            )
            .document(document)
            .build()
            .map_err(|e| config("build the update", e.to_string()))?,
    )
    .await
    .map_err(|e| config("update the DID", e.to_string()))?;
    let entry = serde_json::to_string(updated.log_entry()).map_err(|e| config("encode the entry", e.to_string()))?;
    crate::storage::did_artifacts::append_did_log_raw(dir, &entry)
        .await
        .map_err(|e| config("publish the entry", e.to_string()))?;
    Ok(true)
}

/// Add `next_multibase` as `next_fragment` beside the keys already declared,
/// with an entry signed by `signer` (the current key). Both keys may update the
/// DID until the overlap ends. `false` when `next_multibase` is already declared.
pub async fn introduce_key(
    dir: &Path,
    did: &str,
    signer: &ControlKey,
    next_fragment: &str,
    next_multibase: &str,
) -> Result<bool, VtaError> {
    let raw = crate::storage::did_artifacts::read_did_log_raw(dir)
        .await
        .map_err(|e| VtaError::Config(format!("[vta] auth DID read the log: {e}")))?
        .unwrap_or_default();
    let mut keys = declared_keys(&raw);
    if keys
        .iter()
        .any(|k| k.multibase == next_multibase)
    {
        return Ok(false);
    }
    keys.push(DeclaredKey {
        fragment: next_fragment.to_string(),
        multibase: next_multibase.to_string(),
    });
    let update_keys = vec![signer.public_key_multibase(), next_multibase.to_string()];
    append_key_entry(dir, did, signer, &keys, &update_keys).await
}

/// Leave only `keep_fragment` declared, and let only `signer` update the DID
/// next. Used to retire the old key (signed by the new one) and to roll back
/// (signed by the old one). `false` when the log already says so.
pub async fn keep_only_key(
    dir: &Path,
    did: &str,
    signer: &ControlKey,
    keep_fragment: &str,
) -> Result<bool, VtaError> {
    let raw = crate::storage::did_artifacts::read_did_log_raw(dir)
        .await
        .map_err(|e| VtaError::Config(format!("[vta] auth DID read the log: {e}")))?
        .unwrap_or_default();
    let kept: Vec<DeclaredKey> = declared_keys(&raw)
        .into_iter()
        .filter(|k| k.fragment == keep_fragment)
        .collect();
    if kept.is_empty() {
        return Err(VtaError::Config(format!("[vta] auth DID does not declare `{keep_fragment}`")));
    }
    let update_keys = vec![signer.public_key_multibase()];
    append_key_entry(dir, did, signer, &kept, &update_keys).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_document_declares_only_authentication() {
        let did = "did:webvh:QmScid:example.com:vta-auth";
        let document = auth_did_document(did, "z6MkPublic");

        assert_eq!(document["authentication"][0], json!(format!("{did}#key-1")));
        assert!(
            document
                .get("assertionMethod")
                .is_none(),
            "this key authenticates and signs nothing else; declaring assertionMethod would invite \
             the reuse the split exists to prevent: {document}"
        );
        assert_eq!(document["verificationMethod"][0]["publicKeyMultibase"], json!("z6MkPublic"));
        assert_eq!(document["verificationMethod"][0]["controller"], json!(did));
    }

    #[test]
    fn the_did_is_read_from_the_first_log_entry() {
        let log = "{\"state\":{\"id\":\"did:webvh:QmScid:example.com:vta-auth\"}}\n";
        assert_eq!(did_from_log(log).as_deref(), Some("did:webvh:QmScid:example.com:vta-auth"));
    }

    /// A rotation appends entries; the identifier is still the one from birth,
    /// so adopting must not drift to a later line.
    #[test]
    fn a_rotated_log_still_reports_the_birth_identifier() {
        let log = "{\"state\":{\"id\":\"did:webvh:QmScid:example.com:vta-auth\"}}\n\
                   {\"state\":{\"id\":\"did:webvh:QmScid:example.com:vta-auth\",\"rotated\":true}}\n";
        assert_eq!(did_from_log(log).as_deref(), Some("did:webvh:QmScid:example.com:vta-auth"));
    }

    #[test]
    fn a_log_without_an_identifier_is_not_adopted() {
        assert_eq!(did_from_log(""), None);
        assert_eq!(did_from_log("not json"), None);
        assert_eq!(did_from_log("{\"state\":{}}"), None);
    }

    #[test]
    fn the_log_lives_under_the_issuer_storage() {
        let dir = auth_did_dir(Path::new("/storage/vc_keys"));
        assert_eq!(dir, Path::new("/storage/vc_keys/vta_auth"));
    }

    /// The identity the operator's grant names. Minting a second one on the
    /// next boot would silently invalidate that grant and the gateway would
    /// stop authenticating, so a restart must adopt what is already there.
    #[tokio::test]
    async fn a_restart_adopts_the_existing_auth_did() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ControlKey::from_seed([3u8; 32]);

        let first = ensure_auth_did(dir.path(), "example.com", &key)
            .await
            .expect("create the auth DID");
        assert!(first.starts_with("did:webvh:"), "{first}");
        assert!(first.contains(AUTH_DID_PATH_SEGMENT), "{first}");

        let second = ensure_auth_did(dir.path(), "example.com", &key)
            .await
            .expect("adopt the existing auth DID");
        assert_eq!(first, second, "a restart must not mint a second identity");
    }

    /// The published document must declare the key the gateway will actually
    /// authenticate with, or the trust agent resolves it and rejects every
    /// request.
    #[tokio::test]
    async fn the_published_document_declares_the_control_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ControlKey::from_seed([4u8; 32]);

        let did = ensure_auth_did(dir.path(), "example.com", &key)
            .await
            .expect("create the auth DID");

        let raw = crate::storage::did_artifacts::read_did_log_raw(&auth_did_dir(dir.path()))
            .await
            .expect("read log")
            .expect("log exists");
        let entry: Value = serde_json::from_str(
            raw.lines()
                .next()
                .expect("one line"),
        )
        .expect("entry parses");
        let method = &entry["state"]["verificationMethod"][0];

        assert_eq!(method["publicKeyMultibase"], json!(key.public_key_multibase()));
        assert_eq!(method["controller"], json!(did));
        assert_eq!(
            entry["state"]["authentication"][0],
            json!(format!("{did}#key-1")),
            "the default verification method the control key presents is `#key-1`"
        );
    }

    /// A connection's DID names the connection, so two connections never share
    /// an identity, and the path it resolves from is the one the gateway serves.
    #[tokio::test]
    async fn each_connection_gets_its_own_did_under_its_own_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_a = ControlKey::from_seed([5u8; 32]);
        let key_b = ControlKey::from_seed([6u8; 32]);

        let a = ensure_connection_auth_did(dir.path(), "example.com", "conn-a", &key_a)
            .await
            .expect("create a");
        let b = ensure_connection_auth_did(dir.path(), "example.com", "conn-b", &key_b)
            .await
            .expect("create b");

        assert_ne!(a, b);
        assert!(a.starts_with("did:webvh:"), "{a}");
        assert!(a.ends_with(":example.com:vta-auth:conn-a"), "{a}");
        assert!(b.ends_with(":example.com:vta-auth:conn-b"), "{b}");

        let app_did = ensure_auth_did(dir.path(), "example.com", &key_a)
            .await
            .expect("the appliance's own DID is unaffected");
        assert!(app_did.ends_with(":example.com:vta-auth"), "{app_did}");
    }

    /// The operator granted this DID; a restart must not mint another.
    #[tokio::test]
    async fn a_restart_adopts_a_connections_existing_did() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ControlKey::from_seed([7u8; 32]);

        let first = ensure_connection_auth_did(dir.path(), "example.com", "conn-a", &key)
            .await
            .expect("create");
        let second = ensure_connection_auth_did(dir.path(), "example.com", "conn-a", &key)
            .await
            .expect("adopt");

        assert_eq!(first, second);
    }

    /// The document the connection's DID resolves to declares the key the
    /// connection authenticates with, and only for authentication.
    #[tokio::test]
    async fn a_connections_document_declares_its_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ControlKey::from_seed([8u8; 32]);

        let did = ensure_connection_auth_did(dir.path(), "example.com", "conn-a", &key)
            .await
            .expect("create");
        let log_dir = connection_auth_did_dir(dir.path(), "conn-a").expect("dir");
        let raw = crate::storage::did_artifacts::read_did_log_raw(&log_dir)
            .await
            .expect("read")
            .expect("log exists");
        let entry: Value = serde_json::from_str(
            raw.lines()
                .next()
                .expect("a line"),
        )
        .expect("parses");
        let state = &entry["state"];

        assert_eq!(state["id"], json!(did));
        assert_eq!(state["verificationMethod"][0]["publicKeyMultibase"], json!(key.public_key_multibase()));
        assert_eq!(state["authentication"][0], json!(format!("{did}#key-1")));
        assert!(
            state
                .get("assertionMethod")
                .is_none()
        );
    }

    /// An id is a path segment on disk and in the URL, so a traversal attempt
    /// is refused instead of joined.

    async fn born(seed: u8) -> (tempfile::TempDir, std::path::PathBuf, String, ControlKey) {
        let storage = tempfile::tempdir().expect("tempdir");
        let key = ControlKey::from_seed([seed; 32]);
        let did = ensure_connection_auth_did(storage.path(), "example.com", "conn-r", &key)
            .await
            .expect("born");
        let dir = connection_auth_did_dir(storage.path(), "conn-r").expect("dir");
        (storage, dir, did, key)
    }

    async fn log_of(dir: &Path) -> String {
        crate::storage::did_artifacts::read_did_log_raw(dir)
            .await
            .expect("read")
            .expect("log")
    }

    async fn resolves(
        dir: &Path,
        did: &str,
    ) -> bool {
        let lines: Vec<String> = log_of(dir)
            .await
            .lines()
            .map(str::to_string)
            .collect();
        crate::identity::didwebvh::handlers::build_webvh_state(did, &lines)
            .await
            .is_ok()
    }

    fn last_entry(raw: &str) -> Value {
        serde_json::from_str(
            raw.lines()
                .last()
                .expect("an entry"),
        )
        .expect("json")
    }

    fn signed_by(entry: &Value) -> String {
        entry["proof"][0]["verificationMethod"]
            .as_str()
            .expect("a proof")
            .to_string()
    }

    #[tokio::test]
    async fn introducing_a_key_keeps_the_did_and_declares_both_keys_for_authentication() {
        let (_s, dir, did, old) = born(31).await;
        let new = ControlKey::from_seed([32u8; 32]);

        let done = introduce_key(&dir, &did, &old, "key-2", &new.public_key_multibase())
            .await
            .expect("introduce");

        assert!(done);
        let raw = log_of(&dir).await;
        assert!(resolves(&dir, &did).await, "the log still validates");
        assert_eq!(did_from_log(&raw).as_deref(), Some(did.as_str()));
        let state = &last_entry(&raw)["state"];
        assert_eq!(state["id"], json!(did));
        assert_eq!(
            declared_keys(&raw),
            vec![
                DeclaredKey {
                    fragment: "key-1".to_string(),
                    multibase: old.public_key_multibase()
                },
                DeclaredKey {
                    fragment: "key-2".to_string(),
                    multibase: new.public_key_multibase()
                },
            ]
        );
        assert_eq!(state["authentication"], json!([format!("{did}#key-1"), format!("{did}#key-2")]));
    }

    #[tokio::test]
    async fn the_introduce_entry_is_signed_by_the_current_key_and_hands_updates_to_both() {
        let (_s, dir, did, old) = born(33).await;
        let new = ControlKey::from_seed([34u8; 32]);

        introduce_key(&dir, &did, &old, "key-2", &new.public_key_multibase())
            .await
            .expect("introduce");

        let entry = last_entry(&log_of(&dir).await);
        let old_mb = old.public_key_multibase();
        assert_eq!(signed_by(&entry), format!("did:key:{old_mb}#{old_mb}"));
        assert_eq!(entry["parameters"]["updateKeys"], json!([old_mb, new.public_key_multibase()]));
    }

    #[tokio::test]
    async fn retiring_leaves_only_the_new_key_and_is_signed_by_it() {
        let (_s, dir, did, old) = born(35).await;
        let new = ControlKey::from_seed([36u8; 32]);
        introduce_key(&dir, &did, &old, "key-2", &new.public_key_multibase())
            .await
            .expect("introduce");

        let done = keep_only_key(&dir, &did, &new, "key-2")
            .await
            .expect("retire");

        assert!(done);
        let raw = log_of(&dir).await;
        assert!(resolves(&dir, &did).await);
        assert_eq!(
            declared_keys(&raw),
            vec![DeclaredKey {
                fragment: "key-2".to_string(),
                multibase: new.public_key_multibase()
            }]
        );
        let entry = last_entry(&raw);
        let new_mb = new.public_key_multibase();
        assert_eq!(signed_by(&entry), format!("did:key:{new_mb}#{new_mb}"));
        assert_eq!(entry["parameters"]["updateKeys"], json!([new_mb]));
    }

    #[tokio::test]
    async fn rolling_back_leaves_only_the_old_key_and_is_signed_by_it() {
        let (_s, dir, did, old) = born(37).await;
        let new = ControlKey::from_seed([38u8; 32]);
        introduce_key(&dir, &did, &old, "key-2", &new.public_key_multibase())
            .await
            .expect("introduce");

        keep_only_key(&dir, &did, &old, "key-1")
            .await
            .expect("roll back");

        let raw = log_of(&dir).await;
        assert!(resolves(&dir, &did).await);
        assert_eq!(
            declared_keys(&raw),
            vec![DeclaredKey {
                fragment: "key-1".to_string(),
                multibase: old.public_key_multibase()
            }]
        );
        let old_mb = old.public_key_multibase();
        assert_eq!(signed_by(&last_entry(&raw)), format!("did:key:{old_mb}#{old_mb}"));
    }

    #[tokio::test]
    async fn no_entry_declares_assertion_method() {
        let (_s, dir, did, old) = born(39).await;
        let new = ControlKey::from_seed([40u8; 32]);
        introduce_key(&dir, &did, &old, "key-2", &new.public_key_multibase())
            .await
            .expect("introduce");
        keep_only_key(&dir, &did, &new, "key-2")
            .await
            .expect("retire");

        for line in log_of(&dir).await.lines() {
            let entry: Value = serde_json::from_str(line).expect("json");
            assert!(
                entry["state"]
                    .get("assertionMethod")
                    .is_none(),
                "{entry}"
            );
        }
    }

    #[tokio::test]
    async fn introducing_twice_is_a_no_op() {
        let (_s, dir, did, old) = born(41).await;
        let new = ControlKey::from_seed([42u8; 32]);
        introduce_key(&dir, &did, &old, "key-2", &new.public_key_multibase())
            .await
            .expect("introduce");
        let before = log_of(&dir).await;

        let again = introduce_key(&dir, &did, &old, "key-2", &new.public_key_multibase())
            .await
            .expect("introduce again");

        assert!(!again);
        assert_eq!(log_of(&dir).await, before, "nothing was appended");
        let retire_again = {
            keep_only_key(&dir, &did, &new, "key-2")
                .await
                .expect("retire");
            keep_only_key(&dir, &did, &new, "key-2")
                .await
                .expect("retire again")
        };
        assert!(!retire_again);
    }

    #[tokio::test]
    async fn the_next_key_fragment_is_one_past_the_highest_ever_used() {
        let (_s, dir, did, old) = born(43).await;
        assert_eq!(next_key_fragment(&log_of(&dir).await), "key-2");
        let new = ControlKey::from_seed([44u8; 32]);
        introduce_key(&dir, &did, &old, "key-2", &new.public_key_multibase())
            .await
            .expect("introduce");
        keep_only_key(&dir, &did, &new, "key-2")
            .await
            .expect("retire");

        assert_eq!(
            next_key_fragment(&log_of(&dir).await),
            "key-3",
            "a retired id is never reused, and the highest one counts even once it is the only key"
        );
    }

    #[tokio::test]
    async fn an_entry_is_never_built_in_the_same_second_as_the_previous_one() {
        let (_s, dir, did, old) = born(45).await;
        let new = ControlKey::from_seed([46u8; 32]);

        introduce_key(&dir, &did, &old, "key-2", &new.public_key_multibase())
            .await
            .expect("introduce right after the birth");
        keep_only_key(&dir, &did, &new, "key-2")
            .await
            .expect("retire right after");

        assert!(resolves(&dir, &did).await, "every entry is later than the one before");
        let times: Vec<i64> = log_of(&dir)
            .await
            .lines()
            .map(|l| {
                let v: Value = serde_json::from_str(l).unwrap();
                chrono::DateTime::parse_from_rfc3339(
                    v["versionTime"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap()
                .timestamp()
            })
            .collect();
        assert!(
            times
                .windows(2)
                .all(|w| w[0] < w[1]),
            "{times:?}"
        );
    }

    #[tokio::test]
    async fn keeping_a_key_the_document_does_not_declare_is_refused() {
        let (_s, dir, did, old) = born(47).await;
        let err = keep_only_key(&dir, &did, &old, "key-9")
            .await
            .expect_err("not declared");
        assert!(format!("{}", err.log_detail()).contains("key-9"));
    }

    #[tokio::test]
    async fn an_id_that_is_not_a_plain_identifier_cannot_name_a_did() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ControlKey::from_seed([9u8; 32]);

        for bad in ["", "..", "a/b", "a:b", "a b", "../x", "a%2Fb"] {
            let err = ensure_connection_auth_did(dir.path(), "example.com", bad, &key)
                .await
                .expect_err(bad);
            assert!(
                err.log_detail()
                    .contains("cannot name an auth DID"),
                "{bad}: {}",
                err.log_detail()
            );
        }
        assert!(is_plain_identifier("3f2c9a1e-7d4b-4c1a-9e55-0a1b2c3d4e5f"));
        assert!(is_plain_identifier("vta-bootstrap"));
    }
}

/// The whole chain, live, in one test: the gateway publishes its own
/// `did:webvh`, authenticates to a real VTA **as that DID**, provisions a
/// sub-context for a newly landed agent, and has the VTA sign for that agent's
/// key.
///
/// Every other live test authenticates with a bare `did:key`, so the auth
/// `did:webvh` — the thing an operator actually grants — was the one link
/// never exercised end to end. It is also the link most likely to fail
/// silently, because it only works if the VTA can **resolve** the published
/// document over HTTP and find the key inside it, which no unit test can show.
///
/// ```text
/// VTA_LIVE_URL=http://127.0.0.1:3000 \
/// VTA_LIVE_DID=did:webvh:<scid>:localhost%3A3000 \
/// VTA_LIVE_PARENT_CONTEXT=<granted context> \
///   cargo test --bin agent-trust-gateway \
///     vta::auth_did::live_tests -- --ignored --nocapture --test-threads=1
/// ```
///
/// The first run publishes the DID and fails, printing the grant command. Run
/// that once on the VTA and run the test again: the DID is stable across runs
/// (fixed seed, fixed storage, adopted rather than re-minted), so the grant
/// keeps matching.
#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::identity::ssi::vp_issuer::{Credentials, VpIssuer, VpIssuerPayload};
    use crate::vta::agent_contexts::{AgentKeyProvisioner, RegistryVtaClients, VtaAgentProvisioner};
    use crate::vta::client::VtaRestClient;
    use crate::vta::context_creator::GatewayContextCreator;
    use crate::vta::provisioning::ContextCreator;
    use crate::vta::vp_issuer::{AgentBinding, AgentContexts, VtaVpIssuer};
    use async_trait::async_trait;
    use std::sync::Arc;
    use std::time::Duration;

    /// Fixed so the published DID is identical on every run; the operator
    /// grants it once.
    const AUTH_SEED: [u8; 32] = [77u8; 32];
    const AUTH_STORAGE: &str = "/tmp/tg-vta-auth-e2e";
    const AUTH_PORT: u16 = 4567;

    /// Serve the published log at the URL its DID resolves to, so the VTA
    /// reads it the way any resolver would. Stands in for the gateway's own
    /// `/vta-auth/did.jsonl` route, which would need a whole running gateway.
    async fn serve_auth_did(dir: PathBuf) -> std::net::SocketAddr {
        use axum::Router;
        use axum::routing::get;

        let app = Router::new().route(
            "/vta-auth/did.jsonl",
            get(move || {
                let dir = dir.clone();
                async move {
                    tokio::fs::read_to_string(dir.join("did.jsonl"))
                        .await
                        .unwrap_or_default()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", AUTH_PORT))
            .await
            .expect("bind the auth DID server; is the port already in use?");
        let addr = listener
            .local_addr()
            .expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    struct Bound(AgentBinding);

    #[async_trait]
    impl AgentContexts for Bound {
        async fn binding_for(
            &self,
            _agent_did: &str,
        ) -> anyhow::Result<Option<AgentBinding>> {
            Ok(Some(self.0.clone()))
        }
    }

    struct Unreachable;

    #[async_trait]
    impl VpIssuer for Unreachable {
        async fn issue<'a>(
            &self,
            _payload: VpIssuerPayload<'a>,
        ) -> anyhow::Result<Value> {
            panic!("the local signer must not be reached — the agent's key lives in the VTA")
        }
    }

    #[tokio::test]
    #[ignore = "requires a running vta-service and a one-time grant of the published auth DID"]
    async fn live_the_whole_chain_from_published_auth_did_to_an_agent_signature() {
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID");
        let parent = std::env::var("VTA_LIVE_PARENT_CONTEXT").expect("set VTA_LIVE_PARENT_CONTEXT");

        // 1. The gateway publishes its own auth DID at bootstrap.
        let storage = PathBuf::from(AUTH_STORAGE);
        tokio::fs::create_dir_all(&storage)
            .await
            .expect("storage");
        let control = ControlKey::from_seed(AUTH_SEED);
        let domain = format!("localhost:{AUTH_PORT}");
        let auth_did = ensure_auth_did(&storage, &domain, &control)
            .await
            .expect("publish the gateway's auth DID");
        eprintln!("LIVE_AUTH_DID={auth_did}");

        // The operator's grant names this DID, so a restart must adopt it
        // rather than mint a new one and silently break authentication.
        assert_eq!(
            ensure_auth_did(&storage, &domain, &control)
                .await
                .expect("adopt"),
            auth_did,
            "a restart must not change the identity the grant names"
        );

        // 2. Make it resolvable, as a real deployment must.
        let addr = serve_auth_did(auth_did_dir(&storage)).await;
        eprintln!("LIVE_AUTH_DID_URL=http://{addr}/vta-auth/did.jsonl");

        // 3. Authenticate to the VTA *as that DID*. This is the step the test
        //    exists for: it succeeds only if the VTA resolved the document
        //    above and found this key declared inside it.
        let stable = control
            .with_stable_did(auth_did.clone(), None)
            .expect("present under the published DID");
        let client = Arc::new(
            VtaRestClient::new(&url, &vta_did, Arc::new(stable), Duration::from_secs(15), 8, None)
                .expect("build client"),
        );

        // 4. A new agent lands — provision a sub-context for it.
        let provisioner = VtaAgentProvisioner::new(
            GatewayContextCreator::new(Arc::clone(&client), parent.clone()),
            crate::vta::connections::BOOTSTRAP_CONNECTION_ID.to_string(),
        );
        let identity_hash = format!("live-chain-{}", uuid::Uuid::new_v4().simple());
        let agent = match provisioner
            .provision(&identity_hash)
            .await
        {
            Ok(agent) => agent,
            Err(e) => panic!(
                "could not provision while authenticated as the published auth DID.\n\n\
                 If this is a permission error, grant it once on the VTA:\n\n  {}\n\n\
                 If it is an authentication error, the VTA could not resolve \
                 http://{addr}/vta-auth/did.jsonl\n\n{e:?}",
                // The shared helper, so this stays a command the CLI accepts:
                // `import-did` takes no `--capabilities` and spells contexts
                // singular, so the form printed here could never be run.
                crate::vta::onboarding::grant_command_with_provisioning(&auth_did, &parent),
            ),
        };
        eprintln!("LIVE_CHAIN_AGENT did={} context={}", agent.did, agent.context_id);
        assert!(
            agent
                .context_id
                .starts_with(&format!("{parent}/")),
            "the agent's context must be a child of the granted one: {}",
            agent.context_id
        );
        assert!(
            agent
                .did
                .starts_with("did:key:"),
            "{}",
            agent.did
        );

        // The gateway's own signing context is a different one, so an agent's
        // key can never sign as the gateway or as another agent.
        let gateway_context = GatewayContextCreator::new(Arc::clone(&client), parent.clone())
            .create_context("ctx:_global/live-chain-gateway")
            .await
            .expect("the gateway's own signing context");
        assert_ne!(gateway_context.as_str(), agent.context_id, "an agent must not share the gateway's signing context");

        // 5. The VTA signs with that agent's key: a credential issued as the
        //    agent's own context, over the connection authenticated as the
        //    published auth DID.
        use crate::identity::ssi::vc_issuer::{AgentIdentity, IssueVcPayload, VcIssuer};
        let credential = crate::vta::vc_issuer::VtaVcIssuer::new(Arc::clone(&client), agent.context_id.clone())
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: std::borrow::Cow::Borrowed("did:key:zLiveChainSubject"),
                identity_fields: std::borrow::Cow::Owned(std::collections::HashMap::new()),
                workload_binding: None,
                display_name: None,
            }))
            .await
            .expect("the VTA signs for the agent's own key");
        assert_eq!(credential["issuer"], json!(agent.did), "issued as the agent's own context");
        assert_eq!(credential["proof"]["cryptosuite"], json!("eddsa-jcs-2022"));

        // 6. And it verifies against that agent's key — a signature nobody can
        //    check is not an outcome.
        let public_key = agent
            .did
            .strip_prefix("did:key:")
            .expect("did:key");
        let proof: affinidi_data_integrity::DataIntegrityProof =
            serde_json::from_value(credential["proof"].clone()).expect("proof deserialises");
        let mut unsigned = credential.clone();
        unsigned
            .as_object_mut()
            .expect("object")
            .remove("proof");
        let (_base, public_bytes) = multibase::decode(public_key).expect("multibase");
        proof
            .verify_with_public_key(&unsigned, &public_bytes[2..], affinidi_data_integrity::VerifyOptions::default())
            .expect("the credential must verify against the agent's own key");

        // 7. The agent's presentation is signed by the same key, over the same
        //    connection, and never touches a key the gateway holds.
        let issuer = VtaVpIssuer::new(
            Arc::new(RegistryVtaClients::new(Arc::clone(&client), None)),
            Arc::new(Bound(AgentBinding {
                context_id: agent.context_id.clone(),
                connection_id: None,
            })),
            Arc::new(Unreachable),
        );
        let vp = issuer
            .issue(VpIssuerPayload::Credentials(Credentials {
                holder_key: None,
                holder_did: std::borrow::Cow::Borrowed(&agent.did),
                verifiable_credentials: std::borrow::Cow::Owned(vec![credential]),
                challenge: None,
                domain: None,
            }))
            .await
            .expect("the VTA signs the agent's presentation");
        assert_eq!(vp["holder"], json!(agent.did));
        assert_eq!(vp["proof"]["proofPurpose"], json!("authentication"));
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .expect("resolver");
        let mut vp_unsigned = vp.clone();
        vp_unsigned
            .as_object_mut()
            .expect("object")
            .remove("proof");
        crate::identity::ssi::di_jcs::verify_jcs_proof(
            &vp_unsigned,
            &vp["proof"],
            Arc::clone(crate::gateways::did_cache::shared_resolver()),
        )
        .await
        .expect("the presentation must verify against the agent's own key");

        eprintln!("LIVE_CHAIN_OK auth={auth_did} agent={}", agent.did);
    }
    const CONN_SEED: [u8; 32] = [78u8; 32];
    const CONN_STORAGE: &str = "/tmp/tg-vta-conn-auth-e2e";
    const CONN_PORT: u16 = 4568;
    const CONN_ID: &str = "live-conn-webvh";

    /// Serve connection logs at the path the real gateway route serves them
    /// on (`/vta-auth/{connection_id}/did.jsonl`), reading them from where the
    /// publisher wrote them.
    async fn serve_connection_dids(
        storage: PathBuf,
        port: u16,
    ) -> std::net::SocketAddr {
        use axum::Router;
        use axum::extract::Path as UrlPath;
        use axum::routing::get;

        let app = Router::new().route(
            "/vta-auth/{connection_id}/did.jsonl",
            get(move |UrlPath(id): UrlPath<String>| {
                let storage = storage.clone();
                async move {
                    match connection_auth_did_dir(&storage, &id) {
                        Ok(dir) => tokio::fs::read_to_string(dir.join("did.jsonl"))
                            .await
                            .unwrap_or_default(),
                        Err(_) => String::new(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("bind the connection DID server; is the port already in use?");
        let addr = listener
            .local_addr()
            .expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// A managed connection authenticates to a real VTA **as the `did:webvh`
    /// the gateway published for it**, through the real connection registry.
    ///
    /// This is the path the dashboard creates: a per-connection key in the
    /// secrets store, a recorded `control_did`, and a registry that presents
    /// the key under that DID. It succeeds only if the VTA resolved the log at
    /// `/vta-auth/{id}/did.jsonl` and found the control key declared in it.
    ///
    /// The first run prints the grant command for the published DID. Run it on
    /// the VTA, then run the test again: the DID is stable across runs.
    #[tokio::test]
    #[ignore = "requires a running vta-service and a one-time grant of the published connection DID"]
    async fn live_a_managed_connection_authenticates_as_its_published_did() {
        use crate::vta::connections::{
            VtaConnection, VtaConnectionStatus, VtaConnectionStorage, VtaConnectionTransport,
        };
        use crate::vta::registry::VtaConnectionRegistry;

        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID");
        let parent = std::env::var("VTA_LIVE_PARENT_CONTEXT").expect("set VTA_LIVE_PARENT_CONTEXT");

        let storage = PathBuf::from(CONN_STORAGE);
        tokio::fs::create_dir_all(&storage)
            .await
            .expect("storage");
        let control = ControlKey::from_seed(CONN_SEED);
        let publisher = ConnectionDidPublisher::new(storage.clone(), format!("localhost:{CONN_PORT}"));
        let did = publisher
            .publish(CONN_ID, &control)
            .await
            .expect("publish the connection's DID");
        eprintln!("LIVE_CONN_DID={did}");
        assert_eq!(
            publisher
                .publish(CONN_ID, &control)
                .await
                .expect("adopt"),
            did,
            "a restart must not change the identity the grant names"
        );
        let addr = serve_connection_dids(storage.clone(), CONN_PORT).await;
        eprintln!("LIVE_CONN_DID_URL=http://{addr}/vta-auth/{CONN_ID}/did.jsonl");

        let now = chrono::Utc::now();
        let connection = VtaConnection {
            id: CONN_ID.to_string(),
            tenant_id: None,
            name: "live webvh connection".to_string(),
            description: None,
            enabled: true,
            transport: VtaConnectionTransport::Https,
            endpoint: url,
            vta_did,
            default_context_id: Some(parent.clone()),
            control_key_ref: Some("conn-seed".to_string()),
            control_did: Some(did.clone()),
            status: VtaConnectionStatus::Unpaired,
            keys: Default::default(),
            pairing: Default::default(),
            created_at: now,
            updated_at: now,
        };
        let records = tempfile::tempdir().expect("records");
        let store: Arc<dyn VtaConnectionStorage> = Arc::new(
            crate::vta::connections::FileSystemVtaConnectionStore::new(records.path().to_path_buf())
                .await
                .expect("store"),
        );
        let seed_hex: &'static str = Box::leak(
            control
                .seed_hex()
                .into_boxed_str(),
        );
        let secrets: Arc<dyn crate::secrets::SecretsStore> =
            Arc::new(crate::integrations::definitions::test_secrets::Secrets(vec![("conn-seed", None, seed_hex)]));
        let registry = VtaConnectionRegistry::new(store, Some(secrets), None, None, Duration::from_secs(15), 4);

        let outcome = match registry
            .verify(&connection)
            .await
        {
            Ok(outcome) => outcome,
            Err(e) => panic!(
                "could not authenticate as the published connection DID.\n\n\
                 If this is a permission error, grant it once on the VTA:\n\n  {}\n\n\
                 If it is an authentication error, the VTA could not resolve http://{addr}/vta-auth/{CONN_ID}/did.jsonl\n\n{e:?}",
                crate::vta::onboarding::grant_command_with_provisioning(&did, &parent),
            ),
        };

        assert!(
            outcome
                .scope
                .contexts
                .iter()
                .any(|c| c == &parent),
            "the session must carry the granted context: {:?}",
            outcome.scope
        );
        eprintln!("LIVE_CONN_OK did={did} scope={:?}", outcome.scope);
    }

    const ROTATE_STORAGE: &str = "/tmp/tg-vta-rotate-e2e";
    const ROTATE_PORT: u16 = 4569;
    const ROTATE_CONN: &str = "live-rotate-webvh";

    /// Append a log entry to the connection's `did.jsonl` that declares `keys`
    /// for authentication, hands updates to `update_keys`, and is signed by
    /// `signer`, the way a rotation would.
    async fn append_rotation_entry(
        dir: &Path,
        did: &str,
        signer: &ControlKey,
        keys: &[(&str, &ControlKey)],
        update_keys: &[&ControlKey],
    ) {
        // A webvh entry's versionTime (whole seconds) must be later than the last one's.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let path = dir.join("did.jsonl");
        let raw = tokio::fs::read_to_string(&path)
            .await
            .expect("log");
        let lines: Vec<&str> = raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        let mut state = didwebvh_rs::DIDWebVHState::default();
        state
            .resolve_log(did, &lines.join("\n"), None)
            .await
            .expect("the current log resolves");
        let last: Value = serde_json::from_str(
            lines
                .last()
                .expect("an entry"),
        )
        .expect("json");
        let mut doc = last["state"].clone();
        doc["verificationMethod"] = json!(
            keys.iter()
                .map(|(id, key)| json!({
                    "id": format!("{did}#{id}"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": key.public_key_multibase(),
                }))
                .collect::<Vec<_>>()
        );
        doc["authentication"] = json!(
            keys.iter()
                .map(|(id, _)| format!("{did}#{id}"))
                .collect::<Vec<_>>()
        );
        let mb = signer.public_key_multibase();
        let key_id = format!("did:key:{mb}#{mb}");
        let mut secret = didwebvh_rs::prelude::Secret::from_str(&key_id, &control_key_jwk(signer)).expect("secret");
        secret.id = key_id;
        let result = didwebvh_rs::prelude::update_did(
            didwebvh_rs::prelude::UpdateDIDConfig::builder()
                .state(state)
                .signing_key(secret)
                .update_keys(
                    update_keys
                        .iter()
                        .map(|k| didwebvh_rs::Multibase::new(k.public_key_multibase()))
                        .collect(),
                )
                .document(doc)
                .build()
                .expect("update config"),
        )
        .await
        .expect("update the DID");
        let entry = serde_json::to_string(result.log_entry()).expect("entry json");
        let updated = format!("{}\n{}\n", lines.join("\n"), entry);
        let mut check = didwebvh_rs::DIDWebVHState::default();
        check
            .resolve_log(did, updated.trim_end(), None)
            .await
            .expect("the new log still resolves locally");
        tokio::fs::write(&path, updated)
            .await
            .expect("write");
    }

    fn client_for(
        url: &str,
        vta_did: &str,
        key: &ControlKey,
        did: &str,
        vm: &str,
    ) -> VtaRestClient {
        let key = ControlKey::from_seed(key.seed_bytes())
            .with_stable_did(did.to_string(), Some(vm.to_string()))
            .expect("stable did");
        VtaRestClient::new(url, vta_did, Arc::new(key), Duration::from_secs(15), 4, None).expect("client")
    }

    /// Loop until `f` returns the wanted outcome or the time runs out; prints
    /// what happened on the way and returns how long it took.
    async fn until(
        what: &str,
        want_ok: bool,
        limit: Duration,
        f: impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), VtaError>> + Send>>,
    ) -> Option<Duration> {
        let start = std::time::Instant::now();
        let mut last = String::new();
        while start.elapsed() < limit {
            let r = f().await;
            let now = match &r {
                Ok(()) => "ok".to_string(),
                Err(VtaError::Http { status, body }) => format!(
                    "HTTP {status} {}",
                    body.chars()
                        .take(220)
                        .collect::<String>()
                ),
                Err(e) => format!("{e:?}"),
            };
            if now != last {
                eprintln!("  [{:>5.1}s] {what}: {now}", start.elapsed().as_secs_f32());
                last = now;
            }
            let refused = matches!(&r, Err(VtaError::Http { status: 401 | 403 | 422, .. }));
            if (want_ok && r.is_ok()) || (!want_ok && refused) {
                return Some(start.elapsed());
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        None
    }

    /// What a key rotation inside a connection's `did:webvh` needs from a real
    /// trust agent: a second key in the document authenticates, a superseded
    /// session says so, and a removed key stops authenticating.
    ///
    /// `LIVE_ROTATE_PHASE=publish` publishes a fresh DID and prints its grant
    /// command; grant it on the VTA, then run with `LIVE_ROTATE_PHASE=run`.
    #[tokio::test]
    #[ignore = "requires a running vta-service and a grant of the published DID"]
    async fn live_a_connection_did_rotates_its_key_on_a_real_trust_agent() {
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID");
        let phase = std::env::var("LIVE_ROTATE_PHASE").unwrap_or_else(|_| "run".to_string());
        let storage = PathBuf::from(ROTATE_STORAGE);
        let old = ControlKey::from_seed([91u8; 32]);
        let new = ControlKey::from_seed([92u8; 32]);
        let publisher = ConnectionDidPublisher::new(storage.clone(), format!("localhost:{ROTATE_PORT}"));
        if phase == "publish" {
            let _ = tokio::fs::remove_dir_all(&storage).await;
            tokio::fs::create_dir_all(&storage)
                .await
                .expect("storage");
            let did = publisher
                .publish(ROTATE_CONN, &old)
                .await
                .expect("publish");
            println!("LIVE_ROTATE_DID={did}");
            return;
        }
        let did = publisher
            .publish(ROTATE_CONN, &old)
            .await
            .expect("adopt");
        let dir = connection_auth_did_dir(&storage, ROTATE_CONN).expect("dir");
        serve_connection_dids(storage.clone(), ROTATE_PORT).await;
        let limit = Duration::from_secs(420);
        eprintln!("DID {did}");

        eprintln!("1. the old key, #key-1, signs in");
        let a = client_for(&url, &vta_did, &old, &did, "#key-1");
        a.authenticate()
            .await
            .expect("the published key authenticates");

        eprintln!("2. publish an entry declaring #key-1 and #key-2, updates by both, signed by the old key");
        append_rotation_entry(&dir, &did, &old, &[("key-1", &old), ("key-2", &new)], &[&old, &new]).await;
        let introduced = std::time::Instant::now();

        eprintln!("3. the new key, #key-2, signs in (the VTA may still have the old document cached)");
        let took = until("new key #key-2", true, limit, || {
            let c = client_for(&url, &vta_did, &new, &did, "#key-2");
            Box::pin(async move { c.authenticate().await })
        })
        .await;
        eprintln!("   => the new key was accepted after {took:?}");
        assert!(took.is_some(), "a second key in the document never authenticated");

        eprintln!("4. the old key still signs in while both are declared");
        let a2 = client_for(&url, &vta_did, &old, &did, "#key-1");
        a2.authenticate()
            .await
            .expect("the old key still authenticates during the overlap");

        eprintln!("5. a session of the same DID is superseded by a new sign-in");
        let b = client_for(&url, &vta_did, &new, &did, "#key-2");
        b.authenticate()
            .await
            .expect("new key");
        match a2.whoami().await {
            Ok(_) => eprintln!("   => NOT superseded: the old session still answers whoami"),
            Err(e) => eprintln!(
                "   => superseded: {e} code={:?} body={}",
                e.trust_task_code(),
                e.log_detail()
                    .chars()
                    .take(300)
                    .collect::<String>()
            ),
        }
        b.whoami()
            .await
            .expect("the newest session answers");

        eprintln!("6. retire #key-1: only #key-2, updates by the new key, signed by the new key");
        append_rotation_entry(&dir, &did, &new, &[("key-2", &new)], &[&new]).await;
        let gone = until("old key #key-1 after retire", false, limit, || {
            let c = client_for(&url, &vta_did, &old, &did, "#key-1");
            Box::pin(async move { c.authenticate().await })
        })
        .await;
        eprintln!("   => the old key was refused after {gone:?} (from the introduce: {:?})", introduced.elapsed());
        assert!(gone.is_some(), "the removed key kept authenticating");
        client_for(&url, &vta_did, &new, &did, "#key-2")
            .authenticate()
            .await
            .expect("the new key still authenticates after the retire");
        eprintln!("LIVE_ROTATE_OK");
    }
}
