//! The gateway's own signing keys, signed by the VTA library running in this
//! process.
//!
//! Local signing keeps the gateway's keys and DIDs exactly as they are on disk:
//! the key files stay the source of truth, and nothing new is persisted. Each
//! private key is imported once into an in-process VTA store, and every
//! signature is made by the VTA's own signing operations, so a signing bug is
//! fixed in one place whether the gateway signs locally or through a connected
//! trust agent.
//!
//! The store is a working copy, not a database. It lives in a directory this
//! process alone owns, encrypted with a key that exists only in memory, and is
//! rebuilt on every start. It is deliberately outside `_storage`: the VTA's
//! embedded database locks its directory, and an Active and a Standby node
//! share that folder.

mod signers;
mod support;

pub use signers::{VtaDiSigner, VtaSsiSigner};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde_json::{Map, Value};
use tokio::sync::{Mutex, OnceCell};
use vta_audit::SharedAuditSink;
use vta_sdk::keys::KeyType;
use vta_sdk::protocols::key_management::sign::{SignAlgorithm, SigningDomain};
use vta_service::keyspaces as ks;
use vta_service::operations::keys::{ImportKeyParams, import_key, sign_jws as vta_sign_jws, sign_payload};
use vta_service::operations::sign_formats::JwsPayload;
use vti_common::acl::Role;
use vti_common::auth::AuthClaims;
use vti_common::seed_store::SeedStore;
use vti_common::store::KeyspaceHandle;
use zeroize::Zeroizing;

use super::error::VtaError;
use support::{EphemeralSeedStore, TracingAuditSink};

const CONTEXT: &str = "gateway";
const CHANNEL: &str = "local";
const PRINCIPAL: &str = "local:agent-gateway";
const DIR_PREFIX: &str = "agent-gateway-vta-";

static ROOT: OnceLock<PathBuf> = OnceLock::new();
static SHARED: OnceCell<Arc<LocalVta>> = OnceCell::const_new();

/// Choose the directory the working store is created in, before the first use.
/// Absent, the system temporary directory is used. Ignored once chosen.
pub fn set_root(root: PathBuf) {
    let _ = ROOT.set(root);
}

/// The process-wide local signer, opened on first use.
pub async fn shared() -> Result<Arc<LocalVta>, VtaError> {
    SHARED
        .get_or_try_init(|| async {
            let root = ROOT
                .get()
                .cloned()
                .unwrap_or_else(std::env::temp_dir);
            LocalVta::open(&root).map(Arc::new)
        })
        .await
        .cloned()
}

fn config_error(detail: impl std::fmt::Display) -> VtaError {
    VtaError::Config(format!("local signing: {detail}"))
}

fn signing_error(detail: impl std::fmt::Debug) -> VtaError {
    VtaError::Signing(format!("local signing: {detail:?}"))
}

/// Remove working stores a crashed process left behind: those whose owner is
/// no longer running. They hold only ciphertext whose key died with that
/// process.
fn sweep_stale(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut system = sysinfo::System::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name
            .to_string_lossy()
            .strip_prefix(DIR_PREFIX)
            .map(str::to_string)
        else {
            continue;
        };
        let Some(pid) = rest
            .split('-')
            .next()
            .and_then(|p| p.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        let pid = sysinfo::Pid::from_u32(pid);
        system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        if system.process(pid).is_none() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The Ed25519 seed of a JWK's private part (`d`).
pub fn secret_of(key: &ssi::jwk::JWK) -> Result<Zeroizing<[u8; 32]>, VtaError> {
    let json = serde_json::to_value(key).map_err(signing_error)?;
    let d = json
        .get("d")
        .and_then(Value::as_str)
        .ok_or_else(|| VtaError::Signing("local signing: the key has no private part".to_string()))?;
    let bytes = Zeroizing::new(
        B64URL
            .decode(d)
            .map_err(|e| VtaError::Signing(format!("local signing: the private key is not base64url: {e}")))?,
    );
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| VtaError::Signing("local signing: the private key is not 32 bytes".to_string()))?;
    Ok(Zeroizing::new(seed))
}

pub struct LocalVta {
    keys: KeyspaceHandle,
    imported: KeyspaceHandle,
    internal: KeyspaceHandle,
    contexts: KeyspaceHandle,
    acl: KeyspaceHandle,
    seed: Arc<dyn SeedStore>,
    audit: SharedAuditSink,
    auth: AuthClaims,
    imported_keys: Mutex<HashMap<[u8; 32], String>>,
    _store: vta_service::store::Store,
    _dir: tempfile::TempDir,
}

fn public_key_of(secret: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(secret)
        .verifying_key()
        .to_bytes()
}

impl LocalVta {
    /// Open a fresh working store under `root`.
    pub fn open(root: &Path) -> Result<Self, VtaError> {
        std::fs::create_dir_all(root).map_err(|e| config_error(format!("cannot create {}: {e}", root.display())))?;
        sweep_stale(root);
        let dir = tempfile::Builder::new()
            .prefix(&format!("{DIR_PREFIX}{}-", std::process::id()))
            .tempdir_in(root)
            .map_err(|e| config_error(format!("cannot create a working store in {}: {e}", root.display())))?;
        let store = vta_service::store::Store::open(&vti_common::config::StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .map_err(|e| config_error(format!("cannot open the working store: {e}")))?;
        let wrapping_key = Zeroizing::new(rand::random::<[u8; 32]>());
        let keyspace = |name: &str| {
            store
                .keyspace(name)
                .map(|k| k.with_encryption(*wrapping_key))
                .map_err(|e| config_error(format!("cannot open keyspace {name}: {e}")))
        };
        Ok(Self {
            keys: keyspace(ks::KEYS)?,
            imported: keyspace(ks::IMPORTED_SECRETS)?,
            internal: keyspace(ks::INTERNAL_KEYS)?,
            contexts: keyspace(ks::CONTEXTS)?,
            acl: keyspace(ks::ACL)?,
            seed: Arc::new(EphemeralSeedStore::random()),
            audit: Arc::new(TracingAuditSink),
            auth: AuthClaims {
                did: PRINCIPAL.to_string(),
                role: Role::Admin,
                allowed_contexts: vec![CONTEXT.to_string()],
                ..Default::default()
            },
            imported_keys: Mutex::new(HashMap::new()),
            _store: store,
            _dir: dir,
        })
    }

    /// The VTA key id holding `secret`, importing it the first time it is seen.
    ///
    /// Keyed by the key's own public half, so the same key is imported once
    /// however many callers present it, and a replaced key is simply a new one.
    async fn key_id_for(
        &self,
        secret: &[u8; 32],
    ) -> Result<String, VtaError> {
        let public = public_key_of(secret);
        let mut imported = self
            .imported_keys
            .lock()
            .await;
        if let Some(key_id) = imported.get(&public) {
            return Ok(key_id.clone());
        }
        let label = format!("k-{}", hex::encode(&public[..16]));
        let created = import_key(
            &self.keys,
            &self.imported,
            &self.seed,
            &self.audit,
            &self.auth,
            ImportKeyParams {
                key_type: KeyType::Ed25519,
                private_key_bytes: secret.to_vec(),
                label: Some(label),
                context_id: Some(CONTEXT.to_string()),
            },
            CHANNEL,
        )
        .await
        .map_err(signing_error)?;
        imported.insert(public, created.key_id.clone());
        Ok(created.key_id)
    }

    #[cfg(test)]
    pub async fn holds(
        &self,
        secret: &[u8; 32],
    ) -> bool {
        self.imported_keys
            .lock()
            .await
            .contains_key(&public_key_of(secret))
    }

    /// The compact JWS of `payload_b64` (an already base64url-encoded payload,
    /// signed exactly as given) under the header `{typ, kid}` plus the `alg`
    /// the VTA sets, signed by the Ed25519 key `secret`.
    pub async fn sign_jws(
        &self,
        secret: &[u8; 32],
        typ: &str,
        kid: &str,
        payload_b64: &str,
    ) -> Result<String, VtaError> {
        let key_id = self
            .key_id_for(secret)
            .await?;
        let mut header = Map::new();
        header.insert("typ".to_string(), Value::String(typ.to_string()));
        header.insert("kid".to_string(), Value::String(kid.to_string()));
        let (jws, alg) = vta_sign_jws(
            &self.keys,
            &self.imported,
            &self.internal,
            &self.contexts,
            &self.acl,
            &self.seed,
            &self.audit,
            &self.auth,
            &key_id,
            &header,
            JwsPayload::Base64Url(payload_b64),
            CHANNEL,
        )
        .await
        .map_err(signing_error)?;
        if alg != "EdDSA" {
            return Err(VtaError::Signing(format!("local signing: the key signed with {alg}, not EdDSA")));
        }
        Ok(jws)
    }

    /// The Ed25519 signature of exactly `message`, by the key `secret`. For
    /// formats whose signed bytes the gateway builds itself (Data Integrity
    /// hash data, a `did:webvh` log entry).
    pub async fn sign_raw(
        &self,
        secret: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; 64], VtaError> {
        let key_id = self
            .key_id_for(secret)
            .await?;
        let signed = sign_payload(
            &self.keys,
            &self.imported,
            &self.internal,
            &self.contexts,
            &self.acl,
            &self.seed,
            &self.audit,
            &self.auth,
            &key_id,
            message,
            &SignAlgorithm::EdDSA,
            SigningDomain::ProtocolDefined,
            CHANNEL,
        )
        .await
        .map_err(signing_error)?;
        let bytes = B64URL
            .decode(signed.signature.as_bytes())
            .map_err(|e| VtaError::Signing(format!("local signing: the signature is not base64url: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| VtaError::Signing("local signing: the signature is not 64 bytes".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
    use serde_json::json;

    use super::*;

    fn secret(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn payload_b64(claims: &Value) -> String {
        B64URL.encode(serde_json::to_string(claims).expect("json"))
    }

    fn verify(
        jws: &str,
        secret: &[u8; 32],
    ) -> bool {
        let parts: Vec<&str> = jws.split('.').collect();
        let signature = Signature::from_slice(
            &B64URL
                .decode(parts[2])
                .expect("signature"),
        )
        .expect("64 bytes");
        SigningKey::from_bytes(secret)
            .verifying_key()
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .is_ok()
    }

    fn open() -> (LocalVta, tempfile::TempDir) {
        let root = tempfile::tempdir().expect("root");
        (LocalVta::open(root.path()).expect("open"), root)
    }

    #[tokio::test]
    async fn a_token_signed_through_the_vta_verifies_under_the_keys_own_public_half() {
        let (vta, _root) = open();
        let claims =
            json!({"iss": "did:web:example.com", "sub": "agent", "iat": 1_700_000_000, "n": {"b": 1, "a": "x"}});
        let payload = payload_b64(&claims);

        let jws = vta
            .sign_jws(&secret(1), "JWT", "key-1", &payload)
            .await
            .expect("signed");

        assert!(verify(&jws, &secret(1)));
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts[1], payload, "the payload segment is signed exactly as given");
        let header: Value = serde_json::from_slice(
            &B64URL
                .decode(parts[0])
                .expect("header"),
        )
        .expect("json");
        assert_eq!(header, json!({"alg": "EdDSA", "typ": "JWT", "kid": "key-1"}));
    }

    #[tokio::test]
    async fn the_explicit_type_is_carried_into_the_header() {
        let (vta, _root) = open();
        let jws = vta
            .sign_jws(&secret(2), "oauth-id-jag+jwt", "key-1", &payload_b64(&json!({"a": 1})))
            .await
            .expect("signed");
        let header: Value = serde_json::from_slice(
            &B64URL
                .decode(jws.split('.').next().unwrap())
                .expect("header"),
        )
        .expect("json");
        assert_eq!(header["typ"], "oauth-id-jag+jwt");
    }

    #[tokio::test]
    async fn a_raw_signature_is_the_one_the_key_makes_itself() {
        let (vta, _root) = open();
        let message = b"hash data the gateway built itself";

        let signature = vta
            .sign_raw(&secret(3), message)
            .await
            .expect("signed");

        assert_eq!(
            signature,
            SigningKey::from_bytes(&secret(3))
                .sign(message)
                .to_bytes()
        );
    }

    #[tokio::test]
    async fn two_keys_sign_independently_and_a_key_is_imported_once() {
        let (vta, _root) = open();
        let payload = payload_b64(&json!({"a": 1}));

        let first = vta
            .sign_jws(&secret(4), "JWT", "k", &payload)
            .await
            .expect("signed");
        let again = vta
            .sign_jws(&secret(4), "JWT", "k", &payload)
            .await
            .expect("signed");
        let other = vta
            .sign_jws(&secret(5), "JWT", "k", &payload)
            .await
            .expect("signed");

        assert_eq!(first, again, "Ed25519 is deterministic");
        assert!(verify(&other, &secret(5)));
        assert!(!verify(&other, &secret(4)), "a token is not valid under another key");
        assert_eq!(
            vta.imported_keys
                .lock()
                .await
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn concurrent_first_uses_of_one_key_import_it_once() {
        let (vta, _root) = open();
        let vta = Arc::new(vta);
        let payload = payload_b64(&json!({"a": 1}));

        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let vta = Arc::clone(&vta);
                let payload = payload.clone();
                tokio::spawn(async move {
                    vta.sign_jws(&secret(6), "JWT", "k", &payload)
                        .await
                })
            })
            .collect();
        for task in tasks {
            task.await
                .expect("joined")
                .expect("signed");
        }

        assert_eq!(
            vta.imported_keys
                .lock()
                .await
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_payload_that_is_not_canonical_base64url_is_refused_not_signed() {
        let (vta, _root) = open();
        let refused = vta
            .sign_jws(&secret(7), "JWT", "k", "not base64url!")
            .await;
        assert!(matches!(refused, Err(VtaError::Signing(_))), "{refused:?}");
    }

    #[test]
    fn each_open_store_has_its_own_directory_and_it_goes_away_with_the_signer() {
        let root = tempfile::tempdir().expect("root");
        let first = LocalVta::open(root.path()).expect("first");
        let second = LocalVta::open(root.path()).expect("second");
        let count = || {
            std::fs::read_dir(root.path())
                .expect("read")
                .filter(|e| {
                    e.as_ref().is_ok_and(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with(DIR_PREFIX)
                    })
                })
                .count()
        };
        assert_eq!(count(), 2);
        drop(first);
        drop(second);
        assert_eq!(count(), 0);
    }

    #[test]
    fn a_store_left_by_a_process_that_is_gone_is_removed_and_a_live_one_is_kept() {
        let root = tempfile::tempdir().expect("root");
        let gone = root
            .path()
            .join(format!("{DIR_PREFIX}4294967294-abc"));
        let live = root
            .path()
            .join(format!("{DIR_PREFIX}{}-abc", std::process::id()));
        let unrelated = root
            .path()
            .join("something-else");
        for dir in [&gone, &live, &unrelated] {
            std::fs::create_dir(dir).expect("dir");
        }

        sweep_stale(root.path());

        assert!(!gone.exists(), "a dead process's store is removed");
        assert!(live.exists(), "this process's store is kept");
        assert!(unrelated.exists(), "other directories are left alone");
    }

    #[tokio::test]
    async fn the_shared_signer_is_one_instance() {
        let first = shared().await.expect("first");
        let second = shared()
            .await
            .expect("second");
        assert!(Arc::ptr_eq(&first, &second));
    }
}
