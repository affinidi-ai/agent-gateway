//! Verifiable Trust Agent (VTA) **signing connector**.
//!
//! The gateway delegates its private-key operations to a VTA by acting as a
//! thin REST/Trust-Task **client** of the VTA (`POST {base_url}/trust-tasks`).
//! The gateway and VTA are separate services; this module speaks the VTA's HTTP
//! surface with the gateway's own `reqwest`/crypto and does **not** link
//! `vta-sdk`.
//!
//! ## Pluggable signing connectors
//!
//! [`crate::identity::authority::CredentialAuthority`] is the connector
//! interface. Two connectors exist today:
//!
//! - **local** — the in-process issuer key (`LocalCredentialAuthority`).
//! - **vta** — this module ([`authority::VtaCredentialAuthority`]).
//!
//! [`select_credential_authority`] is the connector registry: it picks the
//! active connector from `[vta]` config. A future third signing backend (an
//! HSM/KMS service, or any external signer that is *not* a VTA) is added by
//! implementing `CredentialAuthority` and adding one arm here — no signing call
//! site changes.

pub mod agent_contexts;
pub mod appliance_di;
pub mod audit;
pub mod auth_did;
pub mod authority;
pub mod client;
pub mod connections;
pub mod connections_admin;
pub mod context_creator;
pub mod context_signer;
pub mod control_key;
pub mod di_proof;
pub mod error;
pub mod inventory;
pub mod isolation;
pub mod key_directory;
pub mod key_surfaces;
pub mod onboarding;
pub mod onboarding_default;
pub mod pairing;
pub mod provisioning;
pub mod quota;
pub mod registry;
pub mod resilience;
pub mod transport;
pub mod vc_issuer;
pub mod vp_issuer;
pub mod wire;

pub use error::VtaError;

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::config::vta::VtaConfig;
use crate::identity::authority::CredentialAuthority;
use authority::VtaCredentialAuthority;
use client::VtaRestClient;
use control_key::{ControlKey, SignerKeyProvider};

/// The signing backends `[vta]` selects, built from **one** client.
///
/// One client because one control DID gets one VTA session: a second client
/// authenticating as the same DID supersedes the first, and the superseded one
/// then fails with `401 unauthorized: token superseded`. So the credential
/// authority and the Data-Integrity issuer share a connection rather than each
/// opening their own.
pub struct SelectedSigning {
    /// Signs JWT-shaped artifacts: STS tokens, ID-JAGs, payment receipts, and
    /// the JWT agent-identity credential (VTA-11a).
    pub authority: Arc<dyn CredentialAuthority>,
    /// Issues the Data-Integrity agent-identity credential embedded in the
    /// forwarding VP (VTA-11b). `None` when `[vta]` is disabled, in which case
    /// the local issuer stays in place.
    pub di_vc_issuer: Option<Arc<dyn crate::identity::ssi::vc_issuer::VcIssuer>>,
    /// Creates per-surface contexts under the gateway's own (VTA-16). `None`
    /// when `[vta]` is disabled or the operator has not opted into
    /// auto-provisioning, in which case an unmapped surface is a configuration
    /// error rather than something provisioned behind the operator's back.
    pub context_creator: Option<Arc<dyn crate::vta::provisioning::ContextCreator>>,
    /// Provisions a per-agent context so an agent's holder key lives in the
    /// VTA rather than on this host (VTA-12). `None` under the same conditions
    /// as `context_creator`, and for the same reason: provisioning a context
    /// per managed agent is not something to start doing silently.
    pub agent_provisioner: Option<Arc<dyn crate::vta::agent_contexts::AgentKeyProvisioner>>,
    /// The client the holder-proof issuer dials (VTA-12).
    ///
    /// Handed out rather than used here because that issuer needs the identity
    /// store to map an agent to its context, and the store is not available
    /// this early. Sharing the client matters: the VTA supersedes an earlier
    /// session when a second one opens for the same control DID, so a separate
    /// client would knock this one out.
    pub client: Option<Arc<crate::vta::client::VtaRestClient>>,
}

/// Select the active signing connector from `[vta]` config.
///
/// When the block is disabled (the default) the `local` connector is returned
/// unchanged — a zero-cost no-op. When enabled, the VTA connector is built from
/// the configured coordinates. Fails closed: an enabled-but-unbuildable
/// connector is a startup error, never a silent fallback to local signing.
///
/// Returns the Data-Integrity issuer alongside it, sharing the same client.
pub async fn select_signing_backends(
    config: &VtaConfig,
    local: Arc<dyn CredentialAuthority>,
) -> Result<SelectedSigning, VtaError> {
    if !config.enabled {
        return Ok(SelectedSigning {
            authority: local,
            di_vc_issuer: None,
            context_creator: None,
            agent_provisioner: None,
            client: None,
        });
    }
    let base_url = config
        .base_url
        .as_deref()
        .ok_or_else(|| VtaError::Config("[vta] base_url is required when enabled".to_string()))?;

    // Take the VTA's address off the data plane before anything can forward to
    // it (VTA-21). A bundled sidecar lives on loopback or a private network —
    // addresses a surface is otherwise allowed to reach — so without this a
    // caller could drive the agent holding this gateway's signing keys through
    // the proxy pipeline.
    isolation::reserve(base_url);

    // A bundled sidecar keeps its key material on the gateway's own disk, so
    // encryption at rest is the only thing standing between a disk image and
    // the signing keys. Fail closed rather than starting a deployment whose
    // security story quietly does not hold.
    if config
        .mode
        .allows_self_administration()
        && !crate::encryption::global::is_field_encryption_configured()
    {
        return Err(VtaError::Config(
            "[vta] the bundled deployment keeps VTA key material on this host, so encryption at rest must be \
             configured; enable it or switch to `mode = \"appliance\"`"
                .to_string(),
        ));
    }

    let vta_did = config
        .vta_did
        .as_deref()
        .ok_or_else(|| VtaError::Config("[vta] vta_did is required when enabled".to_string()))?;
    let context_id = config
        .context_id
        .as_deref()
        .ok_or_else(|| VtaError::Config("[vta] context_id is required when enabled".to_string()))?;
    let signing_key_id = config
        .signing_key_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| VtaError::Config("[vta] signing_key_id is required when enabled".to_string()))?
        .to_string();

    let control_key = build_control_key(config).await?;
    // The issuer DID is established at onboarding (VTA-05); until then it
    // defaults to the VTA service DID.
    let issuer_did = vta_did.to_string();

    // Customer-sovereign onboarding (VTA-05): print the exact one-consent-step
    // grant command the customer runs on their VTA, and set up the post-auth
    // grant-scope + record checks. The gateway never holds VTA admin itself.
    tracing::info!(
        target: "vta_audit",
        control_did = %control_key.did(),
        "VTA connector enabled — grant this gateway with: {}",
        if config.auto_provision_contexts {
            onboarding::grant_command_with_provisioning(control_key.did(), context_id)
        } else {
            onboarding::grant_command(control_key.did(), context_id)
        }
    );
    let record_path = onboarding_record_path(config);
    let onboarding = onboarding::OnboardingState::new(
        record_path,
        context_id.to_string(),
        issuer_did.clone(),
        std::time::Duration::from_secs(ROTATION_MIN_INTERVAL_SECS),
    );

    let client = Arc::new(VtaRestClient::new(
        base_url,
        vta_did,
        control_key,
        Duration::from_millis(config.timeout_ms),
        config.max_concurrent,
        Some(onboarding),
    )?);

    // Optional VTA-08 audit sink: bounded, data-minimized, non-blocking. Off by
    // default; when enabled it logs hashes-only records on the `vta_audit`
    // target and can never block or fail a signing request.
    let audit = config
        .audit_enabled
        .then(|| audit::VtaAuditSink::spawn(config.audit_queue_capacity, Arc::new(audit::LogAuditEmitter)));

    // VTA-17: keep the local issuer's **public** key in the published JWKS.
    // Migrating surface by surface means tokens signed by the local key are
    // still in flight; dropping it from the JWKS would break them. A failure
    // here must not block startup — it only costs the carried-over key.
    let carried_over_jwks = match local.issuer_jwks().await {
        Ok(jwks) => jwks
            .get("keys")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        Err(e) => {
            tracing::warn!(
                target: "vta_audit",
                error = %e,
                "local issuer JWKS unavailable; VTA-signed tokens will publish without it",
            );
            Vec::new()
        }
    };

    let di_vc_issuer: Arc<dyn crate::identity::ssi::vc_issuer::VcIssuer> =
        Arc::new(vc_issuer::VtaVcIssuer::new(Arc::clone(&client), context_id.to_string()));

    // Provisioning uses the narrow `context-create` capability, never
    // super-admin: every context it creates is a child of the one the gateway
    // was granted, which is also the only place the capability reaches
    // (VTA-16). Opt-in, because a gateway whose grant lacks the capability
    // should be told so at surface-write time rather than discover it at the
    // first signing call.
    let provisioner: Option<Arc<dyn crate::vta::provisioning::ContextCreator>> = config
        .auto_provision_contexts
        .then(|| {
            Arc::new(context_creator::GatewayContextCreator::new(Arc::clone(&client), context_id.to_string()))
                as Arc<dyn crate::vta::provisioning::ContextCreator>
        });

    // The agent provisioner branches from the same grant, but designates its
    // contexts for `authentication` as well: a holder signs a presentation,
    // and the VTA resolves a different key for that purpose.
    let agent_provisioner: Option<Arc<dyn crate::vta::agent_contexts::AgentKeyProvisioner>> = config
        .auto_provision_contexts
        .then(|| {
            Arc::new(agent_contexts::VtaAgentProvisioner::new(
                context_creator::GatewayContextCreator::new(Arc::clone(&client), context_id.to_string()),
                connections::BOOTSTRAP_CONNECTION_ID.to_string(),
            )) as Arc<dyn crate::vta::agent_contexts::AgentKeyProvisioner>
        });

    Ok(SelectedSigning {
        authority: Arc::new(
            VtaCredentialAuthority::new(Arc::clone(&client), issuer_did, signing_key_id, audit)
                .with_signing_key_public(
                    config
                        .signing_key_public
                        .clone(),
                )
                .with_retiring_keys(
                    config
                        .retiring_keys
                        .iter()
                        .map(|k| (k.key_id.clone(), k.public_key.clone()))
                        .collect(),
                )
                .with_carried_over_jwks(carried_over_jwks)
                .with_quota(quota::SignQuota::new(config.sign_quota_max, config.sign_quota_window_secs)),
        ),
        di_vc_issuer: Some(di_vc_issuer),
        context_creator: provisioner,
        agent_provisioner,
        client: Some(Arc::clone(&client)),
    })
}

/// Minimum interval between control-DID changes before a rotation is flagged
/// off-schedule (24h).
const ROTATION_MIN_INTERVAL_SECS: u64 = 86_400;

/// Where to persist the onboarding record, encrypted at rest: alongside a
/// `file://` control key (so key + grant travel together). `None` for
/// ephemeral / `env://` keys, which are not persisted.
fn onboarding_record_path(config: &VtaConfig) -> Option<std::path::PathBuf> {
    let source = config
        .auth_key_source
        .as_deref()?;
    let key_path = source.strip_prefix("file://")?;
    std::path::Path::new(key_path)
        .parent()
        .map(|dir| dir.join("vta_onboarding"))
}

/// Source the gateway's Ed25519 control key behind the [`SignerKeyProvider`]
/// seam (so a non-exportable KMS key can replace it later without changing the
/// handshake).
///
/// - no `auth_key_source` → **ephemeral** key (regenerated each start),
/// - `env://VAR` → a 32-byte hex seed from the environment,
/// - `file://path` → a seed persisted **encrypted at rest** (whole-file `.enc`
///   via the shared secret-file helper) and generated on first boot.
async fn build_control_key(config: &VtaConfig) -> Result<Arc<dyn SignerKeyProvider>, VtaError> {
    let key = build_control_key_material(config).await?;
    // A stable identifier is applied *after* the key is sourced, because the
    // two are independent by design: the key rotates, the identifier does not
    // (VTA-13). Nothing here can rewrite the DID document — the update key
    // that could lives off this host.
    let Some(auth_did) = config.auth_did.as_deref() else {
        return Ok(Arc::new(key));
    };
    let key = key.with_stable_did(
        auth_did.to_string(),
        config
            .auth_verification_method
            .clone(),
    )?;
    verify_stable_did_declares_key(&key).await?;
    Ok(Arc::new(key))
}

/// Check that the DID document `key`'s identifier resolves to actually declares
/// the key the gateway holds.
///
/// A stable identifier decouples the key from the DID, which is the point — and
/// also the new failure mode: a rotation that was *intended* but never
/// published leaves the gateway signing with a key its own DID document does
/// not name, and every authentication fails with a signature error that says
/// nothing about why.
///
/// Resolution failure and mismatch are treated differently on purpose. Failing
/// to resolve may be transient or an ordering problem at boot, so it warns.
/// Resolving to a document that does not declare this key is a configuration
/// error that will never succeed, so it fails closed at startup rather than at
/// the first request.
async fn verify_stable_did_declares_key(key: &ControlKey) -> Result<(), VtaError> {
    let did = key.did();
    let resolved = match crate::gateways::did_cache::shared_resolver()
        .resolve(did)
        .await
    {
        Ok(resolved) => resolved,
        Err(e) => {
            tracing::warn!(
                target: "vta_audit",
                auth_did = %did,
                error = %e,
                "could not resolve the gateway's auth DID at startup; authentication will fail \
                 until it resolves \u{2014} check the did.jsonl is published and reachable",
            );
            return Ok(());
        }
    };

    let document = serde_json::to_value(&resolved.doc)
        .map_err(|e| VtaError::Config(format!("[vta] auth_did document could not be read: {e}")))?;
    let expected = key.public_key_multibase();
    let vm = key.verification_method();

    let declares = document
        .get("verificationMethod")
        .and_then(|m| m.as_array())
        .is_some_and(|methods| {
            methods.iter().any(|method| {
                let id_matches = method
                    .get("id")
                    .and_then(|i| i.as_str())
                    .is_some_and(|id| {
                        id == vm
                            || id.strip_prefix('#')
                                == vm
                                    .split_once('#')
                                    .map(|(_, f)| f)
                    });
                let key_matches = method
                    .get("publicKeyMultibase")
                    .and_then(|k| k.as_str())
                    .is_some_and(|k| k == expected);
                id_matches && key_matches
            })
        });

    if !declares {
        return Err(VtaError::Config(format!(
            "[vta] auth_did `{did}` resolves, but its DID document does not declare `{vm}` with \
             the signing key this gateway holds. Publish the rotation to the did.jsonl, or point \
             auth_verification_method at the method this key actually backs."
        )));
    }

    tracing::info!(
        target: "vta_audit",
        auth_did = %did,
        verification_method = %vm,
        "gateway auth DID resolves and declares the held signing key",
    );
    Ok(())
}

/// Source the control key material itself, before any identifier is applied.
pub(crate) async fn build_control_key_material(config: &VtaConfig) -> Result<ControlKey, VtaError> {
    let Some(source) = config
        .auth_key_source
        .as_deref()
    else {
        return Ok(ControlKey::generate());
    };
    if let Some(var) = source.strip_prefix("env://") {
        let hex = std::env::var(var)
            .map_err(|_| VtaError::Config(format!("[vta] auth_key_source env var `{var}` is not set")))?;
        return Ok(ControlKey::from_seed(decode_hex_seed(hex.trim())?));
    }
    if let Some(path) = source.strip_prefix("file://") {
        return load_or_create_file_key(std::path::Path::new(path)).await;
    }
    Err(VtaError::Config(format!("[vta] auth_key_source scheme is not supported (use env:// or file://): {source}")))
}

/// Where the appliance's own VTA control key is persisted.
///
/// One per gateway, beside the issuer's other key material so it inherits
/// encryption at rest.
pub fn appliance_control_key_path(issuer_storage: &std::path::Path) -> std::path::PathBuf {
    issuer_storage.join("vta_appliance_control_key")
}

/// Mint the appliance's VTA control key, or adopt the one already stored.
///
/// **Idempotent, and that is the whole point.** This key is the gateway's
/// identity to a trust agent, and an operator grants that identity by hand. A
/// restart that minted a second key would silently invalidate a grant that had
/// already been made, and the failure would surface later as an
/// authentication error with no obvious cause.
pub async fn ensure_appliance_control_key(issuer_storage: &std::path::Path) -> Result<ControlKey, VtaError> {
    load_or_create_file_key(&appliance_control_key_path(issuer_storage)).await
}

/// Load the control-key seed from `path`, generating and persisting a fresh one
/// on first boot. Persistence goes through the encrypted secret-file helper, so
/// the seed is written as a whole-file `.enc` blob when encryption at rest is
/// active and never lingers in plaintext.
async fn load_or_create_file_key(path: &std::path::Path) -> Result<ControlKey, VtaError> {
    match crate::encryption::secret_file::read_secret_file(path).await {
        Ok(Some(hex)) => Ok(ControlKey::from_seed(decode_hex_seed(hex.trim())?)),
        Ok(None) => {
            let key = ControlKey::generate();
            crate::encryption::secret_file::write_secret_file(path, &key.seed_hex())
                .await
                .map_err(|e| VtaError::Config(format!("[vta] persist control key: {e}")))?;
            Ok(key)
        }
        Err(e) => Err(VtaError::Config(format!("[vta] read control key: {e}"))),
    }
}

/// The `did:key` of a control-key seed, without holding the key.
///
/// Derived rather than stored on the connection record, so the DID the customer
/// is asked to grant and the key the gateway will actually authenticate with
/// cannot drift apart (VTA-24).
pub fn control_key_did(seed_hex: &str) -> Result<String, VtaError> {
    Ok(ControlKey::from_seed(decode_hex_seed(seed_hex)?)
        .did()
        .to_string())
}

/// Decode a 64-character hex string into a 32-byte Ed25519 seed.
fn decode_hex_seed(hex: &str) -> Result<[u8; 32], VtaError> {
    if hex.len() != 64 {
        return Err(VtaError::Config("[vta] control-key seed must be 32 bytes (64 hex chars)".to_string()));
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        let hi = hex_nibble(hex.as_bytes()[i * 2])?;
        let lo = hex_nibble(hex.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(seed)
}

fn hex_nibble(c: u8) -> Result<u8, VtaError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(VtaError::Config("[vta] control-key seed is not valid hex".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::authority::LocalCredentialAuthority;

    async fn local_authority() -> (Arc<dyn CredentialAuthority>, tempfile::TempDir) {
        let (issuer, tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        (Arc::new(LocalCredentialAuthority::new(Arc::new(issuer))), tmp)
    }

    #[tokio::test]
    async fn disabled_config_returns_the_local_connector() {
        let (local, _tmp) = local_authority().await;
        let config = VtaConfig::default();
        let selected = select_signing_backends(&config, Arc::clone(&local))
            .await
            .expect("select");
        // Disabled → the very same local authority is handed back.
        assert!(Arc::ptr_eq(&local, &selected.authority));
    }

    #[tokio::test]
    async fn enabled_config_builds_the_vta_connector() {
        let (local, _tmp) = local_authority().await;
        let config = VtaConfig {
            enabled: true,
            base_url: Some("http://localhost:3000".to_string()),
            vta_did: Some("did:webvh:vta.example".to_string()),
            context_id: Some("ctx".to_string()),
            signing_key_id: Some("key-gateway-jwt".to_string()),
            ..VtaConfig::default()
        };
        let selected = select_signing_backends(&config, Arc::clone(&local))
            .await
            .expect("select");
        // Enabled → a different (VTA) connector, not the local one.
        assert!(!Arc::ptr_eq(&local, &selected.authority));
    }

    #[tokio::test]
    async fn enabled_without_a_signing_key_fails_closed() {
        let (local, _tmp) = local_authority().await;
        let config = VtaConfig {
            enabled: true,
            base_url: Some("http://localhost:3000".to_string()),
            vta_did: Some("did:webvh:vta.example".to_string()),
            context_id: Some("ctx".to_string()),
            signing_key_id: None,
            ..VtaConfig::default()
        };
        let err = match select_signing_backends(&config, Arc::clone(&local)).await {
            Ok(_) => panic!("no pinned signing key must fail closed"),
            Err(e) => e,
        };
        assert!(matches!(err, VtaError::Config(_)), "config error, got {err:?}");
    }

    #[tokio::test]
    async fn file_control_key_is_persisted_and_reloaded_stably() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("vta_control_key");
        let source = format!("file://{}", path.display());

        // First boot: generates + persists the seed, and the file now exists
        // (plaintext seed when encryption at rest is inactive in tests).
        let first = build_control_key(&VtaConfig {
            auth_key_source: Some(source.clone()),
            ..VtaConfig::default()
        })
        .await
        .expect("first build");
        assert!(path.exists() || crate::encryption::secret_file::secret_enc_path(&path).exists());

        // Second boot: reloads the same seed → the same control did:key.
        let second = build_control_key(&VtaConfig {
            auth_key_source: Some(source),
            ..VtaConfig::default()
        })
        .await
        .expect("second build");
        assert_eq!(first.did(), second.did(), "persisted key reloads to the same identity");
    }

    #[test]
    fn hex_seed_decodes_32_bytes() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let seed = decode_hex_seed(hex).expect("valid seed");
        assert_eq!(seed[0], 0x00);
        assert_eq!(seed[1], 0x11);
        assert_eq!(seed[31], 0xff);
    }

    #[test]
    fn hex_seed_rejects_wrong_length() {
        assert!(decode_hex_seed("abcd").is_err());
    }

    /// The property the whole startup mint depends on. An operator grants this
    /// gateway's DID by hand on their trust agent; a restart that minted a
    /// second key would silently invalidate that grant, and the failure would
    /// surface later as an authentication error with no obvious cause.
    #[tokio::test]
    async fn the_appliance_control_key_survives_a_restart() {
        let tmp = tempfile::tempdir().expect("tempdir");

        let first = ensure_appliance_control_key(tmp.path())
            .await
            .expect("mints on first boot");
        let second = ensure_appliance_control_key(tmp.path())
            .await
            .expect("adopts on the next boot");

        assert_eq!(first.did(), second.did(), "a restart must not change the identity the operator already granted");
    }

    /// A fresh gateway has no key until asked, and asking creates exactly one.
    #[tokio::test]
    async fn the_appliance_control_key_is_created_on_first_use() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = appliance_control_key_path(tmp.path());
        assert!(!path.exists(), "nothing is created before it is asked for");

        let key = ensure_appliance_control_key(tmp.path())
            .await
            .expect("mints");

        assert!(
            key.did()
                .starts_with("did:key:"),
            "the appliance identity must be a resolvable did:key, got {}",
            key.did()
        );
    }
}
