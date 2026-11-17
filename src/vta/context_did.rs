//! The DID a trust agent context the gateway creates signs as.
//!
//! By default a context signs as the `did:key` of a key it holds: nothing to
//! host, and nothing a compromise of the gateway can rewrite. With
//! `[vta] context_did_method = "did_webvh"` a context the gateway creates gets a
//! `did:webvh` instead, created **by the trust agent**: the trust agent holds its
//! signing key and its update key, and the gateway only asks for it, finds it
//! again, signs as it and, with `gateway` hosting, serves its log. The DID then
//! survives a key rotation by the trust agent's operator.
//!
//! The gateway keeps no record of which DID a context has: it asks the trust
//! agent. Creating the `did:webvh` records it as the context's DID; a context
//! whose record names none signs as its `did:webvh` only when that is the
//! **only** one it holds, so an ambiguous context refuses instead of guessing.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::vta::{ContextDidHosting, ContextDidMethod, VtaConfig};
use crate::vta::VtaError;
use crate::vta::client::VtaRestClient;
use crate::vta::context_identity::payload_of;

/// `vta/webvh/dids/create/1.2`.
const TASK_WEBVH_DIDS_CREATE: &str = "https://trusttasks.org/spec/vta/webvh/dids/create/1.2";
/// `vta/webvh/dids/list/1.0`.
const TASK_WEBVH_DIDS_LIST: &str = "https://trusttasks.org/spec/vta/webvh/dids/list/1.0";
/// `vta/webvh/dids/get/1.0`.
const TASK_WEBVH_DIDS_GET: &str = "https://trusttasks.org/spec/vta/webvh/dids/get/1.0";

/// The path segment the gateway serves context DID logs under.
pub const ISSUER_DID_PATH_SEGMENT: &str = "vta-issuer";

/// Characters of the digest kept in a hosting token.
const TOKEN_DIGEST_LEN: usize = 20;

/// Where a context's `did:webvh` log lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hosting {
    /// This gateway serves it: written under `storage`, at `domain`.
    Gateway { storage: PathBuf, domain: String },
    /// A webvh hosting server registered on the trust agent publishes it.
    VtaServer { server_id: String },
}

/// Which DID the contexts the gateway creates sign as, and where a `did:webvh`
/// is hosted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextDidPolicy {
    pub method: ContextDidMethod,
    pub hosting: Hosting,
}

impl ContextDidPolicy {
    /// The policy `[vta]` sets, hosting gateway-served logs under `storage` at
    /// `domain`. `None` when `did_webvh` with `gateway` hosting has no domain to
    /// serve at, which [`VtaConfig::validate`] cannot know about.
    pub fn from_config(
        config: &VtaConfig,
        storage: PathBuf,
        domain: Option<String>,
    ) -> Result<Self, String> {
        let hosting = match config.context_did_hosting {
            ContextDidHosting::VtaServer => Hosting::VtaServer {
                server_id: config
                    .context_did_server_id
                    .clone()
                    .unwrap_or_default(),
            },
            ContextDidHosting::Gateway => Hosting::Gateway {
                storage,
                domain: domain.unwrap_or_default(),
            },
        };
        if config.context_did_method == ContextDidMethod::DidWebvh
            && matches!(&hosting, Hosting::Gateway { domain, .. } if domain.trim().is_empty())
        {
            return Err(
                "[vta] context_did_method = \"did_webvh\" with gateway hosting needs the gateway's own DID domain, \
                 which is not configured"
                    .to_string(),
            );
        }
        Ok(Self {
            method: config.context_did_method,
            hosting,
        })
    }
}

static POLICY: OnceLock<ContextDidPolicy> = OnceLock::new();

/// Install the policy for this process. Called once at startup; a second call
/// is ignored, since the setting is read from configuration.
pub fn install(policy: ContextDidPolicy) {
    let _ = POLICY.set(policy);
}

/// The installed policy, if any. Absent means `did:key`, as before the setting.
pub fn current() -> Option<ContextDidPolicy> {
    POLICY.get().cloned()
}

/// The hosting token for a context's DID: a path segment that is stable for one
/// trust agent and context and distinct across them, carrying neither id.
pub fn hosting_token(
    vta_did: &str,
    context_id: &str,
) -> String {
    let digest = Sha256::digest(format!("{vta_did}\u{1e}{context_id}").as_bytes());
    let hex: String = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("ctx-{}", &hex[..TOKEN_DIGEST_LEN])
}

/// The hosting token of a DID this gateway serves, read from its path:
/// `did:webvh:<scid>:<domain>:vta-issuer:<token>`.
pub fn hosted_token(did: &str) -> Option<&str> {
    let token = did
        .strip_prefix("did:webvh:")?
        .rsplit_once(&format!(":{ISSUER_DID_PATH_SEGMENT}:"))?
        .1;
    is_token(token).then_some(token)
}

/// Whether `value` is a hosting token, so it is safe as a path segment.
fn is_token(value: &str) -> bool {
    value
        .strip_prefix("ctx-")
        .is_some_and(|hex| {
            hex.len() == TOKEN_DIGEST_LEN
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit())
        })
}

/// Where the log of the DID with hosting token `token` is written.
pub fn hosted_log_path(
    storage: &Path,
    token: &str,
) -> Option<PathBuf> {
    is_token(token).then(|| {
        storage
            .join(ISSUER_DID_PATH_SEGMENT)
            .join(token)
            .join("did.jsonl")
    })
}

/// The URL a DID this gateway hosts is created at: its log is served at this
/// URL plus `/did.jsonl`.
fn hosted_url(
    domain: &str,
    token: &str,
) -> String {
    format!(
        "{}/{ISSUER_DID_PATH_SEGMENT}/{token}",
        crate::identity::didwebvh::base_url_for_domain(domain).trim_end_matches('/')
    )
}

/// Write the log of a DID this gateway serves, replacing the previous one.
pub async fn publish_log(
    storage: &Path,
    token: &str,
    log: &str,
) -> std::io::Result<()> {
    let path = hosted_log_path(storage, token)
        .ok_or_else(|| std::io::Error::other(format!("`{token}` is not a hosting token")))?;
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    let staged = path.with_extension("jsonl.tmp");
    let mut body = log.trim_end().to_string();
    body.push('\n');
    tokio::fs::write(&staged, body).await?;
    tokio::fs::rename(&staged, &path).await
}

/// The `did:webvh` a context signs as: the only one the trust agent holds in
/// exactly that context. `None` when it holds none; an error when it holds
/// several, since signing as one of them would be a guess.
pub async fn context_webvh(
    client: &VtaRestClient,
    context_id: &str,
) -> Result<Option<String>, VtaError> {
    let listed = client
        .dispatch_signed::<Value>(TASK_WEBVH_DIDS_LIST, json!({ "contextId": context_id }))
        .await?;
    let dids = webvh_dids_in(payload_of(&listed), context_id);
    match dids.as_slice() {
        [] => Ok(None),
        [did] => Ok(Some(did.clone())),
        _ => Err(VtaError::Protocol(format!(
            "context `{context_id}` holds {} did:webvh DIDs, so the gateway cannot tell which one it signs as",
            dids.len()
        ))),
    }
}

/// The `did:webvh` DIDs a `webvh/dids/list` answer places in `context_id`.
fn webvh_dids_in(
    listed: &Value,
    context_id: &str,
) -> Vec<String> {
    listed
        .get("dids")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|record| {
            record
                .get("contextId")
                .and_then(Value::as_str)
                == Some(context_id)
        })
        .filter_map(|record| {
            record
                .get("did")
                .and_then(Value::as_str)
        })
        .filter(|did| did.starts_with("did:webvh:"))
        .map(str::to_string)
        .collect()
}

/// The current log of a `did:webvh` the trust agent holds.
pub async fn webvh_log(
    client: &VtaRestClient,
    did: &str,
) -> Result<String, VtaError> {
    let got = client
        .dispatch_signed::<Value>(TASK_WEBVH_DIDS_GET, json!({ "did": did, "includeLog": true }))
        .await?;
    payload_of(&got)
        .get("log")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| VtaError::Protocol(format!("the trust agent returned no log for `{did}`")))
}

/// How many entries the log of a `did:webvh` the trust agent holds has, without
/// reading it: a cheap check that its key has not been rotated since.
pub async fn webvh_log_entries(
    client: &VtaRestClient,
    did: &str,
) -> Result<u64, VtaError> {
    let got = client
        .dispatch_signed::<Value>(TASK_WEBVH_DIDS_GET, json!({ "did": did, "includeLog": false }))
        .await?;
    payload_of(&got)
        .pointer("/record/logEntryCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| VtaError::Protocol(format!("the trust agent returned no log length for `{did}`")))
}

/// Have the trust agent create the `did:webvh` of `context_id`, and publish its
/// log when this gateway hosts it. Returns the DID.
pub async fn create_context_webvh(
    client: &VtaRestClient,
    context_id: &str,
    hosting: &Hosting,
) -> Result<String, VtaError> {
    let mut request = json!({ "contextId": context_id, "label": "agent-gateway context identity" });
    let token = hosting_token(client.vta_did(), context_id);
    match hosting {
        Hosting::Gateway { domain, .. } => {
            request["url"] = json!(hosted_url(domain, &token));
        }
        Hosting::VtaServer { server_id } => {
            request["serverId"] = json!(server_id);
        }
    }
    let created = client
        .dispatch_signed::<Value>(TASK_WEBVH_DIDS_CREATE, request)
        .await?;
    let created = payload_of(&created);
    let did = created
        .get("did")
        .and_then(Value::as_str)
        .ok_or_else(|| VtaError::Protocol(format!("the did:webvh created for `{context_id}` came back with no DID")))?
        .to_string();
    if let Hosting::Gateway { storage, .. } = hosting {
        let log = match created
            .get("logEntry")
            .and_then(Value::as_str)
        {
            Some(log) => log.to_string(),
            None => webvh_log(client, &did).await?,
        };
        publish_log(storage, &token, &log)
            .await
            .map_err(|e| VtaError::Config(format!("publishing the log of `{did}`: {e}")))?;
    }
    Ok(did)
}

/// Republish the log of a DID this gateway serves, under `storage`, from what
/// the trust agent holds now, so a key the operator rotated is what verifiers
/// resolve. A DID this gateway does not serve is left alone.
pub async fn refresh_hosted_log(
    storage: &Path,
    did: &str,
    log: &str,
) {
    let Some(token) = hosted_token(did) else {
        return;
    };
    if let Err(e) = publish_log(storage, token, log).await {
        tracing::warn!(
            target: "vta_audit",
            did = %did,
            error = %e,
            "could not republish a context DID log",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hosting_token_is_stable_and_distinct_per_trust_agent_and_context() {
        let a = hosting_token("did:webvh:vta-1", "gw/agent-1");
        assert_eq!(a, hosting_token("did:webvh:vta-1", "gw/agent-1"));
        assert_ne!(a, hosting_token("did:webvh:vta-2", "gw/agent-1"));
        assert_ne!(a, hosting_token("did:webvh:vta-1", "gw/agent-2"));
        assert!(is_token(&a), "{a}");
        assert!(!a.contains('/') && !a.contains("agent"), "the token carries no id: {a}");
    }

    #[test]
    fn a_hosted_did_is_recognised_by_its_path() {
        let token = hosting_token("did:webvh:vta", "gw");
        let did = format!("did:webvh:QmScid:gw.example.com:vta-issuer:{token}");
        assert_eq!(hosted_token(&did), Some(token.as_str()));
        assert_eq!(hosted_token("did:webvh:QmScid:other.example.com:dids:abc"), None);
        assert_eq!(hosted_token("did:webvh:QmScid:gw.example.com:vta-issuer:../../etc"), None);
        assert_eq!(hosted_token("did:key:z6Mk"), None);
    }

    #[test]
    fn a_hosted_did_url_has_no_empty_path_segment() {
        let token = hosting_token("did:webvh:vta", "gw");
        assert_eq!(hosted_url("gw.example.com", &token), format!("https://gw.example.com/vta-issuer/{token}"));
        assert_eq!(hosted_url("localhost:8080", &token), format!("http://localhost:8080/vta-issuer/{token}"));
        assert!(!hosted_url("gw.example.com/", &token).contains("//vta-issuer"));
    }

    #[test]
    fn only_a_token_names_a_hosted_log() {
        let storage = Path::new("/srv/gw");
        let token = hosting_token("did:webvh:vta", "gw");
        assert_eq!(
            hosted_log_path(storage, &token),
            Some(
                storage
                    .join("vta-issuer")
                    .join(&token)
                    .join("did.jsonl")
            )
        );
        for bad in ["../x", "ctx-zz", "ctx-", "gw/agent", ""] {
            assert_eq!(hosted_log_path(storage, bad), None, "{bad}");
        }
    }

    #[test]
    fn a_context_signs_as_its_only_did_webvh() {
        let listed = json!({ "dids": [
            { "did": "did:webvh:Qm1:h:a", "contextId": "gw/a" },
            { "did": "did:webvh:Qm2:h:b", "contextId": "gw/b" },
            { "did": "did:webvh:Qm3:h:c", "contextId": "gw/a/child" },
        ]});
        assert_eq!(webvh_dids_in(&listed, "gw/a"), vec!["did:webvh:Qm1:h:a".to_string()]);
        assert!(webvh_dids_in(&listed, "gw/none").is_empty());
    }

    #[tokio::test]
    async fn a_published_log_replaces_the_previous_one() {
        let dir = tempfile::tempdir().unwrap();
        let token = hosting_token("did:webvh:vta", "gw");
        publish_log(dir.path(), &token, "{\"versionId\":\"1\"}")
            .await
            .unwrap();
        publish_log(dir.path(), &token, "{\"versionId\":\"1\"}\n{\"versionId\":\"2\"}\n")
            .await
            .unwrap();
        let written = tokio::fs::read_to_string(hosted_log_path(dir.path(), &token).unwrap())
            .await
            .unwrap();
        assert_eq!(written, "{\"versionId\":\"1\"}\n{\"versionId\":\"2\"}\n");
    }

    fn config(
        method: ContextDidMethod,
        hosting: ContextDidHosting,
        server: Option<&str>,
    ) -> VtaConfig {
        VtaConfig {
            context_did_method: method,
            context_did_hosting: hosting,
            context_did_server_id: server.map(str::to_string),
            ..VtaConfig::default()
        }
    }

    #[test]
    fn the_policy_follows_the_configuration() {
        let policy = ContextDidPolicy::from_config(
            &config(ContextDidMethod::DidWebvh, ContextDidHosting::Gateway, None),
            PathBuf::from("/srv"),
            Some("gw.example.com".into()),
        )
        .unwrap();
        assert_eq!(policy.method, ContextDidMethod::DidWebvh);
        assert_eq!(
            policy.hosting,
            Hosting::Gateway {
                storage: PathBuf::from("/srv"),
                domain: "gw.example.com".into()
            }
        );
        let server = ContextDidPolicy::from_config(
            &config(ContextDidMethod::DidWebvh, ContextDidHosting::VtaServer, Some("host-1")),
            PathBuf::from("/srv"),
            None,
        )
        .unwrap();
        assert_eq!(server.hosting, Hosting::VtaServer { server_id: "host-1".into() });
    }

    #[test]
    fn gateway_hosting_needs_a_domain_to_serve_at() {
        let err = ContextDidPolicy::from_config(
            &config(ContextDidMethod::DidWebvh, ContextDidHosting::Gateway, None),
            PathBuf::from("/srv"),
            None,
        )
        .expect_err("nowhere to serve the log");
        assert!(err.contains("domain"), "{err}");
        ContextDidPolicy::from_config(
            &config(ContextDidMethod::DidKey, ContextDidHosting::Gateway, None),
            PathBuf::from("/srv"),
            None,
        )
        .expect("did:key hosts nothing");
    }
}

/// Against a real trust agent, with only the gateway's provisioning grant
/// (`initiator` plus `context-create, key-mint, sign-jws, sign-document`):
/// `VTA_LIVE_URL`, `VTA_LIVE_DID`, `VTA_LIVE_PARENT_CONTEXT`, and, for the
/// rotation, `VTA_LIVE_OPERATOR` with an admin grant on the parent for seed 44.
#[cfg(test)]
mod live_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use affinidi_did_resolver_cache_sdk::DIDCacheClient;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy;

    use super::*;
    use crate::vta::agent_contexts::{AgentKeyProvisioner, VtaAgentProvisioner};
    use crate::vta::context_creator::GatewayContextCreator;
    use crate::vta::context_identity::ContextIdentityResolver;
    use crate::vta::control_key::ControlKey;
    use crate::vta::provisioning::ContextCreator;

    fn live_client(seed: u8) -> Arc<VtaRestClient> {
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID");
        Arc::new(
            VtaRestClient::new(
                &url,
                &vta_did,
                Arc::new(ControlKey::from_seed([seed; 32])),
                Duration::from_secs(15),
                8,
                None,
            )
            .expect("build client"),
        )
    }

    fn parent() -> String {
        std::env::var("VTA_LIVE_PARENT_CONTEXT").expect("set VTA_LIVE_PARENT_CONTEXT")
    }

    /// Serve the logs this gateway hosts, as the gateway's own route does, on a
    /// local port; returns the domain DIDs hosted there carry.
    async fn serve_hosted_logs(storage: PathBuf) -> String {
        use axum::extract::Path as UrlPath;
        let app = axum::Router::new().route(
            "/vta-issuer/{token}/did.jsonl",
            axum::routing::get(move |UrlPath(token): UrlPath<String>| {
                let storage = storage.clone();
                async move {
                    match hosted_log_path(&storage, &token) {
                        Some(path) => match tokio::fs::read_to_string(path).await {
                            Ok(log) => (axum::http::StatusCode::OK, log),
                            Err(_) => (axum::http::StatusCode::NOT_FOUND, String::new()),
                        },
                        None => (axum::http::StatusCode::NOT_FOUND, String::new()),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener
            .local_addr()
            .expect("addr")
            .port();
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("localhost:{port}")
    }

    /// A resolver as a peer gateway runs it, allowed to reach this host.
    async fn peer_resolver() -> Arc<DIDCacheClient> {
        Arc::new(
            DIDCacheClient::new(
                DIDCacheConfigBuilder::default()
                    .with_host_policy(HostPolicy::AllowPrivate)
                    .build(),
            )
            .await
            .expect("DID cache client"),
        )
    }

    /// The proof on `signed` verifies the way a peer verifies it: by resolving
    /// the signer's `did:webvh` and taking the key from its log.
    async fn a_peer_verifies(signed: &Value) {
        let mut unsigned = signed.clone();
        let proof = unsigned
            .as_object_mut()
            .expect("document")
            .remove("proof")
            .expect("a proof");
        crate::identity::ssi::di_jcs::verify_jcs_proof(&unsigned, &proof, peer_resolver().await)
            .await
            .expect("a peer verifies the proof by resolving the did:webvh");
    }

    fn credential(issuer: &str) -> Value {
        json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiableCredential"],
            "issuer": issuer,
            "credentialSubject": { "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" },
        })
    }

    async fn webvh_creator(client: Arc<VtaRestClient>) -> (GatewayContextCreator, PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = dir.path().to_path_buf();
        let domain = serve_hosted_logs(storage.clone()).await;
        let creator = GatewayContextCreator::new(client, parent()).with_did_policy(Some(ContextDidPolicy {
            method: ContextDidMethod::DidWebvh,
            hosting: Hosting::Gateway {
                storage: storage.clone(),
                domain,
            },
        }));
        (creator, storage, dir)
    }

    #[tokio::test]
    #[ignore = "requires a running vta-service and the provisioning grant; run manually"]
    async fn live_a_did_webvh_context_signs_is_verified_and_keeps_its_did_across_a_rotation() {
        let client = live_client(42);
        let (creator, storage, _dir) = webvh_creator(Arc::clone(&client)).await;
        let context_id = creator
            .create_context(&format!("ctx:_global/webvh-e2e-{}", uuid::Uuid::new_v4()))
            .await
            .expect("create a context with a did:webvh")
            .as_str()
            .to_string();

        let did = creator
            .signing_did(&context_id)
            .await
            .expect("the context signs as something");
        assert!(did.starts_with("did:webvh:"), "{did}");
        let record = creator
            .get_context(&context_id)
            .await
            .expect("the context");
        assert_eq!(record["did"], json!(did), "the trust agent records the did:webvh as the context's DID");
        let token = hosted_token(&did).expect("a DID this gateway hosts");
        assert!(
            hosted_log_path(&storage, token)
                .unwrap()
                .exists(),
            "the log is published"
        );

        let resolver = ContextIdentityResolver::new(Arc::clone(&client), context_id.clone())
            .with_hosted_logs(Some(storage.clone()));
        let identity = resolver
            .identity()
            .await
            .expect("the identity");
        assert_eq!(identity.did, did);
        assert!(
            identity
                .verification_method
                .starts_with(&format!("{did}#")),
            "{identity:?}"
        );

        let signed = resolver
            .sign_document(credential(&did), "assertionMethod", None, None)
            .await
            .expect("signed as the did:webvh");
        assert_eq!(signed["proof"]["verificationMethod"], json!(identity.verification_method));
        a_peer_verifies(&signed).await;

        let claims = crate::gateways::issuer_attestation::IssuerAttestationClaims::new(
            did.clone(),
            "did:peer:2.connection-point",
            "did:peer:2.receiver",
            "nonce-1",
        );
        let attestation = resolver
            .sign_jws(
                &serde_json::to_value(&claims).unwrap(),
                crate::gateways::issuer_attestation::ISSUER_ATTESTATION_TYP,
            )
            .await
            .expect("an attestation signed as the context");
        let document = peer_resolver()
            .await
            .resolve(&did)
            .await
            .expect("a peer resolves the attested issuer");
        let attested = crate::gateways::issuer_attestation::verify_issuer_attestation_with_document(
            &attestation,
            crate::gateways::issuer_attestation::ExpectedAttestation {
                sub: "did:peer:2.connection-point",
                aud: "did:peer:2.receiver",
                nonce: "nonce-1",
            },
            &serde_json::to_value(&document.doc).unwrap(),
        )
        .expect("a peer verifies the attestation");
        assert_eq!(attested, did);
        eprintln!("LIVE_WEBVH_SIGNED did={did} vm={}", identity.verification_method);

        if std::env::var("VTA_LIVE_OPERATOR").is_err() {
            return;
        }
        // The operator rotates the key with an administrator's grant.
        live_client(44)
            .dispatch_signed::<Value>(
                "https://trusttasks.org/spec/vta/webvh/dids/rotate-keys/1.0",
                json!({ "did": did }),
            )
            .await
            .expect("the operator rotates the did:webvh's key");

        // The same resolver, still holding the old key, signs again: the DID is
        // unchanged and the new key signs.
        let after = resolver
            .sign_document(credential(&did), "assertionMethod", None, None)
            .await
            .expect("signed after the rotation, as the same DID");
        let rotated_vm = after["proof"]["verificationMethod"]
            .as_str()
            .expect("method")
            .to_string();
        assert!(rotated_vm.starts_with(&format!("{did}#")), "{rotated_vm}");
        let republished = tokio::fs::read_to_string(hosted_log_path(&storage, token).unwrap())
            .await
            .expect("the hosted log");
        assert_eq!(republished.lines().count(), 2, "the rotation is republished");
        let key_of = |entry: &str| -> String {
            let entry: Value = serde_json::from_str(entry).expect("entry");
            entry["state"]["verificationMethod"]
                .as_array()
                .expect("methods")
                .iter()
                .find(|m| m["id"].as_str() == Some(rotated_vm.as_str()))
                .and_then(|m| m["publicKeyMultibase"].as_str())
                .expect("the signing method")
                .to_string()
        };
        let mut lines = republished.lines();
        let (before_key, after_key) = (key_of(lines.next().unwrap()), key_of(lines.next().unwrap()));
        assert_ne!(before_key, after_key, "the rotation put a new key behind the method");
        a_peer_verifies(&after).await;
        eprintln!("LIVE_WEBVH_ROTATED did={did} vm={rotated_vm} key {before_key} -> {after_key}");
    }

    #[tokio::test]
    #[ignore = "requires a running vta-service and the provisioning grant; run manually"]
    async fn live_an_agent_onboarded_under_did_webvh_presents_as_it() {
        let client = live_client(42);
        let (creator, _storage, _dir) = webvh_creator(Arc::clone(&client)).await;
        let agent = VtaAgentProvisioner::new(creator, "vta-bootstrap".to_string())
            .provision(&format!("agent-{}", uuid::Uuid::new_v4()))
            .await
            .expect("an agent onboarded in its own context");
        assert!(
            agent
                .did
                .starts_with("did:webvh:"),
            "the agent's DID is its context's did:webvh: {}",
            agent.did
        );

        let resolver = ContextIdentityResolver::new(Arc::clone(&client), agent.context_id.clone());
        let identity = resolver
            .identity()
            .await
            .expect("the agent's identity");
        assert_eq!(identity.did, agent.did);
        let mut presentation = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": agent.did,
        });
        presentation["controller"] = json!(agent.did);
        let proved = resolver
            .sign_document(presentation, "authentication", Some("challenge-1"), Some("verifier.example"))
            .await
            .expect("a holder proof as the agent's did:webvh");
        assert_eq!(proved["proof"]["verificationMethod"], json!(identity.verification_method));
        a_peer_verifies(&proved).await;
        let jwt = resolver
            .sign_jws(&json!({ "iss": agent.did, "sub": "task" }), "JWT")
            .await
            .expect("the agent's JWT");
        assert_eq!(jwt.split('.').count(), 3);
        eprintln!("LIVE_WEBVH_AGENT did={}", agent.did);
    }
}
