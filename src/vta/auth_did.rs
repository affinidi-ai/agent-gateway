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

/// Directory under the issuer's storage where the log is kept.
const AUTH_DID_DIR: &str = "vta_auth";

/// Where the auth DID's log lives, given the issuer storage root.
pub fn auth_did_dir(issuer_storage: &Path) -> PathBuf {
    issuer_storage.join(AUTH_DID_DIR)
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
    let dir = auth_did_dir(issuer_storage);

    if let Some(existing) = read_existing_did(&dir).await? {
        return Ok(existing);
    }

    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| VtaError::Config(format!("[vta] create auth DID directory: {e}")))?;

    let domain_encoded = domain.replace(':', "%3A");
    let placeholder = format!("did:webvh:{{SCID}}:{domain_encoded}:{AUTH_DID_PATH_SEGMENT}");
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
        url = %format!("{}{AUTH_DID_PATH_SEGMENT}/did.jsonl", base_url),
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

        // 5. The VTA signs on behalf of that agent's key.
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
                // No key supplied, because the gateway does not have one.
                holder_key: None,
                holder_did: std::borrow::Cow::Borrowed(&agent.did),
                verifiable_credentials: std::borrow::Cow::Owned(vec![json!({
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "type": ["VerifiableCredential"],
                    "issuer": "did:example:issuer",
                    "credentialSubject": { "id": agent.did },
                })]),
                challenge: None,
                domain: None,
            }))
            .await
            .expect("the VTA signs for the agent's own key");

        assert_eq!(vp["holder"], json!(agent.did));
        assert_eq!(vp["proof"]["proofPurpose"], json!("authentication"));

        // 6. And it verifies against that agent's key — a signature nobody can
        //    check is not an outcome.
        let public_key = agent
            .did
            .strip_prefix("did:key:")
            .expect("did:key");
        let proof: affinidi_data_integrity::DataIntegrityProof =
            serde_json::from_value(vp["proof"].clone()).expect("proof deserialises");
        let mut unsigned = vp.clone();
        unsigned
            .as_object_mut()
            .expect("object")
            .remove("proof");
        let (_base, public_bytes) = multibase::decode(public_key).expect("multibase");
        proof
            .verify_with_public_key(&unsigned, &public_bytes[2..], affinidi_data_integrity::VerifyOptions::default())
            .expect("the agent's presentation must verify against the agent's own key");

        eprintln!("LIVE_CHAIN_OK auth={auth_did} agent={}", agent.did);
    }
}
