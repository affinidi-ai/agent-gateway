//! Creating VTA contexts from the gateway, using the narrow `context-create`
//! capability rather than super-admin.
//!
//! The gateway provisions a context per surface (and per variant), so one
//! surface's key cannot sign for another. Creating a context used to require
//! `Role::Admin` of the parent — which the gateway deliberately cannot hold:
//! its own `assert_scoped` refuses an admin grant, because the point of a
//! least-privilege grant on an internet-facing process is that a compromise
//! cannot reconfigure anything.
//!
//! `Capability::ContextCreate` (VTA-16) is the narrow alternative. It is bounded
//! by rules the VTA already enforced:
//!
//! - **top-level** creation still requires super-admin, so this can only branch;
//! - the caller must **reach the parent**, so it can only branch under its own
//!   context.
//!
//! The power is therefore "a subtree under the context I was granted", which is
//! what makes it safe to hand to a request-serving process — and is why no
//! separate super-admin-holding service is needed to provision.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::vta::VtaError;
use crate::vta::client::VtaRestClient;
use crate::vta::context_identity::{list_context_keys, payload_of};
use crate::vta::key_directory::ContextId;
use crate::vta::provisioning::ContextCreator;

/// `vta/contexts/create/1.0`.
const TASK_CONTEXTS_CREATE: &str = "https://trusttasks.org/spec/vta/contexts/create/1.0";

/// `vta/contexts/get/1.0`.
const TASK_CONTEXTS_GET: &str = "https://trusttasks.org/spec/vta/contexts/get/1.0";

/// `vta/contexts/update-did/1.1`.
///
/// Not `contexts/update/1.0`: that one edits the whole record and is
/// super-admin, which the gateway deliberately is not.
const TASK_CONTEXTS_UPDATE_DID: &str = "https://trusttasks.org/spec/vta/contexts/update-did/1.1";

/// `keys/create/0.1`.
const TASK_KEYS_CREATE: &str = "https://trusttasks.org/spec/keys/create/0.1";

/// Suffix on the issuer key minted for a context.
///
/// Derived from the leaf id rather than random, so a retry after a timeout
/// adopts the key the first attempt minted instead of leaving an orphan behind
/// and minting another. The leaf is already a digest, so the id is unique
/// across contexts without further qualification.
const ISSUER_KEY_SUFFIX: &str = "-issuer";

/// Prefix on every generated leaf id, so a context this gateway created is
/// recognisable in the VTA without consulting the gateway.
const LEAF_PREFIX: &str = "sfc-";

/// Hex characters of the digest kept in a leaf id. 20 hex characters is 80
/// bits — far beyond collision range for the number of contexts one gateway
/// can hold (`[vta] max_contexts`), and short enough to read.
const LEAF_DIGEST_LEN: usize = 20;

/// The context id from a `contexts/create` response.
///
/// Read explicitly from `payload` rather than deserialized straight into
/// a typed `{ id }` struct: the client's response parser tries the **flat**
/// shape first, and a Trust Task envelope also carries a top-level `id` (the
/// envelope's own uuid). A `{ id }` type therefore binds to the envelope and
/// silently yields a context id that is not one — which is exactly what the
/// live test caught.
fn context_id_from_response(response: &serde_json::Value) -> Option<String> {
    response
        .get("payload")
        .and_then(|p| p.get("id"))
        .or_else(|| response.get("id"))
        .and_then(|id| id.as_str())
        .filter(|id| !id.starts_with("urn:uuid:"))
        .map(str::to_string)
}

/// Creates sub-contexts under the gateway's own context.
pub struct GatewayContextCreator {
    client: Arc<VtaRestClient>,
    /// The context the gateway was granted. Every context it creates is a child
    /// of this one — which is also the only place the capability lets it create.
    parent_context_id: String,
}

impl GatewayContextCreator {
    pub fn new(
        client: Arc<VtaRestClient>,
        parent_context_id: String,
    ) -> Self {
        Self { client, parent_context_id }
    }

    /// The context itself, created or adopted.
    async fn ensure_context(
        &self,
        leaf: &str,
        name: &str,
        full_id: &str,
    ) -> Result<String, VtaError> {
        let request = json!({
            "id": leaf,
            "name": name,
            "parent": self.parent_context_id,
        });

        match self
            .client
            // Signed, not bearer: `contexts/create` is a mutating management task
            // and the VTA answers `proofRequired` without a request proof. The
            // bearer token says who holds a session; the proof says this exact
            // request was authorised by the key behind it.
            .dispatch_signed::<serde_json::Value>(TASK_CONTEXTS_CREATE, request)
            .await
        {
            Ok(response) => Ok(context_id_from_response(&response).unwrap_or_else(|| full_id.to_string())),
            // Idempotency. The provisioner calls this once per name within a
            // process, but its map does not survive a restart, and a retry
            // after a timeout may find the first attempt succeeded. The
            // context already existing *under the parent this gateway owns* is
            // the state the caller asked for, so it is a success, not a race
            // to report.
            Err(e) if already_exists(&e) => Ok(full_id.to_string()),
            Err(e) => Err(e),
        }
    }

    /// Give the context an identity it can sign with.
    ///
    /// A context with no DID exists but cannot sign as anything: a credential
    /// issued as it has no `issuer`, and a proof has no verification method. So
    /// "created" has to mean "usable", or the first signature fails at a point
    /// where the cause is far away from the cure.
    ///
    /// The identity is a key minted in the context and the `did:key` of that
    /// key. The DID is a consequence of the key, so the verification method a
    /// verifier resolves is the key that signs, with nothing to publish and no
    /// designation to keep in step with it.
    ///
    /// Conditional on the current record, which is what makes a retry safe. It
    /// also has to be: the provisioning path is **write-once**, so re-sending a
    /// DID the context already has is refused by design.
    async fn ensure_signing_identity(
        &self,
        context_id: &str,
        leaf: &str,
    ) -> Result<(), VtaError> {
        let record = self
            .get_context(context_id)
            .await?;
        if record
            .get("did")
            .and_then(|d| d.as_str())
            .is_some()
        {
            return Ok(());
        }

        let key_id = format!("{leaf}{ISSUER_KEY_SUFFIX}");
        let public_key = self
            .ensure_issuer_key(context_id, &key_id)
            .await?;
        self.configure(TASK_CONTEXTS_UPDATE_DID, json!({ "id": context_id, "did": format!("did:key:{public_key}") }))
            .await
    }

    /// A configuration step that tolerates having already been taken.
    ///
    /// Two gateway processes provisioning the same surface race here. The loser
    /// is refused because the field is already set — but the context is exactly
    /// as usable as if it had won, and its DID and key still agree with each
    /// other, so failing the caller would report a problem that does not exist.
    /// Anything else surfaces.
    async fn configure(
        &self,
        task: &str,
        request: serde_json::Value,
    ) -> Result<(), VtaError> {
        match self
            .client
            .dispatch_signed::<serde_json::Value>(task, request)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if already_configured(&e) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The context record, as raw JSON.
    pub(crate) async fn get_context(
        &self,
        context_id: &str,
    ) -> Result<serde_json::Value, VtaError> {
        let response = self
            .client
            .dispatch_signed::<serde_json::Value>(TASK_CONTEXTS_GET, json!({ "id": context_id }))
            .await?;
        Ok(payload_of(&response).clone())
    }

    /// The public key of the context's issuer key, minting it if it is not
    /// already there.
    ///
    /// The key is **internal**: its private half is never released, so the only
    /// thing a gateway compromise can do with it is ask the VTA to sign — which
    /// the VTA can refuse and revoke. That is the whole point of moving signing
    /// here, so it is not an option the caller gets to set.
    async fn ensure_issuer_key(
        &self,
        context_id: &str,
        key_id: &str,
    ) -> Result<String, VtaError> {
        let minted = self
            .client
            .dispatch_signed::<serde_json::Value>(
                TASK_KEYS_CREATE,
                json!({
                    "keyType": "ed25519",
                    "keyId": key_id,
                    "label": "gateway issuer",
                    "contextId": context_id,
                    "internal": true,
                }),
            )
            .await;

        let record = match minted {
            Ok(response) => public_key_of(payload_of(&response)),
            // A retry after a timeout finds the key already minted. Adopt it
            // rather than mint a second one the context will never use.
            Err(e) if already_exists(&e) => {
                let listed = list_context_keys(&self.client, context_id, None)
                    .await
                    .map_err(|e| VtaError::Protocol(e.to_string()))?;
                public_key_in_list(&listed, key_id)
            }
            Err(e) => return Err(e),
        };

        record.ok_or_else(|| VtaError::Protocol(format!("the issuer key `{key_id}` came back with no public key")))
    }
}

/// The `publicKey` of a key record, wherever the response put it.
fn public_key_of(payload: &serde_json::Value) -> Option<String> {
    let record = payload
        .get("key")
        .unwrap_or(payload);
    record
        .get("publicKey")
        .or_else(|| record.get("public_key"))
        .and_then(|k| k.as_str())
        .map(str::to_string)
}

/// The `publicKey` of one named key among a context's key records.
fn public_key_in_list(
    keys: &[serde_json::Value],
    key_id: &str,
) -> Option<String> {
    keys.iter()
        .find(|k| {
            k.get("keyId")
                .or_else(|| k.get("key_id"))
                .and_then(|id| id.as_str())
                == Some(key_id)
        })
        .and_then(public_key_of)
}

/// The leaf id for a derived context name.
///
/// Derived names (`ctx:_global/<uuid>`) carry `:` and `/`, which a context id
/// may not: the VTA requires lowercase alphanumerics and hyphens, 64 characters
/// or fewer. Rather than sanitise — which maps distinct names onto the same id
/// (`_global` and `global` both become `global`) and silently shares one
/// context between two surfaces — the id is a digest of the whole name, so
/// distinct names stay distinct.
///
/// Readability is not lost: the full derived name travels as the context's
/// `name`, which is free text, so an operator reading the VTA sees it.
fn leaf_id(derived_name: &str) -> String {
    let digest = Sha256::digest(derived_name.as_bytes());
    let hex: String = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{LEAF_PREFIX}{}", &hex[..LEAF_DIGEST_LEN])
}

#[async_trait]
impl ContextCreator for GatewayContextCreator {
    async fn create_context(
        &self,
        name: &str,
    ) -> Result<ContextId, VtaError> {
        let leaf = leaf_id(name);
        let full_id = format!("{}/{leaf}", self.parent_context_id);

        let context_id = self
            .ensure_context(&leaf, name, &full_id)
            .await?;
        self.ensure_signing_identity(&context_id, &leaf)
            .await?;
        Ok(ContextId::from(context_id.as_str()))
    }
}

impl GatewayContextCreator {
    /// Give an **existing** context an identity so it can issue.
    ///
    /// A context created by hand (`vta context create`) has no DID, so a
    /// credential issued as it has no `issuer`. That is a perfectly good
    /// context for signing *with a named key* — which is what STS tokens do —
    /// so the operator has no reason to expect it to need anything more until
    /// issuance fails.
    ///
    /// The agent allows this: a caller holding `context-create` may set a DID
    /// **while it is unset**, which is exactly the state a hand-made context
    /// is in. An already-identified context short-circuits, so calling this is
    /// cheap and safe to repeat.
    ///
    /// The key is named after the context's own leaf, matching what a
    /// gateway-provisioned context gets.
    pub async fn ensure_can_issue(
        &self,
        context_id: &str,
    ) -> Result<(), VtaError> {
        let leaf = context_id
            .rsplit('/')
            .next()
            .unwrap_or(context_id)
            .to_string();
        self.ensure_signing_identity(context_id, &leaf)
            .await
    }
}

/// Give `context_id` an identity so it can issue, best effort.
///
/// Shared by every path that builds a context-scoped credential issuer, so the
/// appliance default and a per-surface mapping bootstrap a context identically
/// — a surface that resolved its own agent used to skip this and hit the
/// agent's "has no DID, so it cannot sign as itself" refusal on first issuance.
///
/// Best effort by design: a failure is logged and issuance is still attempted,
/// because the context may already be fine in a way this cannot see (an
/// administrator configured it), and the agent's own refusal is a better error
/// than one invented here.
///
/// Returns whether the context is now known to be issuable, which callers use
/// to avoid repeating the round trip on every request.
pub(crate) async fn ensure_context_can_issue(
    client: &Arc<VtaRestClient>,
    context_id: &str,
) -> bool {
    let creator = GatewayContextCreator::new(Arc::clone(client), context_id.to_string());
    match creator
        .ensure_can_issue(context_id)
        .await
    {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                target: "vta_audit",
                context_id = %context_id,
                error = %e.log_detail(),
                "could not give the context a signing identity; issuing anyway",
            );
            false
        }
    }
}

/// Whether a create failed because the context is already there.
///
/// Reads `log_detail`, not `Display`: `VtaError`'s `Display` is deliberately
/// redacted ("VTA response was not understood"), so matching on it would never
/// fire and idempotency would silently not work.
///
/// Matched on the message because the Trust Task surface reports a conflict in
/// text rather than as a typed code. Deliberately narrow: anything else — a
/// refusal, an unreachable parent, a bad slug — must surface, because treating
/// those as "already fine" would hand back an id for a context that does not
/// exist and fail later at signing, where it means nothing.
fn already_exists(error: &VtaError) -> bool {
    error
        .log_detail()
        .to_ascii_lowercase()
        .contains("already exists")
}

/// Whether a configuration step failed because the field was already set.
///
/// The write-once provisioning path refuses a second write by name ("already
/// has a DID"), which is the same outcome the caller wanted. Narrow on purpose: a plain refusal — no capability, context out of
/// reach — must surface, because swallowing it would report a context as ready
/// to sign when it has no identity at all.
fn already_configured(error: &VtaError) -> bool {
    error
        .log_detail()
        .to_ascii_lowercase()
        .contains("already has a did")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leaf_id_is_a_valid_context_slug() {
        let leaf = leaf_id("ctx:_global/1a2b3c4d-0000-4000-8000-000000000001");
        assert!(leaf.len() <= 64, "{leaf}");
        assert!(
            leaf.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "a context id may only carry lowercase alphanumerics and hyphens: {leaf}"
        );
        assert!(!leaf.starts_with('-') && !leaf.ends_with('-'), "{leaf}");
    }

    #[test]
    fn the_same_name_always_derives_the_same_leaf() {
        let name = "ctx:acme/1a2b3c4d-0000-4000-8000-000000000001";
        assert_eq!(leaf_id(name), leaf_id(name));
    }

    /// The reason the id is a digest rather than a sanitised name: sanitising
    /// collapses distinct names onto one id, which would silently share a
    /// signing context between two surfaces.
    #[test]
    fn names_that_sanitise_alike_still_derive_different_leaves() {
        assert_ne!(leaf_id("ctx:_global/surface"), leaf_id("ctx:global/surface"));
        assert_ne!(leaf_id("ctx:a/b-c"), leaf_id("ctx:a-b/c"));
    }

    /// A variant's context must not collide with its surface's.
    #[test]
    fn a_variant_derives_a_different_leaf_from_its_surface() {
        let surface = "ctx:_global/1a2b3c4d-0000-4000-8000-000000000001";
        let variant = format!("{surface}/9f8e7d6c-0000-4000-8000-000000000002");
        assert_ne!(leaf_id(surface), leaf_id(&variant));
    }

    #[test]
    fn a_conflict_is_recognised_and_other_failures_are_not() {
        assert!(already_exists(&VtaError::Protocol("context already exists: gw/sfc-abc".to_string())));
        assert!(!already_exists(&VtaError::Protocol("parent context not found".to_string())));
        assert!(!already_exists(&VtaError::Config(
            "denied: caller does not carry the context-create capability".to_string()
        )));
    }

    /// The write-once refusals a concurrent provisioner produces are the state
    /// the caller wanted; a real refusal is not.
    #[test]
    fn a_write_once_refusal_is_tolerated_and_a_real_refusal_is_not() {
        assert!(already_configured(&VtaError::Protocol(
            "context `gw/sfc-abc` already has a DID; changing it is an administrator's act".to_string()
        )));
        assert!(
            !already_configured(&VtaError::Protocol("permission denied: forbidden: super admin required".to_string())),
            "a plain refusal must surface, or the context is reported ready with no identity"
        );
        assert!(
            !already_configured(&VtaError::Protocol(
                "clearing the DID on context `gw/sfc-abc` is an administrator's act".to_string()
            )),
            "the gateway never clears, so this can only mean something unexpected"
        );
    }

    /// The envelope also carries a top-level `id`, so reading through `payload`
    /// is what keeps a caller off the envelope's own uuid.
    #[test]
    fn a_payload_is_preferred_over_the_envelope_around_it() {
        let enveloped = json!({ "id": "urn:uuid:1111", "payload": { "id": "gw/sfc-abc" } });
        assert_eq!(payload_of(&enveloped)["id"], json!("gw/sfc-abc"));

        let flat = json!({ "id": "gw/sfc-abc" });
        assert_eq!(payload_of(&flat)["id"], json!("gw/sfc-abc"));
    }

    /// `keys/create` answers with the record inline, `keys/show` nests it under
    /// `key` — the public key has to be found in both, or adopting a key a
    /// retry already minted fails for a cosmetic reason.
    #[test]
    fn a_public_key_is_read_from_either_key_response_shape() {
        assert_eq!(public_key_of(&json!({ "keyId": "k", "publicKey": "z6MkAbc" })).as_deref(), Some("z6MkAbc"));
        assert_eq!(
            public_key_of(&json!({ "key": { "keyId": "k", "publicKey": "z6MkAbc" } })).as_deref(),
            Some("z6MkAbc")
        );
        assert_eq!(
            public_key_of(&json!({ "key": serde_json::Value::Null })),
            None,
            "an absent key must be absent, not an empty string that fails later"
        );
    }

    /// The issuer key id is derived, not random: a retry after a timeout must
    /// adopt the key the first attempt minted instead of orphaning it.
    #[test]
    fn the_issuer_key_id_is_derived_from_the_context() {
        let name = "ctx:_global/1a2b3c4d-0000-4000-8000-000000000001";
        let first = format!("{}{ISSUER_KEY_SUFFIX}", leaf_id(name));
        let second = format!("{}{ISSUER_KEY_SUFFIX}", leaf_id(name));
        assert_eq!(first, second);
        assert_ne!(first, format!("{}{ISSUER_KEY_SUFFIX}", leaf_id("ctx:_global/other")));
    }
}

/// Live end-to-end against a real `vta-service`: the gateway provisions its own
/// context with a *non-admin* grant, gives it a `did:key` identity from a key
/// minted inside it, issues an agent-identity credential as that context with
/// `keys/sign-document`, and verifies the proof.
///
/// Ignored by default — it needs a VTA listening locally — so it never runs in
/// the normal suite. Run it manually:
///
/// ```text
/// VTA_LIVE_URL=http://127.0.0.1:3000 \
/// VTA_LIVE_DID=did:webvh:<scid>:localhost%3A3000 \
/// VTA_LIVE_PARENT_CONTEXT=<the context the gateway was granted> \
///   cargo test --bin agent-gateway \
///     vta::context_creator::live_tests \
///     -- --ignored --nocapture --test-threads=1
/// ```
///
/// `--test-threads=1` matters: every live test authenticates as the same
/// control DID, and the VTA supersedes an earlier session when a second one is
/// opened for the same DID, so parallel tests fail with
/// `401 unauthorized: token superseded`.
#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::identity::ssi::vc_issuer::{AgentIdentity, IssueVcPayload, VcIssuer};
    use crate::vta::control_key::{ControlKey, SignerKeyProvider};
    use serde_json::Value;
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::time::Duration;

    fn live_client() -> (Arc<VtaRestClient>, String) {
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID to the VTA did:webvh");
        let parent =
            std::env::var("VTA_LIVE_PARENT_CONTEXT").expect("set VTA_LIVE_PARENT_CONTEXT to the granted context");
        let control = Arc::new(ControlKey::from_seed([42u8; 32]));
        eprintln!("GATEWAY_CONTROL_DID={}", control.did());
        let client = Arc::new(
            VtaRestClient::new(&url, &vta_did, control, Duration::from_secs(15), 8, None).expect("build client"),
        );
        (client, parent)
    }

    /// The property the whole provisioning change exists for: a gateway that
    /// is **not** an admin creates a context, and everything downstream works
    /// in it.
    #[tokio::test]
    #[ignore = "requires a running vta-service with the context-create capability granted; run manually"]
    async fn live_provision_a_context_and_issue_a_credential_in_it() {
        let (client, parent) = live_client();

        // 1. Provision. This is the step that needed super-admin — or a whole
        //    control service holding it — before the capability existed.
        let creator = GatewayContextCreator::new(Arc::clone(&client), parent.clone());
        let derived_name = format!("ctx:_global/live-{}", uuid::Uuid::new_v4());
        let context_id = creator
            .create_context(&derived_name)
            .await
            .expect("a non-admin gateway provisions its own sub-context");
        let context_id = context_id
            .as_str()
            .to_string();
        eprintln!("PROVISIONED_CONTEXT={context_id}");
        assert!(
            context_id.starts_with(&format!("{parent}/")),
            "the context must be a child of the granted one, got `{context_id}`"
        );

        // Idempotent: the provisioner's map does not survive a restart, so a
        // second call for the same name must adopt rather than fail.
        let again = creator
            .create_context(&derived_name)
            .await
            .expect("creating the same context again must be a no-op");
        assert_eq!(again.as_str(), context_id, "a repeat must adopt the same context");

        // 2. The context is already usable: `create_context` provisions its
        //    DID and issuer key, so there is nothing left to do by hand. Read
        //    them back rather than assume.
        let record = creator
            .get_context(&context_id)
            .await
            .expect("read the provisioned context back");
        let issuer_did = record["did"]
            .as_str()
            .expect("the provisioned context must carry a DID")
            .to_string();
        eprintln!("PROVISIONED_DID={issuer_did}");

        // The issuer key is **internal**, so its record is not readable and
        // its private half never leaves the VTA — which is the custody
        // property the whole migration exists for. The public half is
        // recovered from the DID, and step 4 proves it is the right one by
        // verifying a real signature against it.
        let public_key = issuer_did
            .strip_prefix("did:key:")
            .expect("the provisioned DID must be a did:key, so it resolves to the signing key")
            .to_string();

        // 3. Issue an agent-identity credential as that context.
        let issuer = crate::vta::vc_issuer::VtaVcIssuer::new(Arc::clone(&client), context_id.clone());
        let agent_did = "did:peer:live-agent";
        let mut fields = HashMap::new();
        fields.insert("region".to_string(), json!("eu"));
        let credential = issuer
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: Cow::Borrowed(agent_did),
                identity_fields: Cow::Owned(fields),
                workload_binding: None,
                display_name: None,
            }))
            .await
            .expect("issue an agent-identity credential in the provisioned context");

        assert_eq!(
            credential["issuer"], issuer_did,
            "the credential must be issued as the context's DID, not the VTA's: {credential}"
        );
        assert_eq!(credential["credentialSubject"]["id"], agent_did);
        assert_eq!(credential["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert_eq!(
            credential["@context"][1],
            json!(crate::identity::ssi::context::CTX_AGENT_IDENTITY_V1_URL),
            "the agent-identity context must travel with the credential"
        );

        // 4. Verify the proof the way the gateway's verifier does — a
        //    credential that cannot be verified is not an outcome.
        let proof: affinidi_data_integrity::DataIntegrityProof =
            serde_json::from_value(credential["proof"].clone()).expect("proof deserialises");
        let mut unsigned = credential.clone();
        unsigned
            .as_object_mut()
            .expect("credential is an object")
            .remove("proof");
        let (_base, public_bytes) = multibase::decode(&public_key).expect("multibase public key");
        proof
            .verify_with_public_key(&unsigned, &public_bytes[2..], affinidi_data_integrity::VerifyOptions::default())
            .expect("the credential must verify against the context's issuer key");

        eprintln!("LIVE_OK context={context_id} issuer={issuer_did}");
    }

    /// An agent's **holder** key lives in its own VTA context, so the gateway
    /// never holds it. Provisioning works and is idempotent, the agent's DID is
    /// the `did:key` of the key the trust agent minted, and the agent's
    /// presentation is signed by that key — bound to a challenge and a domain —
    /// without the gateway ever having the private half.
    #[tokio::test]
    #[ignore = "requires a running vta-service with the context-create capability granted; run manually"]
    async fn live_an_agent_is_provisioned_and_presents_with_a_key_the_gateway_never_held() {
        use crate::identity::ssi::vp_issuer::{Credentials, VpIssuer, VpIssuerPayload};
        use crate::vta::agent_contexts::{AgentKeyProvisioner, VtaAgentProvisioner};
        use crate::vta::vp_issuer::{AgentBinding, AgentContexts, VtaVpIssuer};

        let (client, parent) = live_client();

        let provisioner = VtaAgentProvisioner::new(
            GatewayContextCreator::new(Arc::clone(&client), parent.clone()),
            crate::vta::connections::BOOTSTRAP_CONNECTION_ID.to_string(),
        );
        let identity_hash = format!("live-{}", uuid::Uuid::new_v4().simple());
        let agent = provisioner
            .provision(&identity_hash)
            .await
            .expect("provision an agent identity with no gateway-held key");
        eprintln!("LIVE_AGENT did={} context={}", agent.did, agent.context_id);
        assert!(
            agent
                .did
                .starts_with("did:key:"),
            "an agent DID must resolve to the VTA-held key with no update key to steal, got `{}`",
            agent.did
        );
        assert!(provisioner.available(), "a trust agent as the provisioner must be used: new agents belong in it");

        let again = provisioner
            .provision(&identity_hash)
            .await
            .expect("re-provisioning the same agent must be a no-op");
        assert_eq!(again, agent, "a retry must not mint a second identity");

        struct Fixed(String);
        #[async_trait]
        impl AgentContexts for Fixed {
            async fn binding_for(
                &self,
                _agent_did: &str,
            ) -> anyhow::Result<Option<AgentBinding>> {
                Ok(Some(AgentBinding {
                    context_id: self.0.clone(),
                    connection_id: None,
                }))
            }
        }
        struct Unreachable;
        #[async_trait]
        impl VpIssuer for Unreachable {
            async fn issue<'a>(
                &self,
                _payload: VpIssuerPayload<'a>,
            ) -> anyhow::Result<Value> {
                panic!("the local signer must not be reached: it would use a key the gateway should not have")
            }
        }
        let issuer = VtaVpIssuer::new(
            Arc::new(crate::vta::agent_contexts::RegistryVtaClients::new(Arc::clone(&client), None)),
            Arc::new(Fixed(agent.context_id.clone())),
            Arc::new(Unreachable),
        );
        let vp = issuer
            .issue(VpIssuerPayload::Credentials(Credentials {
                holder_key: None,
                holder_did: std::borrow::Cow::Borrowed(&agent.did),
                verifiable_credentials: std::borrow::Cow::Owned(vec![json!({
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "type": ["VerifiableCredential"],
                    "issuer": "did:example:issuer",
                    "credentialSubject": { "id": agent.did },
                })]),
                challenge: Some(std::borrow::Cow::Borrowed("live-nonce")),
                domain: Some(std::borrow::Cow::Borrowed("verifier.example")),
            }))
            .await
            .expect("the agent's own trust agent signs its presentation");

        assert_eq!(vp["holder"], json!(agent.did));
        assert_eq!(vp["controller"], json!(agent.did), "the trust agent reads its signer from here");
        assert_eq!(vp["proof"]["proofPurpose"], json!("authentication"));
        assert_eq!(vp["proof"]["cryptosuite"], json!("eddsa-jcs-2022"));
        assert_eq!(vp["proof"]["challenge"], json!("live-nonce"));
        assert_eq!(vp["proof"]["domain"], json!("verifier.example"));

        // Verified by the gateway's own verifier — the consumer that matters —
        // because it reconstructs the challenge and domain the proof is bound to.
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .expect("resolver");
        let mut unsigned = vp.clone();
        unsigned
            .as_object_mut()
            .expect("vp is an object")
            .remove("proof");
        crate::identity::ssi::di_jcs::verify_jcs_proof(
            &unsigned,
            &vp["proof"],
            Arc::clone(crate::gateways::did_cache::shared_resolver()),
        )
        .await
        .expect("the presentation must verify, bound to its challenge and domain");

        eprintln!("LIVE_HOLDER_OK agent={}", agent.did);
    }

    /// A credential naming the **trust agent's own DID** as its issuer cannot be
    /// obtained through a context key. `keys/sign-document` signs only as the
    /// DID a document names and only with a key that DID's document lists, and
    /// the context's key is not the trust agent's — so the gateway cannot mint
    /// a credential that claims to come from the trust agent itself.
    #[tokio::test]
    #[ignore = "requires a running vta-service with the context-create capability granted; run manually"]
    async fn live_a_context_key_cannot_sign_as_the_trust_agents_own_did() {
        use crate::vta::context_identity::ContextIdentityResolver;

        let (client, parent) = live_client();
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID");
        let creator = GatewayContextCreator::new(Arc::clone(&client), parent);
        let context_id = creator
            .create_context(&format!("ctx:_global/forge-{}", uuid::Uuid::new_v4()))
            .await
            .expect("provision a context")
            .as_str()
            .to_string();
        let identity = ContextIdentityResolver::new(Arc::clone(&client), context_id)
            .identity()
            .await
            .expect("identity");

        let outcome: Result<Value, VtaError> = client
            .dispatch_signed(
                "https://trusttasks.org/spec/keys/sign-document/0.1",
                json!({
                    "keyId": identity.key_id,
                    "document": {
                        "@context": ["https://www.w3.org/ns/credentials/v2"],
                        "type": ["VerifiableCredential"],
                        "issuer": vta_did,
                        "credentialSubject": { "id": "did:key:zVictim" },
                    },
                    "proofPurpose": "assertionMethod",
                }),
            )
            .await;

        let err = match outcome {
            Ok(signed) => panic!("a context key must not sign as the trust agent's own DID, got {signed}"),
            Err(e) => e,
        };
        let detail = err.log_detail();
        assert!(
            !detail.contains("proofRequired"),
            "refused for the wrong reason (the request was not signed): {detail}"
        );
        eprintln!("LIVE_FORGERY_REFUSED detail={detail}");
    }

    /// A document that already carries a proof is refused rather than silently
    /// re-proofed: dropping the old proof would hand back a document with only
    /// ours and no indication the caller's was discarded.
    #[tokio::test]
    #[ignore = "requires a running vta-service with the context-create capability granted; run manually"]
    async fn live_a_document_that_already_carries_a_proof_is_refused() {
        use crate::vta::context_identity::{ContextIdentityResolver, PURPOSE_ASSERTION_METHOD};

        let (client, parent) = live_client();
        let creator = GatewayContextCreator::new(Arc::clone(&client), parent);
        let context_id = creator
            .create_context(&format!("ctx:_global/proofed-{}", uuid::Uuid::new_v4()))
            .await
            .expect("provision a context")
            .as_str()
            .to_string();
        let resolver = ContextIdentityResolver::new(Arc::clone(&client), context_id);
        let identity = resolver
            .identity()
            .await
            .expect("identity");

        let outcome = resolver
            .sign_document(
                json!({
                    "@context": ["https://www.w3.org/ns/credentials/v2"],
                    "type": ["VerifiableCredential"],
                    "issuer": identity.did,
                    "credentialSubject": { "id": "did:key:zAgent" },
                    "proof": { "type": "DataIntegrityProof", "proofValue": "zAlreadyThere" },
                }),
                PURPOSE_ASSERTION_METHOD,
                None,
                None,
            )
            .await;

        assert!(outcome.is_err(), "an existing proof must be refused, not replaced");
    }

    /// The provisioning grant lets a gateway name a context's DID **once**, and
    /// only a DID the context itself controls. A DID of any other method, or a
    /// `did:key` nothing in the context holds, is an administrator's decision.
    ///
    /// Needs a caller that is **not** an administrator — an administrator keeps
    /// the ordinary gate, which is exactly what this rule is not about — so it
    /// authenticates as its own control key (seed `[43; 32]`, printed as
    /// `GATEWAY_PROVISIONER_DID`) holding only the provisioning grant:
    ///
    /// ```text
    /// vta acl create --did <GATEWAY_PROVISIONER_DID> --role initiator \
    ///   --contexts <parent> --capabilities context-create,key-mint,sign-jws,sign-document
    /// ```
    #[tokio::test]
    #[ignore = "requires a running vta-service and a provisioning-only grant for the printed DID; run manually"]
    async fn live_the_gateway_may_name_only_a_did_its_context_controls() {
        let (_admin_client, parent) = live_client();
        let url = std::env::var("VTA_LIVE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let vta_did = std::env::var("VTA_LIVE_DID").expect("set VTA_LIVE_DID");
        let provisioner = Arc::new(ControlKey::from_seed([43u8; 32]));
        eprintln!("GATEWAY_PROVISIONER_DID={}", provisioner.did());
        let client = Arc::new(
            VtaRestClient::new(&url, &vta_did, provisioner, Duration::from_secs(15), 8, None).expect("build client"),
        );
        let creator = GatewayContextCreator::new(Arc::clone(&client), parent.clone());
        let leaf = format!("bare-{}", uuid::Uuid::new_v4().simple());
        let context_id = creator
            .ensure_context(&leaf, "a context with no identity", &format!("{parent}/{leaf}"))
            .await
            .expect("create a bare context");

        for did in ["did:web:example.com", "did:key:z6MkNobodyInThisContextHoldsThis"] {
            let outcome: Result<Value, VtaError> = client
                .dispatch_signed(TASK_CONTEXTS_UPDATE_DID, json!({ "id": context_id, "did": did }))
                .await;
            assert!(outcome.is_err(), "`{did}` is not a DID this context controls, so naming it must be refused");
        }
        let record = creator
            .get_context(&context_id)
            .await
            .expect("read it back");
        assert!(record.get("did").is_none(), "a refused write left a DID behind: {record}");

        creator
            .ensure_signing_identity(&context_id, &leaf)
            .await
            .expect("naming the did:key of a key the context holds is what provisioning does");
        let record = creator
            .get_context(&context_id)
            .await
            .expect("read it back");
        assert!(
            record["did"]
                .as_str()
                .is_some_and(|d| d.starts_with("did:key:")),
            "{record}"
        );
    }

    /// The property that makes the fabric issuer attestation migratable: an
    /// attestation signed **as the context** verifies against that context's
    /// own DID document.
    ///
    /// This is the check that caught a wrong design. Routing the attestation
    /// through the ordinary signing authority would claim the trust agent's
    /// DID while signing with a key held in the gateway's context — and
    /// `check_signature` resolves the claimed DID and demands the key be
    /// declared *there*, so every peer would have rejected it. Signing as the
    /// context makes the claimed DID and the signing key the same party.
    #[tokio::test]
    #[ignore = "requires a running vta-service with the context-create capability granted; run manually"]
    async fn live_an_attestation_signed_as_the_context_verifies_at_a_peer() {
        use crate::gateways::issuer_attestation::{
            ExpectedAttestation, ISSUER_ATTESTATION_TYP, IssuerAttestationClaims,
            verify_issuer_attestation_with_document,
        };
        use crate::vta::context_signer::{ContextSigner, VtaContextSigner};

        let (client, parent) = live_client();

        // A provisioned context: a DID and the key behind it, exactly what the
        // gateway's own context looks like after onboarding.
        let creator = GatewayContextCreator::new(Arc::clone(&client), parent.clone());
        let name = format!("ctx:_global/attest-{}", uuid::Uuid::new_v4());
        let context_id = creator
            .create_context(&name)
            .await
            .expect("provision the signing context");
        let context_id = context_id
            .as_str()
            .to_string();

        let signer = VtaContextSigner::new(Arc::clone(&client), context_id.clone());
        let issuer_did = signer
            .issuer_did()
            .await
            .expect("the context reports the DID it signs as");
        assert!(issuer_did.starts_with("did:key:"), "{issuer_did}");

        let connection_point_did = "did:peer:live-connection-point";
        let peer_did = "did:web:peer.example";
        let nonce = uuid::Uuid::new_v4().to_string();
        let claims = IssuerAttestationClaims::new(issuer_did.clone(), connection_point_did, peer_did, &nonce);
        let attestation = signer
            .sign_typ(&serde_json::to_value(&claims).expect("claims serialise"), ISSUER_ATTESTATION_TYP)
            .await
            .expect("sign the attestation as the context");

        // Resolve the claimed DID the way a peer would, then verify. A
        // `did:key` document declares exactly the key that signed.
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .expect("resolver");
        let resolver = crate::gateways::did_cache::shared_resolver();
        let resolved = resolver
            .resolve(&issuer_did)
            .await
            .expect("a peer must be able to resolve the DID we claim");
        let document = serde_json::to_value(&resolved.doc).expect("document serialises");

        let verified = verify_issuer_attestation_with_document(
            &attestation,
            ExpectedAttestation {
                sub: connection_point_did,
                aud: peer_did,
                nonce: &nonce,
            },
            &document,
        )
        .expect("the attestation must verify against the context's own DID document");
        assert_eq!(verified, issuer_did);

        eprintln!("LIVE_ATTESTATION_OK iss={issuer_did} context={context_id}");
    }

    /// The bound that makes the capability safe to hold: it can branch under
    /// the granted context and nowhere else.
    #[tokio::test]
    #[ignore = "requires a running vta-service with the context-create capability granted; run manually"]
    async fn live_the_gateway_cannot_create_a_top_level_context() {
        let (client, _parent) = live_client();
        let leaf = format!("rogue-{}", uuid::Uuid::new_v4().simple());

        let outcome: Result<Value, VtaError> = client
            .dispatch_signed(
                "https://trusttasks.org/spec/vta/contexts/create/1.0",
                json!({ "id": leaf, "name": "rogue" }),
            )
            .await;

        let err = match outcome {
            Ok(created) => panic!("a top-level context must still require super-admin, got: {created}"),
            Err(e) => e,
        };
        let detail = err.log_detail();
        // Assert *why* it was refused. Without this the test passes on any
        // failure at all — it did exactly that while the request was unsigned,
        // reporting `proofRequired` and proving nothing about authorization.
        assert!(
            !detail.contains("proofRequired"),
            "refused for the wrong reason (the request was not signed): {detail}"
        );
        eprintln!("LIVE_TOP_LEVEL_REFUSED detail={detail}");
    }
}
