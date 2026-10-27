//! Signing an agent's Verifiable Presentation through a Verifiable Trust Agent
//! (VTA-12) — so the gateway stops holding other parties' private keys.
//!
//! The gateway's `LocalVpSigner` signs a VP *as the agent*, using an Ed25519
//! key the gateway generated for that agent and stored in its identity record.
//! That is the worst shape custody can take: the key belongs to someone else,
//! and a gateway compromise impersonates every managed agent at once.
//!
//! Here the agent's key lives in its own VTA context and the gateway asks the
//! VTA to attach the proof. What that buys is precise, and worth stating
//! plainly: it converts N stealable private keys into **one revocable
//! authority**. It does **not** make impersonation impossible — a gateway that
//! is compromised *while running* can still ask the VTA to sign, because it is
//! the party authorized to ask. The VTA's own design notes say as much: a
//! process that legitimately signs for N identities holds authority for N
//! identities. What changes is that the authority can be withdrawn, is
//! attributable, and does not survive in a stolen disk image or backup.
//!
//! **Why a context per agent.** `proofs/attach` resolves the signing key from
//! (context, `proofPurpose`) and deliberately accepts no key id — a caller that
//! could name a key could name someone else's. One context therefore signs as
//! exactly one holder, so N agents need N contexts.
//!
//! **Why `did:key` for the agent.** The agent DID is derived from the
//! VTA-held public key, so the verification method resolves to the key that
//! signed with no document to publish and — the point — **no update key**. A
//! `did:webvh` agent would need an update key per agent that can re-point its
//! own verification methods, which would put the authority to impersonate the
//! agent right back on the gateway and make the migration cosmetic.

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::identity::ssi::vp_issuer::{VpIssuer, VpIssuerPayload, build_unsigned_presentation};
use crate::vta::client::VtaRestClient;

/// `vta/proofs/attach/0.1` (VTA-29).
const TASK_PROOFS_ATTACH: &str = "https://trusttasks.org/spec/vta/proofs/attach/0.1";

/// The proof purpose a holder signs a presentation with.
///
/// Not `assertionMethod`: a presentation proof is the holder answering "I am
/// who this says I am", which is authentication. The VTA resolves a different
/// key per purpose, so naming the wrong one would either fail to resolve or
/// mint a signature whose meaning is not the one claimed.
pub const HOLDER_PROOF_PURPOSE: &str = "authentication";

#[derive(Debug, Deserialize)]
struct AttachProofResult {
    document: Value,
    #[allow(dead_code)]
    #[serde(rename = "verificationMethod")]
    verification_method: String,
}

/// Where an agent's holder key lives: which trust agent, and which context
/// inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBinding {
    /// The context whose designated `authentication` key is this agent's.
    pub context_id: String,
    /// The trust agent holding it. `None` means the bootstrap connection —
    /// either an agent onboarded before the connection was recorded, or a
    /// deployment with only one.
    pub connection_id: Option<String>,
}

/// Resolves where a given agent's key lives.
///
/// A port rather than a concrete type so the signing path can be tested
/// without a VTA, and so the mapping can later come from somewhere other than
/// on-demand provisioning.
#[async_trait]
pub trait AgentContexts: Send + Sync {
    /// Where this agent's key is, or `None` when it has no trust agent — an
    /// agent onboarded before the migration, whose key is still held locally.
    async fn binding_for(
        &self,
        agent_did: &str,
    ) -> Result<Option<AgentBinding>>;
}

/// Supplies the client for a named trust agent.
///
/// Separate from [`AgentContexts`] because knowing *where* an agent's key is
/// and being able to *reach* that trust agent are different concerns, and only
/// the second needs the connection registry.
#[async_trait]
pub trait VtaClients: Send + Sync {
    /// The client for `connection_id`, or the bootstrap one when `None`.
    async fn client_for(
        &self,
        connection_id: Option<&str>,
    ) -> Result<Arc<VtaRestClient>>;
}

/// Signs agent presentations through the agent's own VTA context.
pub struct VtaVpIssuer {
    clients: Arc<dyn VtaClients>,
    contexts: Arc<dyn AgentContexts>,
    /// Signs for agents with no VTA context.
    ///
    /// Keeping the local signer reachable is what lets the migration be
    /// gradual: an agent onboarded before the change still has a gateway-held
    /// key and must keep working. It is **not** a fallback for failure — an
    /// agent that *has* a context and whose VTA call fails is an error, never
    /// a quiet downgrade to the key we are trying to stop using.
    local: Arc<dyn VpIssuer>,
}

impl VtaVpIssuer {
    pub fn new(
        clients: Arc<dyn VtaClients>,
        contexts: Arc<dyn AgentContexts>,
        local: Arc<dyn VpIssuer>,
    ) -> Self {
        Self { clients, contexts, local }
    }
}

#[async_trait]
impl VpIssuer for VtaVpIssuer {
    async fn issue<'a>(
        &self,
        payload: VpIssuerPayload<'a>,
    ) -> Result<Value> {
        let VpIssuerPayload::Credentials(ref pc) = payload;
        let holder_did = pc
            .holder_did
            .as_ref()
            .to_string();

        let Some(binding) = self
            .contexts
            .binding_for(&holder_did)
            .await?
        else {
            // No VTA context: a pre-migration agent whose key the gateway
            // still holds. Signing locally is the only thing that works, and
            // refusing would break every agent onboarded before the change.
            return self
                .local
                .issue(payload)
                .await;
        };

        // `proofs/attach` accepts `challenge`/`domain` and then refuses them,
        // because the `eddsa-jcs-2022` proof it produces carries no member to
        // bind them to. Refuse here too, with the reason: returning a proof
        // the caller believes is replay-bound and is not would be worse than
        // failing. No production call site sets either today.
        if pc.challenge.is_some() || pc.domain.is_some() {
            bail!(
                "a VTA-signed presentation cannot be bound to a challenge or domain: the \
                 eddsa-jcs-2022 proof carries no member to bind them to, so the presentation \
                 would not be replay-protected"
            );
        }

        let presentation = build_unsigned_presentation(
            &holder_did,
            pc.verifiable_credentials
                .as_ref(),
        );

        let response = self
            .clients
            // Resolve the agent's own trust agent — what lets two agents hold
            // their keys in different ones.
            .client_for(
                binding
                    .connection_id
                    .as_deref(),
            )
            .await?
            .dispatch_signed::<Value>(
                TASK_PROOFS_ATTACH,
                json!({
                    "contextId": binding.context_id,
                    "document": presentation,
                    "proofPurpose": HOLDER_PROOF_PURPOSE,
                }),
            )
            .await
            .map_err(|e| anyhow!("attaching a holder proof through the VTA: {e}"))?;

        let payload = response
            .get("payload")
            .cloned()
            .unwrap_or(response);
        let result: AttachProofResult =
            serde_json::from_value(payload).map_err(|e| anyhow!("the VTA's proof response was not understood: {e}"))?;

        Ok(result.document)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ssi::vp_issuer::Credentials;
    use std::borrow::Cow;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NoContexts;

    #[async_trait]
    impl AgentContexts for NoContexts {
        async fn binding_for(
            &self,
            _agent_did: &str,
        ) -> Result<Option<AgentBinding>> {
            Ok(None)
        }
    }

    struct FixedContext(&'static str);

    #[async_trait]
    impl AgentContexts for FixedContext {
        async fn binding_for(
            &self,
            _agent_did: &str,
        ) -> Result<Option<AgentBinding>> {
            Ok(Some(AgentBinding {
                context_id: self.0.to_string(),
                connection_id: None,
            }))
        }
    }

    #[derive(Default)]
    struct CountingLocal(AtomicUsize);

    #[async_trait]
    impl VpIssuer for CountingLocal {
        async fn issue<'a>(
            &self,
            _payload: VpIssuerPayload<'a>,
        ) -> Result<Value> {
            self.0
                .fetch_add(1, Ordering::SeqCst);
            Ok(json!({ "signed": "locally" }))
        }
    }

    fn credentials(challenge: Option<&'static str>) -> VpIssuerPayload<'static> {
        VpIssuerPayload::Credentials(Credentials {
            holder_key: None,
            holder_did: Cow::Borrowed("did:key:zAgent"),
            verifiable_credentials: Cow::Owned(vec![json!({ "type": "VerifiableCredential" })]),
            challenge: challenge.map(Cow::Borrowed),
            domain: None,
        })
    }

    fn clients() -> Arc<dyn VtaClients> {
        Arc::new(crate::vta::agent_contexts::RegistryVtaClients::new(client(), None))
    }

    fn client() -> Arc<VtaRestClient> {
        use crate::vta::control_key::ControlKey;
        use std::time::Duration;
        Arc::new(
            VtaRestClient::new(
                "http://127.0.0.1:1",
                "did:webvh:vta.example",
                Arc::new(ControlKey::from_seed([7u8; 32])),
                Duration::from_millis(50),
                1,
                None,
            )
            .expect("build client"),
        )
    }

    /// An agent onboarded before the migration keeps working: it has no VTA
    /// context, so the local signer handles it rather than the call failing.
    #[tokio::test]
    async fn an_agent_with_no_context_is_signed_locally() {
        let local = Arc::new(CountingLocal::default());
        let issuer = VtaVpIssuer::new(clients(), Arc::new(NoContexts), Arc::clone(&local) as Arc<dyn VpIssuer>);

        let vp = issuer
            .issue(credentials(None))
            .await
            .expect("a pre-migration agent must still be able to present");
        assert_eq!(vp, json!({ "signed": "locally" }));
        assert_eq!(local.0.load(Ordering::SeqCst), 1);
    }

    /// A challenge is refused rather than dropped: a presentation the caller
    /// believes is replay-bound, and is not, is worse than no presentation.
    #[tokio::test]
    async fn a_challenge_is_refused_rather_than_silently_dropped() {
        let local = Arc::new(CountingLocal::default());
        let issuer =
            VtaVpIssuer::new(clients(), Arc::new(FixedContext("gw/agent-1")), Arc::clone(&local) as Arc<dyn VpIssuer>);

        let err = match issuer
            .issue(credentials(Some("nonce-1")))
            .await
        {
            Ok(vp) => panic!("a challenge must not be silently dropped, got {vp}"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("replay"), "{err}");
        assert_eq!(local.0.load(Ordering::SeqCst), 0, "it must not quietly fall back to the local key either");
    }

    /// The agent that *has* a context never falls back to a local key when the
    /// VTA is unreachable — that would sign with the very key the migration
    /// exists to stop using.
    #[tokio::test]
    async fn a_vta_failure_is_an_error_and_never_a_local_downgrade() {
        let local = Arc::new(CountingLocal::default());
        let issuer =
            VtaVpIssuer::new(clients(), Arc::new(FixedContext("gw/agent-1")), Arc::clone(&local) as Arc<dyn VpIssuer>);

        let outcome = issuer
            .issue(credentials(None))
            .await;
        assert!(outcome.is_err(), "an unreachable VTA must surface, not downgrade");
        assert_eq!(local.0.load(Ordering::SeqCst), 0, "falling back here would re-introduce the custody this removes");
    }

    /// An agent bound to a named trust agent is routed to **that** one, not to
    /// the bootstrap client.
    ///
    /// This is the property that lets two agents hold their keys in different
    /// trust agents — one hosted, one self-hosted. It fails loudly rather than
    /// silently signing in the wrong place, which would produce a proof that
    /// verifies against a key the agent's DID does not name.
    #[tokio::test]
    async fn an_agent_bound_to_a_named_trust_agent_is_not_sent_to_the_bootstrap_one() {
        struct NamedContext;

        #[async_trait]
        impl AgentContexts for NamedContext {
            async fn binding_for(
                &self,
                _agent_did: &str,
            ) -> Result<Option<AgentBinding>> {
                Ok(Some(AgentBinding {
                    context_id: "pi/agent-1".to_string(),
                    connection_id: Some("raspberry-pi".to_string()),
                }))
            }
        }

        let local = Arc::new(CountingLocal::default());
        // No registry wired, so a named connection cannot be resolved.
        let issuer = VtaVpIssuer::new(clients(), Arc::new(NamedContext), Arc::clone(&local) as Arc<dyn VpIssuer>);

        let err = match issuer
            .issue(credentials(None))
            .await
        {
            Ok(vp) => panic!("a named trust agent must not resolve to the bootstrap client, got {vp}"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("raspberry-pi"), "the error must name the trust agent that could not be reached: {err}");
        assert_eq!(local.0.load(Ordering::SeqCst), 0, "and it must not quietly sign locally either");
    }
}
