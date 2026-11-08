//! Signing an agent's Verifiable Presentation through a Verifiable Trust Agent
//! (VTA-12) — so the gateway stops holding other parties' private keys.
//!
//! The gateway's `LocalVpSigner` signs a VP *as the agent*, using an Ed25519
//! key the gateway generated for that agent and stored in its identity record.
//! That is the worst shape custody can take: the key belongs to someone else,
//! and a gateway compromise impersonates every managed agent at once.
//!
//! Here the agent's key lives in its own VTA context and the gateway asks the
//! VTA to attach the proof with `keys/sign-document`. What that buys is precise,
//! and worth stating plainly: it converts N stealable private keys into **one revocable
//! authority**. It does **not** make impersonation impossible — a gateway that
//! is compromised *while running* can still ask the VTA to sign, because it is
//! the party authorized to ask. The VTA's own design notes say as much: a
//! process that legitimately signs for N identities holds authority for N
//! identities. What changes is that the authority can be withdrawn, is
//! attributable, and does not survive in a stolen disk image or backup.
//!
//! **Why a context per agent.** `keys/sign-document` signs only as the DID the
//! document names, with a key that DID's own document lists for the requested
//! relationship. An agent's DID is the `did:key` of one key, so one context
//! signs as exactly one holder, and N agents need N contexts.
//!
//! **Why `did:key` for the agent.** The agent DID is derived from the
//! VTA-held public key, so the verification method resolves to the key that
//! signed with no document to publish and — the point — **no update key**. A
//! `did:webvh` agent would need an update key per agent that can re-point its
//! own verification methods, which would put the authority to impersonate the
//! agent right back on the gateway and make the migration cosmetic.
//!
//! **How the signer is named.** `keys/sign-document/0.1` reads the signer from a
//! document's `issuer` or `controller`, and signs only as that DID with a key
//! its own document lists for the requested relationship. A presentation names
//! its holder with `holder`, which that task does not read. So the presentation
//! sent for signing carries `controller` as well, set to the same DID as
//! `holder`: the trust agent finds its signer there, and everything that reads a
//! presentation still finds `holder`. The gateway's own verifier reads `holder`
//! and is unchanged. The one extra member is the whole difference from a
//! presentation the gateway signs itself.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::identity::ssi::vp_issuer::{Credentials, VpIssuer, VpIssuerPayload, build_unsigned_presentation};
use crate::vta::client::VtaRestClient;
use crate::vta::context_identity::{ContextIdentityResolver, PURPOSE_AUTHENTICATION};

/// Where an agent's holder key lives: which trust agent, and which context
/// inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBinding {
    /// The context whose key is this agent's, and whose DID is the agent's.
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
    /// One resolver per (trust agent, context), so an agent's identity is read
    /// from the trust agent once rather than on every presentation.
    resolvers: RwLock<HashMap<String, Arc<ContextIdentityResolver>>>,
}

impl VtaVpIssuer {
    pub fn new(
        clients: Arc<dyn VtaClients>,
        contexts: Arc<dyn AgentContexts>,
        local: Arc<dyn VpIssuer>,
    ) -> Self {
        Self {
            clients,
            contexts,
            local,
            resolvers: RwLock::new(HashMap::new()),
        }
    }

    async fn resolver_for(
        &self,
        binding: &AgentBinding,
    ) -> Result<Arc<ContextIdentityResolver>> {
        let key = format!(
            "{}\u{1e}{}",
            binding
                .connection_id
                .as_deref()
                .unwrap_or(""),
            binding.context_id
        );
        if let Some(resolver) = self
            .resolvers
            .read()
            .await
            .get(&key)
        {
            return Ok(Arc::clone(resolver));
        }
        // Resolve the agent's own trust agent — what lets two agents hold their
        // keys in different ones.
        let client = self
            .clients
            .client_for(
                binding
                    .connection_id
                    .as_deref(),
            )
            .await?;
        let resolver = Arc::new(ContextIdentityResolver::new(client, binding.context_id.clone()));
        self.resolvers
            .write()
            .await
            .insert(key, Arc::clone(&resolver));
        Ok(resolver)
    }

    /// Have the agent's own context attach its holder proof.
    async fn sign_through_agent(
        &self,
        holder_did: &str,
        binding: &AgentBinding,
        presentation: &Credentials<'_>,
    ) -> Result<Value> {
        let resolver = self
            .resolver_for(binding)
            .await?;
        let identity = resolver.identity().await?;
        // The presentation says the holder is `holder_did`, so the context that
        // signs it must be exactly that DID. A mismatch means the agent record
        // and the context have come apart, and signing anyway would put a proof
        // from one identity on a document that names another.
        if identity.did != holder_did {
            bail!(
                "agent `{holder_did}` is bound to context `{}`, whose DID is `{}`; refusing to sign as a different identity",
                binding.context_id,
                identity.did
            );
        }

        let mut unsigned = build_unsigned_presentation(
            holder_did,
            presentation
                .verifiable_credentials
                .as_ref(),
        );
        // The trust agent reads the signer from `controller`; `holder` stays so
        // the presentation is still one that names its holder.
        unsigned["controller"] = Value::String(holder_did.to_string());
        resolver
            .sign_document(
                unsigned,
                PURPOSE_AUTHENTICATION,
                presentation
                    .challenge
                    .as_deref(),
                presentation.domain.as_deref(),
            )
            .await
            .map_err(|e| anyhow!("attaching a holder proof through the VTA: {e}"))
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

        self.sign_through_agent(&holder_did, &binding, pc)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vta::context_identity::mock::MockContextVta;
    use serde_json::json;
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

    fn credentials(
        holder: &'static str,
        challenge: Option<&'static str>,
        domain: Option<&'static str>,
    ) -> VpIssuerPayload<'static> {
        VpIssuerPayload::Credentials(Credentials {
            holder_key: None,
            holder_did: Cow::Borrowed(holder),
            verifiable_credentials: Cow::Owned(vec![json!({ "type": "VerifiableCredential" })]),
            challenge: challenge.map(Cow::Borrowed),
            domain: domain.map(Cow::Borrowed),
        })
    }

    fn clients_for(client: Arc<VtaRestClient>) -> Arc<dyn VtaClients> {
        Arc::new(crate::vta::agent_contexts::RegistryVtaClients::new(client, None))
    }

    fn unreachable_client() -> Arc<VtaRestClient> {
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

    fn issuer(
        client: Arc<VtaRestClient>,
        contexts: Arc<dyn AgentContexts>,
        local: &Arc<CountingLocal>,
    ) -> VtaVpIssuer {
        VtaVpIssuer::new(clients_for(client), contexts, Arc::clone(local) as Arc<dyn VpIssuer>)
    }

    /// An agent onboarded before the migration keeps working: it has no VTA
    /// context, so the local signer handles it rather than the call failing.
    #[tokio::test]
    async fn an_agent_with_no_context_is_signed_locally() {
        let local = Arc::new(CountingLocal::default());
        let issuer = issuer(unreachable_client(), Arc::new(NoContexts), &local);

        let vp = issuer
            .issue(credentials("did:key:zAgent", None, None))
            .await
            .expect("a pre-migration agent must still be able to present");
        assert_eq!(vp, json!({ "signed": "locally" }));
        assert_eq!(local.0.load(Ordering::SeqCst), 1);
    }

    /// The presentation is signed as the agent's own context: its proof is made
    /// by the agent's key, under `authentication`.
    #[tokio::test]
    async fn a_bound_agent_presents_through_its_own_context() {
        let vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        let url = vta.spawn().await;
        let local = Arc::new(CountingLocal::default());
        let issuer = issuer(vta.client(&url), Arc::new(FixedContext("gw/agent-1")), &local);
        let agent_did: &'static str = Box::leak(vta.did().into_boxed_str());

        let vp = issuer
            .issue(credentials(agent_did, None, None))
            .await
            .expect("the agent's own context signs its presentation");

        assert_eq!(vp["holder"], json!(agent_did));
        assert_eq!(vp["controller"], json!(agent_did), "the trust agent reads its signer from `controller`");
        let sent = vta
            .last_sign_request
            .lock()
            .unwrap()
            .clone()
            .expect("a request");
        assert_eq!(sent["document"]["holder"], json!(agent_did), "the presentation still names its holder");
        assert_eq!(sent["document"]["controller"], json!(agent_did));
        assert!(
            sent["document"]
                .get("issuer")
                .is_none(),
            "a presentation has a holder, not an issuer"
        );
        assert_eq!(sent["proofPurpose"], json!("authentication"));
        assert_eq!(vp["proof"]["verificationMethod"], json!(vta.verification_method()));
        assert_eq!(vp["proof"]["proofPurpose"], json!("authentication"));
        assert_eq!(vp["proof"]["cryptosuite"], json!("eddsa-jcs-2022"));
        assert_eq!(local.0.load(Ordering::SeqCst), 0, "no gateway-held key may be involved");
    }

    /// A challenge and a domain are bound into the proof, not refused and not
    /// dropped: a holder proof is exactly the artifact that needs replay
    /// protection, and `eddsa-jcs-2022` carries both in the proof it signs.
    #[tokio::test]
    async fn a_challenge_and_domain_are_bound_into_the_holder_proof() {
        let vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        let url = vta.spawn().await;
        let local = Arc::new(CountingLocal::default());
        let issuer = issuer(vta.client(&url), Arc::new(FixedContext("gw/agent-1")), &local);
        let agent_did: &'static str = Box::leak(vta.did().into_boxed_str());

        let vp = issuer
            .issue(credentials(agent_did, Some("nonce-1"), Some("verifier.example")))
            .await
            .expect("a replay-bound presentation");

        assert_eq!(vp["proof"]["challenge"], json!("nonce-1"));
        assert_eq!(vp["proof"]["domain"], json!("verifier.example"));
    }

    /// The presentation names a holder, so the context that signs it must be
    /// that holder. A record and a context that have come apart must not yield
    /// a proof from one identity on a document that names another.
    #[tokio::test]
    async fn a_context_that_is_not_the_holder_is_refused_before_signing() {
        let vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        let url = vta.spawn().await;
        let local = Arc::new(CountingLocal::default());
        let issuer = issuer(vta.client(&url), Arc::new(FixedContext("gw/agent-1")), &local);

        let err = issuer
            .issue(credentials("did:key:zSomeoneElse", None, None))
            .await
            .expect_err("the context is not this holder")
            .to_string();

        assert!(err.contains("different identity"), "{err}");
        assert_eq!(vta.sign_calls(), 0, "nothing may be signed for a holder the context is not");
    }

    /// The agent that *has* a context never falls back to a local key when the
    /// VTA is unreachable — that would sign with the very key the migration
    /// exists to stop using.
    #[tokio::test]
    async fn a_vta_failure_is_an_error_and_never_a_local_downgrade() {
        let local = Arc::new(CountingLocal::default());
        let issuer = issuer(unreachable_client(), Arc::new(FixedContext("gw/agent-1")), &local);

        let outcome = issuer
            .issue(credentials("did:key:zAgent", None, None))
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
        let issuer = issuer(unreachable_client(), Arc::new(NamedContext), &local);

        let err = match issuer
            .issue(credentials("did:key:zAgent", None, None))
            .await
        {
            Ok(vp) => panic!("a named trust agent must not resolve to the bootstrap client, got {vp}"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("raspberry-pi"), "the error must name the trust agent that could not be reached: {err}");
        assert_eq!(local.0.load(Ordering::SeqCst), 0, "and it must not quietly sign locally either");
    }
}
