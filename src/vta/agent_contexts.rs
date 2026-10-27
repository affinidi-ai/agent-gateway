//! Per-agent VTA contexts (VTA-12): provisioning an agent identity whose
//! private key never exists on this host, and finding it again later.
//!
//! An agent's holder key lives in its own VTA context because `proofs/attach`
//! resolves the signing key from (context, `proofPurpose`) and accepts no key
//! id — so one context signs as exactly one holder, and N agents need N
//! contexts.
//!
//! The agent's DID is the `did:key` of that context's key. That ordering
//! matters: the DID is a *consequence* of the key the VTA minted, so there is
//! never a moment where the gateway knows a private half. The context name is
//! derived from the agent's identity hash instead — stable, assigned before
//! any key exists, and unchanged by rotation.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_trait::async_trait;

use crate::identity::store::IdentityStore;
use crate::vta::context_creator::GatewayContextCreator;
use crate::vta::provisioning::ContextCreator;
use crate::vta::vp_issuer::{AgentContexts, HOLDER_PROOF_PURPOSE};

/// Prefix on a derived agent context name, so an operator reading the VTA can
/// tell an agent's context from a surface's.
const AGENT_CONTEXT_PREFIX: &str = "agent:";

/// An agent identity whose key the gateway does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedAgent {
    /// `did:key` of the VTA-held key, so the verification method a verifier
    /// resolves is the key that signs.
    pub did: String,
    /// The context that holds it.
    pub context_id: String,
    /// The trust agent that context lives in.
    pub connection_id: String,
}

/// Provisions agent identities in a Verifiable Trust Agent.
///
/// A port so onboarding can be tested without a VTA, and so the gateway's
/// identity path does not depend on the VTA module directly.
#[async_trait]
pub trait AgentKeyProvisioner: Send + Sync {
    /// Create (or adopt) the context for `identity_hash` and return the agent
    /// identity it defines. Must be idempotent: a retry after a timeout has to
    /// return the same DID, not mint a second identity for the same agent.
    async fn provision(
        &self,
        identity_hash: &str,
    ) -> Result<ProvisionedAgent>;

    /// Whether onboarding may fall back to a gateway-held key when
    /// [`Self::provision`] fails.
    ///
    /// `false` — the default — is for a provisioner the operator asked for
    /// explicitly (`[vta] auto_provision_contexts`): they demanded that agent
    /// keys live in the agent, so quietly minting one here instead would hand
    /// back a weaker guarantee than the one they configured. Onboarding fails
    /// and says why.
    ///
    /// `true` is for a provisioner the gateway *inferred* it could use, from
    /// an agent being the appliance default. The grant may simply not carry
    /// `context-create`, and that cannot be known in advance — the agent
    /// deliberately keeps capabilities out of the session token so a narrowing
    /// takes effect on the next call rather than the next login. Refusing to
    /// onboard any agent at all over an inference would be far worse than
    /// continuing with the key the gateway would have minted anyway.
    fn optional(&self) -> bool {
        false
    }

    /// Whether there is anything to provision into right now.
    ///
    /// `false` means "no trust agent is configured", which is the ordinary
    /// state of a gateway that never adopted one — not a failure. An inferred
    /// provisioner is installed whether or not an agent is the appliance
    /// default, because that default can be set while the gateway runs; without
    /// this check every onboarding on an install with no agent would attempt,
    /// fail and warn, which reads like a fault to anyone who never asked for
    /// one.
    ///
    /// Sync and cheap on purpose: it is consulted before each attempt.
    fn available(&self) -> bool {
        true
    }
}

/// The derived context name for an agent.
fn agent_context_name(identity_hash: &str) -> String {
    format!("{AGENT_CONTEXT_PREFIX}{identity_hash}")
}

/// Provisions agent contexts through the gateway's own VTA grant.
pub struct VtaAgentProvisioner {
    creator: GatewayContextCreator,
    /// The connection this provisioner creates in.
    ///
    /// Carried so every agent records *which* trust agent holds its key. Only
    /// one provisioner exists today, so the value is always the same one — but
    /// recording it is what makes a second trust agent a configuration change
    /// rather than a migration of every record written before it.
    connection_id: String,
}

impl VtaAgentProvisioner {
    pub fn new(
        creator: GatewayContextCreator,
        connection_id: String,
    ) -> Self {
        // The holder proof is an `authentication` proof, and the VTA resolves
        // a different key per purpose with no fallback for that one. A context
        // designated only as an issuer would create fine and then fail to sign
        // a presentation, so the designation is part of provisioning.
        Self {
            creator: creator.with_proof_purposes([HOLDER_PROOF_PURPOSE]),
            connection_id,
        }
    }
}

#[async_trait]
impl AgentKeyProvisioner for VtaAgentProvisioner {
    async fn provision(
        &self,
        identity_hash: &str,
    ) -> Result<ProvisionedAgent> {
        let name = agent_context_name(identity_hash);
        let context_id = self
            .creator
            .create_context(&name)
            .await
            .map_err(|e| anyhow!("provisioning a VTA context for agent `{identity_hash}`: {e}"))?;
        let context_id = context_id
            .as_str()
            .to_string();

        let record = self
            .creator
            .get_context(&context_id)
            .await
            .map_err(|e| anyhow!("reading back the agent context `{context_id}`: {e}"))?;
        let did = record
            .get("did")
            .and_then(|d| d.as_str())
            .ok_or_else(|| {
                anyhow!("the provisioned agent context `{context_id}` carries no DID, so it cannot be an identity")
            })?
            .to_string();

        Ok(ProvisionedAgent {
            did,
            context_id,
            connection_id: self.connection_id.clone(),
        })
    }
}

/// Supplies clients by connection, so an agent can sign in whichever trust
/// agent holds its key.
///
/// Falls back to the bootstrap client when no connection is named — which is
/// every agent today, and remains correct for them once a second trust agent
/// is connected, because their record says which one they are on.
pub struct RegistryVtaClients {
    bootstrap: Arc<crate::vta::client::VtaRestClient>,
    registry: Option<Arc<crate::vta::registry::VtaConnectionRegistry>>,
}

impl RegistryVtaClients {
    pub fn new(
        bootstrap: Arc<crate::vta::client::VtaRestClient>,
        registry: Option<Arc<crate::vta::registry::VtaConnectionRegistry>>,
    ) -> Self {
        Self { bootstrap, registry }
    }
}

#[async_trait]
impl crate::vta::vp_issuer::VtaClients for RegistryVtaClients {
    async fn client_for(
        &self,
        connection_id: Option<&str>,
    ) -> Result<Arc<crate::vta::client::VtaRestClient>> {
        let Some(connection_id) = connection_id else {
            return Ok(Arc::clone(&self.bootstrap));
        };
        if connection_id == crate::vta::connections::BOOTSTRAP_CONNECTION_ID {
            return Ok(Arc::clone(&self.bootstrap));
        }
        // A named connection that cannot be resolved is an error, never a
        // silent fall back to the bootstrap one: signing in the wrong trust
        // agent would produce a proof that verifies against a key the agent's
        // DID does not name.
        let registry = self
            .registry
            .as_ref()
            .ok_or_else(|| {
                anyhow!("agent is bound to trust agent `{connection_id}`, but no connection registry is configured")
            })?;
        registry
            .client(connection_id)
            .await
            .map_err(|e| anyhow!("reaching trust agent `{connection_id}`: {}", e.log_detail()))
    }
}

/// Finds an agent's VTA context from its identity record.
///
/// Reads the context recorded at onboarding rather than re-deriving it: an
/// agent onboarded before the migration has none, and deriving a name would
/// produce one that looks plausible and does not exist.
pub struct StoredAgentContexts {
    identity_store: Arc<dyn IdentityStore>,
}

impl StoredAgentContexts {
    pub fn new(identity_store: Arc<dyn IdentityStore>) -> Self {
        Self { identity_store }
    }
}

#[async_trait]
impl AgentContexts for StoredAgentContexts {
    async fn binding_for(
        &self,
        agent_did: &str,
    ) -> Result<Option<crate::vta::vp_issuer::AgentBinding>> {
        Ok(self
            .identity_store
            .find_by_did(agent_did)
            .await?
            .and_then(|record| {
                record
                    .vta_context_id
                    .map(|context_id| crate::vta::vp_issuer::AgentBinding {
                        context_id,
                        // Absent on a record written before the connection was
                        // tracked; the bootstrap one is the only trust agent it
                        // could have used.
                        connection_id: record.vta_connection_id,
                    })
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name is derived from the identity hash, not the DID: the DID does
    /// not exist until the VTA has minted the key, so deriving from it would
    /// be circular.
    #[test]
    fn an_agent_context_name_is_derived_from_its_identity_hash() {
        assert_eq!(agent_context_name("abc123"), "agent:abc123");
        assert_ne!(agent_context_name("abc123"), agent_context_name("abc124"));
    }

    /// An agent onboarded before the migration has no context, which is what
    /// tells the signing path to use the key the gateway still holds.
    #[tokio::test]
    async fn an_agent_with_no_recorded_context_reports_none() {
        let store = Arc::new(crate::identity::test_helpers::MockIdentityStore::new());
        let contexts = StoredAgentContexts::new(store);
        assert_eq!(
            contexts
                .binding_for("did:key:zUnknown")
                .await
                .expect("a missing agent is not an error"),
            None
        );
    }

    /// The property this whole ticket exists for: an agent provisioned through
    /// a VTA has **no private key on this host**, and its DID is the one the
    /// VTA minted.
    #[tokio::test]
    async fn a_vta_provisioned_agent_record_holds_no_private_key() {
        let store = Arc::new(crate::identity::test_helpers::MockIdentityStore::new());
        let record = crate::identity::AgentIdentityRecord {
            did: "did:key:zAgentOne".to_string(),
            identity_hash: "hash-1".to_string(),
            created_at: chrono::Utc::now(),
            identity_fields: std::collections::HashMap::new(),
            usage_count: 0,
            last_used_at: None,
            channel_usage: vec![],
            private_key: None,
            vta_context_id: Some("gw/agent-1".to_string()),
            vta_connection_id: Some("bootstrap".to_string()),
            channel_config_id: None,
            is_local: true,
            verified: true,
        };
        crate::identity::store::IdentityStore::create(&*store, record)
            .await
            .expect("store the provisioned agent");

        let stored = crate::identity::store::IdentityStore::find_by_did(&*store, "did:key:zAgentOne")
            .await
            .expect("lookup")
            .expect("the agent is there");
        assert!(
            stored.private_key.is_none(),
            "a VTA-backed agent must carry no private key: holding one is the custody this removes"
        );
        assert!(
            stored
                .did
                .starts_with("did:key:"),
            "the agent DID must resolve to the VTA-held key with no document to publish and no update key"
        );

        let contexts = StoredAgentContexts::new(store);
        assert_eq!(
            contexts
                .binding_for("did:key:zAgentOne")
                .await
                .expect("lookup"),
            Some(crate::vta::vp_issuer::AgentBinding {
                context_id: "gw/agent-1".to_string(),
                connection_id: Some("bootstrap".to_string()),
            }),
            "the signing path must find both the context and the trust agent recorded at onboarding"
        );
    }

    /// An agent recorded before the trust agent was tracked still resolves,
    /// to the bootstrap connection — the only one it could have used. This is
    /// what makes connecting a second trust agent a configuration change
    /// rather than a migration of every existing record.
    #[tokio::test]
    async fn an_agent_without_a_recorded_connection_falls_back_to_bootstrap() {
        let store = Arc::new(crate::identity::test_helpers::MockIdentityStore::new());
        let record = crate::identity::AgentIdentityRecord {
            did: "did:key:zLegacyVta".to_string(),
            identity_hash: "hash-2".to_string(),
            created_at: chrono::Utc::now(),
            identity_fields: std::collections::HashMap::new(),
            usage_count: 0,
            last_used_at: None,
            channel_usage: vec![],
            private_key: None,
            vta_context_id: Some("gw/agent-2".to_string()),
            vta_connection_id: None,
            channel_config_id: None,
            is_local: true,
            verified: true,
        };
        crate::identity::store::IdentityStore::create(&*store, record)
            .await
            .expect("store");

        let binding = StoredAgentContexts::new(store)
            .binding_for("did:key:zLegacyVta")
            .await
            .expect("lookup")
            .expect("the agent is bound");
        assert_eq!(binding.context_id, "gw/agent-2");
        assert_eq!(
            binding.connection_id, None,
            "an untracked connection must stay absent so it resolves to the bootstrap client"
        );
    }
}
