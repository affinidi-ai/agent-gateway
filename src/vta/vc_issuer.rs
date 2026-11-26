//! Issuing the Data-Integrity agent-identity credential through a Verifiable
//! Trust Agent.
//!
//! The gateway's own `LocalVcIssuer` builds the credential and signs it with
//! the gateway-held issuer key. This builds the **same document** — through
//! the same builder — and has the trust agent sign it with
//! `keys/sign-document/0.1`, so the private key lives in the agent rather than
//! in this process.
//!
//! Why the gateway builds the credential rather than asking the agent to:
//! `keys/sign-document` is the specified way to have a custodian secure a
//! document, and it signs only as the DID the document's `issuer` names, only
//! with a key that DID's own document lists for the requested relationship. The
//! credential's `issuer` is the **context's** `did:key`, so the proof comes from
//! the context's key and from nothing else the agent holds — in particular not
//! from the agent's own key.
//!
//! The agent returns an `eddsa-jcs-2022` proof, which
//! [`crate::identity::ssi::verifier`] verifies through
//! `affinidi-data-integrity` — `ssi` implements no JCS cryptosuite.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde_json::Value;

use crate::identity::ssi::vc_issuer::{IssueVcPayload, VcIssuer, build_agent_identity_credential};
use crate::vta::client::VtaRestClient;
use crate::vta::context_identity::{ContextIdentityResolver, PURPOSE_ASSERTION_METHOD};

/// Issues agent-identity credentials through a VTA context.
pub struct VtaVcIssuer {
    context: ContextIdentityResolver,
}

impl VtaVcIssuer {
    pub fn new(
        client: Arc<VtaRestClient>,
        context_id: String,
    ) -> Self {
        Self {
            context: ContextIdentityResolver::new(client, context_id),
        }
    }
}

#[async_trait]
impl VcIssuer for VtaVcIssuer {
    async fn issue<'a>(
        &self,
        payload: IssueVcPayload<'a>,
    ) -> Result<Value> {
        let IssueVcPayload::AgentIdentity(agent) = payload;

        // The issuer is the context's own DID, so the identity is read first:
        // a context with no identity fails here, with the reason, rather than
        // as a refusal from the signing task.
        let identity = self
            .context
            .identity()
            .await?;
        let credential = build_agent_identity_credential(&identity.did, &agent, chrono::Utc::now())?;

        let signed = self
            .context
            .sign_document(credential, PURPOSE_ASSERTION_METHOD, None, None)
            .await
            .context("issuing the agent-identity credential through the VTA")?;

        // Fail closed on a credential that names someone else. The gateway
        // built the subject, so anything different came back from the wire.
        let subject = signed
            .get("credentialSubject")
            .and_then(|s| s.get("id"))
            .and_then(Value::as_str);
        if subject != Some(agent.did.as_ref()) {
            return Err(anyhow!(
                "VTA issued a credential for {:?}, not for the requested agent {}",
                subject,
                agent.did.as_ref()
            ));
        }

        tracing::debug!(
            verification_method = %identity.verification_method,
            context_id = %self.context.context_id(),
            "agent-identity credential issued by the VTA"
        );

        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::collections::HashMap;

    use serde_json::json;

    use crate::identity::ssi::vc_issuer::AgentIdentity;
    use crate::vta::context_identity::mock::MockContextVta;

    fn agent(did: &str) -> IssueVcPayload<'_> {
        let mut fields = HashMap::new();
        fields.insert("region".to_string(), json!("eu"));
        IssueVcPayload::AgentIdentity(AgentIdentity {
            did: Cow::Borrowed(did),
            identity_fields: Cow::Owned(fields),
            workload_binding: None,
            display_name: Some(Cow::Borrowed("Support bot")),
        })
    }

    fn issuer_for(
        vta: &MockContextVta,
        url: &str,
    ) -> VtaVcIssuer {
        VtaVcIssuer::new(vta.client(url), vta.context_id.clone())
    }

    /// The credential's issuer is the **context's** DID, and its proof is made
    /// by that DID's own verification method — which is what lets a verifier
    /// resolve the proof with no registry.
    #[tokio::test]
    async fn the_credential_is_issued_as_the_context_and_proved_by_its_key() {
        let vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        let url = vta.spawn().await;

        let vc = issuer_for(&vta, &url)
            .issue(agent("did:key:zAgent"))
            .await
            .expect("issued");

        assert_eq!(vc["issuer"], json!(vta.did()));
        assert_eq!(vc["proof"]["verificationMethod"], json!(vta.verification_method()));
        assert_eq!(vc["proof"]["cryptosuite"], json!("eddsa-jcs-2022"));
        assert_eq!(vc["proof"]["proofPurpose"], json!("assertionMethod"));
        assert_eq!(vc["credentialSubject"]["id"], json!("did:key:zAgent"));
        assert_eq!(vc["credentialSubject"]["identityFields"]["region"], json!("eu"));
        assert_eq!(vc["credentialSubject"]["name"], json!("Support bot"));
        assert_eq!(vc["type"], json!(["VerifiableCredential", "AgentIdentityCredential"]));
        assert_eq!(vta.sign_calls(), 1, "one credential is one signature");
    }

    /// The same builder feeds the local issuer, so the document a trust agent
    /// signs is the document the gateway would have signed itself.
    #[tokio::test]
    async fn the_signed_document_is_what_the_shared_builder_produces() {
        let vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        let url = vta.spawn().await;
        issuer_for(&vta, &url)
            .issue(agent("did:key:zAgent"))
            .await
            .expect("issued");

        let sent = vta
            .last_sign_request
            .lock()
            .unwrap()
            .clone()
            .expect("a request");
        let document = &sent["document"];
        assert_eq!(document["issuer"], json!(vta.did()));
        assert!(
            document
                .get("proof")
                .is_none(),
            "the document must be sent unsigned"
        );
        assert_eq!(
            document["@context"][1],
            json!(crate::identity::ssi::context::CTX_AGENT_IDENTITY_V1_URL),
            "the credential's own terms must travel with it"
        );
        assert!(document["validUntil"].is_string() && document["validFrom"].is_string());
        assert!(
            document["id"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:")
        );
    }

    #[tokio::test]
    async fn a_workload_binding_replaces_the_flat_identity_fields() {
        let vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        let url = vta.spawn().await;
        let binding = json!({ "caller": { "did": "did:peer:caller" } });
        let payload = IssueVcPayload::AgentIdentity(AgentIdentity {
            did: Cow::Borrowed("did:key:zAgent"),
            identity_fields: Cow::Owned(HashMap::new()),
            workload_binding: Some(binding.clone()),
            display_name: None,
        });

        let vc = issuer_for(&vta, &url)
            .issue(payload)
            .await
            .expect("issued");

        assert_eq!(vc["credentialSubject"]["workloadBinding"], binding);
        assert!(
            vc["credentialSubject"]
                .get("identityFields")
                .is_none(),
            "the two subject shapes are alternatives, never both"
        );
    }

    /// A trust agent that cannot be reached means no credential — never one
    /// signed locally under a different issuer than the operator mapped.
    #[tokio::test]
    async fn an_unreachable_agent_yields_no_credential() {
        let vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        let issuer = issuer_for(&vta, "http://127.0.0.1:1");
        assert!(
            issuer
                .issue(agent("did:key:zAgent"))
                .await
                .is_err()
        );
    }

    /// A context with no DID cannot sign as itself, and the error says so.
    #[tokio::test]
    async fn a_context_with_no_identity_is_refused_before_any_signing() {
        let mut vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        vta.did = None;
        let url = vta.spawn().await;

        let err = issuer_for(&vta, &url)
            .issue(agent("did:key:zAgent"))
            .await
            .expect_err("no identity, no credential")
            .to_string();

        assert!(err.contains("no DID"), "{err}");
        assert_eq!(vta.sign_calls(), 0, "nothing may be signed for a context with no identity");
    }

    /// A revoked key is not an identity: the context's `did:key` names a key
    /// the agent will no longer sign with.
    #[tokio::test]
    async fn a_revoked_key_is_refused_before_any_signing() {
        let mut vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        vta.key_status = "revoked";
        let url = vta.spawn().await;

        let err = issuer_for(&vta, &url)
            .issue(agent("did:key:zAgent"))
            .await
            .expect_err("a revoked key cannot issue")
            .to_string();

        assert!(err.contains("no active Ed25519 key"), "{err}");
        assert_eq!(vta.sign_calls(), 0);
    }

    #[tokio::test]
    async fn a_refusal_from_the_agent_surfaces_with_its_reason() {
        let vta = MockContextVta::new("gw/agent-1", "agent-1-issuer");
        *vta.refuse_signing
            .lock()
            .unwrap() = true;
        let url = vta.spawn().await;

        let err = format!(
            "{:#}",
            issuer_for(&vta, &url)
                .issue(agent("did:key:zAgent"))
                .await
                .expect_err("a refusal is an error")
        );

        assert!(err.contains("agent-identity credential"), "{err}");
    }
}
