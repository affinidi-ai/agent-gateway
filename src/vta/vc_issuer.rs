//! Issuing the Data-Integrity agent-identity credential through a Verifiable
//! Trust Agent (VTA-11b).
//!
//! The gateway's own `LocalVcIssuer` builds the credential and signs it with
//! the gateway-held issuer key. This issues the same credential through the
//! VTA's `credentials/issue-in-context/0.1` task instead, so the private key
//! lives in the agent rather than in this process.
//!
//! **Not `vta/credentials/issue/0.2`.** That task is instance-super-admin gated
//! and signs with the VTA's *own* `#key-0`, so a gateway using it would need
//! authority over the whole VTA and would mint credentials attributed to the
//! VTA rather than to the tenant. The context-scoped task needs only authority
//! over the gateway's context and issues as that context's DID.
//!
//! The VTA returns an `eddsa-jcs-2022` proof, which
//! [`crate::identity::ssi::verifier`] verifies through
//! `affinidi-data-integrity` — `ssi` implements no JCS cryptosuite.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::identity::ssi::context::CTX_AGENT_IDENTITY_V1_URL;
use crate::identity::ssi::vc_issuer::{IssueVcPayload, VcIssuer};
use crate::vta::client::VtaRestClient;

/// `vta/credentials/issue-in-context/0.1`.
const TASK_CREDENTIALS_ISSUE_IN_CONTEXT: &str = "https://trusttasks.org/spec/vta/credentials/issue-in-context/0.1";

/// `vta/credentials/revoke/0.1`.
const TASK_CREDENTIALS_REVOKE: &str = "https://trusttasks.org/spec/vta/credentials/revoke/0.1";

/// The credential type the gateway issues for an agent identity.
const AGENT_IDENTITY_CREDENTIAL_TYPE: &str = "AgentIdentityCredential";

/// How long an issued agent-identity credential stays valid.
///
/// Mirrors the local issuer's `VC_LIFETIME_DAYS`, expressed in seconds because
/// that is what the Trust Task takes.
const VC_LIFETIME_SECONDS: u64 = 365 * 24 * 60 * 60;

#[derive(Debug, Deserialize)]
struct IssueInContextResult {
    #[serde(rename = "credentialId")]
    credential_id: String,
    credential: Value,
    #[serde(rename = "verificationMethod")]
    verification_method: String,
}

/// Issues agent-identity credentials through a VTA context.
pub struct VtaVcIssuer {
    client: Arc<VtaRestClient>,
    /// The VTA context to issue as. Its designated issuer key signs, and its
    /// DID becomes the credential's `issuer` — which is why the gateway never
    /// names a key.
    context_id: String,
}

impl VtaVcIssuer {
    pub fn new(
        client: Arc<VtaRestClient>,
        context_id: String,
    ) -> Self {
        Self { client, context_id }
    }

    /// Revoke a previously issued credential by id, in the same context.
    ///
    /// Unconsumed today: the gateway has never revoked an agent-identity
    /// credential, and `LocalVerifier::check_revocation_status` is still a
    /// warn-only stub, so there is no caller to wire this to. It is kept
    /// because moving issuance to the VTA is what makes revocation *possible*
    /// — the VTA stores what it issued — and whoever implements status-list
    /// checking needs the matching write side to exist and to be scoped to the
    /// same context as issuance.
    #[allow(dead_code)]
    pub async fn revoke(
        &self,
        credential_id: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let mut request = json!({ "credentialId": credential_id });
        if let Some(reason) = reason {
            request
                .as_object_mut()
                .expect("request is an object")
                .insert("reason".into(), json!(reason));
        }
        let _: Value = self
            .client
            .dispatch(TASK_CREDENTIALS_REVOKE, request)
            .await
            .with_context(|| format!("revoking credential {credential_id} through the VTA"))?;
        Ok(())
    }
}

#[async_trait]
impl VcIssuer for VtaVcIssuer {
    async fn issue<'a>(
        &self,
        payload: IssueVcPayload<'a>,
    ) -> Result<Value> {
        let IssueVcPayload::AgentIdentity(agent) = payload;

        // The same subject shape the local issuer builds: the structured
        // Workload Binding when present, the flat identity fields otherwise.
        // `credentialSubject.id` is set by the VTA from `holder`, so it is not
        // sent here — sending it too would let the two disagree.
        let claims = if let Some(ref binding) = agent.workload_binding {
            json!({ "workloadBinding": binding })
        } else {
            json!({
                "identityFields": serde_json::to_value(&*agent.identity_fields)
                    .context("Failed to serialize identity fields")?,
            })
        };

        let request = json!({
            "contextId": self.context_id,
            "holder": agent.did.as_ref(),
            "claims": claims,
            "credentialType": AGENT_IDENTITY_CREDENTIAL_TYPE,
            "validitySeconds": VC_LIFETIME_SECONDS,
            // The credential's type defines its own terms, so the context that
            // declares them has to travel with it or no verifier can expand it.
            "additionalContexts": [CTX_AGENT_IDENTITY_V1_URL],
        });

        let result: IssueInContextResult = self
            .client
            .dispatch(TASK_CREDENTIALS_ISSUE_IN_CONTEXT, request)
            .await
            .context("issuing the agent-identity credential through the VTA")?;

        // Fail closed on a credential that cannot be used. A VTA that returned
        // an unproven or mis-subjected credential has not done the job, and
        // passing it on would surface as a confusing verification failure at
        // the far end of the request instead of here.
        if result
            .credential
            .get("proof")
            .is_none()
        {
            return Err(anyhow!(
                "VTA returned an agent-identity credential with no proof (credentialId {})",
                result.credential_id
            ));
        }
        let subject = result
            .credential
            .get("credentialSubject")
            .and_then(|s| s.get("id"))
            .and_then(|id| id.as_str());
        if subject != Some(agent.did.as_ref()) {
            return Err(anyhow!(
                "VTA issued a credential for {:?}, not for the requested agent {}",
                subject,
                agent.did.as_ref()
            ));
        }

        tracing::debug!(
            credential_id = %result.credential_id,
            verification_method = %result.verification_method,
            context_id = %self.context_id,
            "agent-identity credential issued by the VTA"
        );

        Ok(result.credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::collections::HashMap;

    use crate::identity::ssi::vc_issuer::AgentIdentity;

    fn agent(did: &str) -> IssueVcPayload<'_> {
        let mut fields = HashMap::new();
        fields.insert("region".to_string(), json!("eu"));
        IssueVcPayload::AgentIdentity(AgentIdentity {
            did: Cow::Borrowed(did),
            identity_fields: Cow::Owned(fields),
            workload_binding: None,
            display_name: None,
        })
    }

    /// The request must name the context, never a key: the VTA resolves the
    /// signing key from the context's designation, which is what keeps the
    /// gateway from being able to point it at another key.
    #[test]
    fn the_request_names_a_context_and_never_a_key() {
        let request = json!({
            "contextId": "ctx-1",
            "holder": "did:peer:agent",
            "claims": { "identityFields": { "region": "eu" } },
            "credentialType": AGENT_IDENTITY_CREDENTIAL_TYPE,
            "validitySeconds": VC_LIFETIME_SECONDS,
            "additionalContexts": [CTX_AGENT_IDENTITY_V1_URL],
        });
        assert!(request.get("keyId").is_none(), "no key may be named");
        assert!(
            request
                .get("issuer")
                .is_none(),
            "the issuer follows the context"
        );
        assert_eq!(request["contextId"], "ctx-1");
    }

    /// The agent-identity context must travel with the credential; without it
    /// the credential's own terms cannot be expanded by a verifier.
    #[test]
    fn the_agent_identity_context_is_requested() {
        assert!(CTX_AGENT_IDENTITY_V1_URL.starts_with("https://"), "the context must be a resolvable URL");
    }

    #[test]
    fn a_workload_binding_replaces_the_flat_identity_fields() {
        let binding = json!({ "caller": { "did": "did:peer:caller" } });
        let payload = IssueVcPayload::AgentIdentity(AgentIdentity {
            did: Cow::Borrowed("did:peer:agent"),
            identity_fields: Cow::Owned(HashMap::new()),
            workload_binding: Some(binding.clone()),
            display_name: None,
        });
        let IssueVcPayload::AgentIdentity(agent) = payload;
        let claims = if let Some(ref wb) = agent.workload_binding {
            json!({ "workloadBinding": wb })
        } else {
            json!({ "identityFields": {} })
        };
        assert_eq!(claims["workloadBinding"], binding);
        assert!(
            claims
                .get("identityFields")
                .is_none(),
            "the two subject shapes are alternatives, never both"
        );
    }

    #[test]
    fn the_flat_identity_fields_are_used_without_a_binding() {
        let IssueVcPayload::AgentIdentity(a) = agent("did:peer:agent");
        assert!(a.workload_binding.is_none());
        assert_eq!(a.identity_fields["region"], json!("eu"));
    }
}
