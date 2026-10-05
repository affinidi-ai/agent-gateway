//! Policy gate for STS token issuance.
//!
//! Before a token is minted, an issuance request is authorized against the
//! **gateway OPA policy** — the same engine that gates proxy traffic — so a
//! single policy language governs both request forwarding and token issuance.
//! Rego rules read the request context under `input.sts.*`.
//!
//! The evaluator is a port so the handler flow stays unit-testable with a mock;
//! the production adapter delegates to [`GatewayPolicyManager`]. When no gateway
//! policy manager is wired the endpoints still issue tokens under the static
//! managed-connection allowlists ([`AllowAllPolicyEvaluator`]).

use std::sync::Arc;

use serde_json::{Value, json};

use crate::policies::GatewayPolicyManager;
use crate::sts::errors::StsError;

/// Build the OPA policy input for an STS issuance. Rego reads `input.sts.*`.
///
/// `actor` / `audience` serialize to JSON `null` when absent so a rule can test
/// for their presence.
#[allow(clippy::too_many_arguments)]
pub fn build_policy_input(
    grant: &str,
    client_id: &str,
    subject: &str,
    actor: Option<&str>,
    audience: Option<&str>,
    scopes: &[String],
    requested_token_type: &str,
) -> Value {
    json!({
        "sts": {
            "grant": grant,
            "client_id": client_id,
            "subject": subject,
            "actor": actor,
            "audience": audience,
            "scope": scopes,
            "requested_token_type": requested_token_type,
        }
    })
}

/// Authorizes an STS issuance against policy before a token is minted.
pub trait StsPolicyEvaluator: Send + Sync {
    /// `Ok(())` on allow; `Err(unauthorized_client)` on a policy deny (carrying
    /// the policy's `deny_reason`); `Err(server_error)` on an evaluation failure.
    fn authorize(
        &self,
        input: &Value,
    ) -> Result<(), StsError>;
}

/// Reuses the gateway OPA policy (the engine that gates proxy traffic) to gate
/// token issuance. Evaluated against the self-gateway id; if that gateway has no
/// policy configured, the manager allows by default.
pub struct GatewayPolicyEvaluator {
    manager: Arc<GatewayPolicyManager>,
}

impl GatewayPolicyEvaluator {
    pub fn new(manager: Arc<GatewayPolicyManager>) -> Self {
        Self { manager }
    }
}

impl StsPolicyEvaluator for GatewayPolicyEvaluator {
    fn authorize(
        &self,
        input: &Value,
    ) -> Result<(), StsError> {
        // No self-gateway id ⇒ no gateway policy context ⇒ allow, matching the
        // manager's allow-by-default for an unconfigured gateway.
        let Some(gateway_id) = self
            .manager
            .get_self_gateway_id()
        else {
            return Ok(());
        };
        match self
            .manager
            .evaluate_policy_decision(&gateway_id, input.clone())
        {
            Ok(decision) if decision.allow => Ok(()),
            Ok(decision) => {
                let reason = decision
                    .reason
                    .unwrap_or_else(|| "issuance blocked by gateway policy".to_string());
                tracing::warn!(target: "sts_audit", policy_scope = "gateway", reason = %reason, "STS issuance denied by policy");
                Err(StsError::UnauthorizedClient(reason))
            }
            Err(e) => Err(StsError::ServerError(format!("policy evaluation failed: {e}"))),
        }
    }
}

/// Fail-open evaluator used when no gateway policy manager is available. STS
/// endpoints still mount and issue tokens under the static allowlists.
pub struct AllowAllPolicyEvaluator;

impl StsPolicyEvaluator for AllowAllPolicyEvaluator {
    fn authorize(
        &self,
        _input: &Value,
    ) -> Result<(), StsError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::types::{Gateway, GatewayCreationType, GatewayOpaPolicyConfig, GatewayStatus, GatewayType};

    fn self_gateway(policy: Option<&str>) -> Gateway {
        Gateway {
            id: "self-gw".to_string(),
            tenant_id: None,
            name: "self".to_string(),
            description: String::new(),
            did: "did:example:self".to_string(),
            issuer_did: None,
            issuer_did_source: None,
            trusted_issuer_dids: Vec::new(),
            gateway_type: GatewayType::SelfGateway,
            status: GatewayStatus::Active,
            creation_type: GatewayCreationType::User,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            exposed_channels: Vec::new(),
            opa_policy_config: policy.map(|p| GatewayOpaPolicyConfig {
                enabled: true,
                policy: p.to_string(),
                policy_definition_id: None,
                ..Default::default()
            }),
        }
    }

    async fn manager_with(policy: Option<&str>) -> Arc<GatewayPolicyManager> {
        let manager = GatewayPolicyManager::new();
        manager
            .update_gateway_policy(&self_gateway(policy))
            .await
            .expect("policy compiles");
        Arc::new(manager)
    }

    #[test]
    fn build_policy_input_carries_sts_context() {
        let scopes = vec!["reports.read".to_string()];
        let input = build_policy_input(
            "token_exchange",
            "agent-client",
            "did:example:user",
            Some("did:example:agent"),
            Some("https://target.example"),
            &scopes,
            "urn:ietf:params:oauth:token-type:access_token",
        );
        assert_eq!(input["sts"]["grant"], "token_exchange");
        assert_eq!(input["sts"]["client_id"], "agent-client");
        assert_eq!(input["sts"]["subject"], "did:example:user");
        assert_eq!(input["sts"]["actor"], "did:example:agent");
        assert_eq!(input["sts"]["audience"], "https://target.example");
        assert_eq!(input["sts"]["scope"], json!(["reports.read"]));
        assert_eq!(input["sts"]["requested_token_type"], "urn:ietf:params:oauth:token-type:access_token");
    }

    #[test]
    fn build_policy_input_omits_optional_as_null() {
        let input = build_policy_input("jwt_bearer", "c", "s", None, None, &[], "t");
        assert!(input["sts"]["actor"].is_null(), "absent actor should be null");
        assert!(input["sts"]["audience"].is_null(), "absent audience should be null");
    }

    #[test]
    fn allow_all_evaluator_allows() {
        assert!(
            AllowAllPolicyEvaluator
                .authorize(&json!({ "sts": {} }))
                .is_ok()
        );
    }

    #[test]
    fn gateway_evaluator_allows_when_no_self_gateway() {
        let evaluator = GatewayPolicyEvaluator::new(Arc::new(GatewayPolicyManager::new()));
        assert!(
            evaluator
                .authorize(&json!({ "sts": { "grant": "token_exchange" } }))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn gateway_evaluator_allows_when_policy_permits() {
        let rego =
            "package gateway.policy\ndefault allow = false\nallow if {\n    input.sts.client_id == \"trusted\"\n}";
        let evaluator = GatewayPolicyEvaluator::new(manager_with(Some(rego)).await);
        assert!(
            evaluator
                .authorize(&json!({ "sts": { "client_id": "trusted" } }))
                .is_ok()
        );
    }

    #[tokio::test]
    async fn gateway_evaluator_denies_with_reason() {
        let rego =
            "package gateway.policy\ndefault allow = false\ndeny_reason = \"issuance not permitted for this client\"";
        let evaluator = GatewayPolicyEvaluator::new(manager_with(Some(rego)).await);
        let err = evaluator
            .authorize(&json!({ "sts": { "client_id": "blocked" } }))
            .unwrap_err();
        assert_eq!(err.error_code(), "unauthorized_client");
        assert!(
            err.description()
                .contains("not permitted"),
            "deny reason should reach the client, got {}",
            err.description()
        );
    }
}
