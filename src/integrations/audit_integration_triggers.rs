//! The Governance Audit integration category: which integrations receive
//! audit records, the template variables a record offers, and publishing one
//! rendered record. Delivery order, retries and selection live in
//! [`crate::audit`].

use std::collections::HashMap;

use anyhow::Context;
use futures::future::BoxFuture;

use crate::audit::catalog::AUDIT_EVENTS;
use crate::delegation_vault::audit::{
    AuditCallerContext, DelegationAuditAction, DelegationAuditEvent, action_category,
};
use crate::storage::Integration;

/// Integration category whose integrations receive governance audit records.
pub const AUDIT_CATEGORY: &str = "audit";

/// The `audit` integration category offered in the integration configuration.
/// Each event type is `audit.<category>`.
pub fn audit_integration_category() -> crate::config::IntegrationCategory {
    crate::config::IntegrationCategory {
        enum_value: AUDIT_CATEGORY.to_string(),
        name: "Governance Audit".to_string(),
        description: "Sends the audit events you select, such as policy decisions, refused requests, trust checks, credential delegation and payment events, whether or not the VP Audit Log keeps them. Requires the audit.view permission.".to_string(),
        metadata: serde_json::json!({
            "event_types": AUDIT_EVENTS
                .iter()
                .map(|event| serde_json::json!({
                    "event_type": format!("{}.{}", AUDIT_CATEGORY, event.category),
                    "name": event.name,
                    "description": event.description,
                    "group": event.group,
                }))
                .collect::<Vec<_>>(),
        }),
    }
}

/// Whether the integration belongs to the governance audit category.
pub fn is_audit_integration(integration: &Integration) -> bool {
    integration
        .category
        .as_deref()
        == Some(AUDIT_CATEGORY)
}

/// Audit records carry appliance-wide evidence, so only active integrations
/// without a tenant owner receive them, whatever their type.
pub(crate) fn receives_audit_records(integration: &Integration) -> bool {
    is_audit_integration(integration)
        && integration.status == "active"
        && integration
            .tenant_id
            .is_none()
}

/// `audit.<category>`, e.g. `audit.policy_decision`.
pub fn audit_event_type(event: &DelegationAuditEvent) -> String {
    format!("{}.{}", AUDIT_CATEGORY, action_category(&event.event))
}

/// Runtime variables describing one audit record.
pub fn audit_variables(event: &DelegationAuditEvent) -> HashMap<String, String> {
    let text = |value: &Option<String>| {
        value
            .clone()
            .unwrap_or_default()
    };
    let policy = match &event.event {
        DelegationAuditAction::PolicyDecision {
            decision,
            deny_reason,
            policy_id,
            policy_name,
            policy_version,
            policy_content_hash,
            ..
        } => PolicyVariables {
            decision: decision.clone(),
            deny_reason: text(deny_reason),
            name: policy_name
                .clone()
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| policy_id.clone()),
            version: policy_version
                .map(|version| version.to_string())
                .unwrap_or_default(),
            content_hash: text(policy_content_hash),
        },
        _ => PolicyVariables::default(),
    };
    let caller = event.caller.as_ref();
    let caller_text = |field: fn(&AuditCallerContext) -> &Option<String>| {
        caller
            .and_then(|caller| field(caller).clone())
            .unwrap_or_default()
    };

    HashMap::from([
        ("EVENT_TYPE".to_string(), audit_event_type(event)),
        ("TIMESTAMP".to_string(), event.timestamp.clone()),
        ("AUDIT_RECORD".to_string(), serde_json::to_string(event).unwrap_or_default()),
        ("AUDIT_CATEGORY".to_string(), action_category(&event.event).to_string()),
        ("AUDIT_TRACE_ID".to_string(), text(&event.trace_id)),
        ("AUDIT_SURFACE_ID".to_string(), text(&event.surface_id)),
        ("AUDIT_SURFACE_NAME".to_string(), text(&event.channel_name)),
        ("AUDIT_PROTOCOL".to_string(), text(&event.protocol)),
        ("AUDIT_AGENT_DID".to_string(), text(&event.agent_identity_did)),
        ("AUDIT_VIA_FABRIC".to_string(), event.via_fabric.to_string()),
        (
            "AUDIT_PRINCIPAL".to_string(),
            caller
                .map(principal)
                .unwrap_or_default(),
        ),
        ("AUDIT_PRINCIPAL_EMAIL".to_string(), caller_text(|caller| &caller.email)),
        ("AUDIT_PRINCIPAL_NAME".to_string(), caller_text(|caller| &caller.name)),
        (
            "AUDIT_AUTH_METHOD".to_string(),
            caller
                .map(|caller| caller.auth_method.clone())
                .unwrap_or_default(),
        ),
        ("AUDIT_DECISION".to_string(), policy.decision),
        ("AUDIT_DENY_REASON".to_string(), policy.deny_reason),
        ("AUDIT_POLICY_NAME".to_string(), policy.name),
        ("AUDIT_POLICY_VERSION".to_string(), policy.version),
        ("AUDIT_POLICY_CONTENT_HASH".to_string(), policy.content_hash),
        ("AUDIT_VP_JWT".to_string(), text(&event.vp_jwt)),
        ("AUDIT_VP_FINGERPRINT".to_string(), text(&event.vp_fingerprint)),
    ])
}

#[derive(Default)]
struct PolicyVariables {
    decision: String,
    deny_reason: String,
    name: String,
    version: String,
    content_hash: String,
}

/// The authenticated caller as a person reads it: email, else display name,
/// else the authenticated subject (JWT `sub`, API key name, DID, mTLS principal).
fn principal(caller: &AuditCallerContext) -> String {
    [&caller.email, &caller.name, &caller.sub]
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_default()
}

/// One audit record, rendered once and shared by every subscribed integration.
#[derive(Debug, Clone)]
pub(crate) struct AuditDelivery {
    subject: String,
    message: String,
    variables: HashMap<String, String>,
}

impl AuditDelivery {
    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn variables(&self) -> &HashMap<String, String> {
        &self.variables
    }

    pub(crate) fn from_event(event: &DelegationAuditEvent) -> Self {
        let event_type = audit_event_type(event);
        Self {
            subject: format!("Governance Audit: {}", event_type),
            message: format!("Governance audit record '{}' written", event_type),
            variables: audit_variables(event),
        }
    }
}

/// The integration no longer receives audit records: it was disabled, given a
/// tenant or moved out of the Governance Audit category.
#[derive(Debug, thiserror::Error)]
#[error("integration {0} no longer receives audit records")]
pub(crate) struct NotReceiving(String);

/// Publishes one rendered record to a Governance Audit integration, counted in
/// `agent_gateway_audit_forward_total`. An integration that no longer
/// receives audit records refuses it with [`NotReceiving`], counted as
/// `not_receiving`: its reader retries until the dispatcher parks the sink,
/// and the record is delivered once the integration receives records again.
pub(crate) fn publish_audit_delivery(
    integration_id: String,
    delivery: AuditDelivery,
) -> BoxFuture<'static, anyhow::Result<()>> {
    use crate::integrations::integration_service::load_integration;

    Box::pin(async move {
        let integration = load_integration(&integration_id)
            .await
            .with_context(|| format!("loading audit integration {integration_id}"))?;
        publish_audit_record(&integration, &delivery).await
    })
}

/// [`publish_audit_delivery`] for an integration already loaded.
async fn publish_audit_record(
    integration: &Integration,
    delivery: &AuditDelivery,
) -> anyhow::Result<()> {
    use crate::integrations::integration_service::publish_to_integration;
    use crate::metrics::backends::prometheus::track_audit_forward;

    if !receives_audit_records(integration) {
        track_audit_forward("not_receiving", Some(&integration.id));
        return Err(NotReceiving(integration.id.clone()).into());
    }
    match publish_to_integration(integration, delivery.subject(), delivery.message(), delivery.variables()).await {
        Ok(()) => {
            track_audit_forward("delivered", Some(&integration.id));
            Ok(())
        }
        Err(e) => {
            track_audit_forward("failed", Some(&integration.id));
            Err(anyhow::Error::from(e).context(format!("publishing to audit integration {}", integration.id)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::events::{
        AuthScheme, DelegationFailureReason, IdentityBindingFailure, RateLimitScope, RejectionReason, RejectionStage,
        RequestFailureOutcome, TargetKind,
    };
    use crate::delegation_vault::audit::{PaymentEventDetails, PaymentRail, PaymentStage, audit_event};
    use std::collections::HashSet;

    fn integration(
        category: Option<&str>,
        status: &str,
        tenant_id: Option<&str>,
    ) -> Integration {
        let mut integration = Integration::new(
            "Audit stream".to_string(),
            String::new(),
            "stream".to_string(),
            serde_json::json!({"platform": "kafka", "topic": "audit"}),
            serde_json::json!({}),
            status.to_string(),
            category.map(str::to_string),
        );
        integration.tenant_id = tenant_id.map(str::to_string);
        integration
    }

    fn policy_decision(decision: &str) -> DelegationAuditEvent {
        let mut event = audit_event(
            DelegationAuditAction::PolicyDecision {
                scope: "surface".to_string(),
                flow: "access_point".to_string(),
                policy_id: "surface.policy".to_string(),
                policy_name: Some("Deny unknown callers".to_string()),
                policy_definition_id: None,
                decision: decision.to_string(),
                deny_reason: (decision == "deny").then(|| "caller not recognised".to_string()),
                surface_id: Some("surface-1".to_string()),
                caller_did: Some("did:web:caller".to_string()),
                http_method: Some("POST".to_string()),
                http_path: Some("/a2a".to_string()),
                policy_version: Some(3),
                policy_content_hash: Some("sha256:abc".to_string()),
                removed_tools: None,
            },
            None,
            None,
            None,
            Some("surface-1"),
        );
        event.channel_name = Some("Billing agent".to_string());
        event.protocol = Some("a2a".to_string());
        event.agent_identity_did = Some("did:web:agent".to_string());
        event.trace_id = Some("trace-1".to_string());
        event.vp_jwt = Some("eyJhbGciOiJFZERTQSJ9.eyJ2cCI6e319.sig".to_string());
        event.vp_fingerprint = Some("sha256:vp".to_string());
        event.caller = Some(jwt_caller(Some("ada@example.com"), Some("Ada Lovelace")));
        event
    }

    fn jwt_caller(
        email: Option<&str>,
        name: Option<&str>,
    ) -> AuditCallerContext {
        crate::delegation_vault::audit::build_caller_context(&crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "user-123".to_string(),
            claims: serde_json::json!({"iss": "https://idp.example.com", "email": email, "name": name}),
        })
    }

    fn vp_injected(trace_id: &str) -> DelegationAuditEvent {
        let mut event = audit_event(DelegationAuditAction::VpInjected, None, None, None, Some("surface-2"));
        event.trace_id = Some(trace_id.to_string());
        event.via_fabric = true;
        event.vp_jwt = Some("vp-jwt".to_string());
        event
    }

    fn forwards(
        result: &str,
        integration_id: &str,
    ) -> u64 {
        crate::metrics::backends::prometheus::AUDIT_FORWARD
            .with_label_values(&[result, integration_id])
            .get()
    }

    #[tokio::test]
    async fn an_integration_that_no_longer_receives_audit_records_refuses_the_record() {
        let delivery = AuditDelivery::from_event(&policy_decision("allow"));
        for stopped in [
            integration(Some(AUDIT_CATEGORY), "disabled", None),
            integration(Some(AUDIT_CATEGORY), "active", Some("tenant-a")),
            integration(Some("general"), "active", None),
        ] {
            let error = publish_audit_record(&stopped, &delivery)
                .await
                .unwrap_err();

            assert!(error.is::<NotReceiving>(), "{error:#}");
            assert_eq!(forwards("not_receiving", &stopped.id), 1);
            assert_eq!(forwards("failed", &stopped.id), 0);
            assert_eq!(forwards("delivered", &stopped.id), 0);
        }
    }

    #[test]
    fn audit_variables_describe_a_policy_decision() {
        let event = policy_decision("deny");
        let variables = audit_variables(&event);

        assert_eq!(variables["EVENT_TYPE"], "audit.policy_decision");
        assert_eq!(variables["TIMESTAMP"], event.timestamp);
        assert_eq!(variables["AUDIT_CATEGORY"], "policy_decision");
        assert_eq!(variables["AUDIT_TRACE_ID"], "trace-1");
        assert_eq!(variables["AUDIT_SURFACE_ID"], "surface-1");
        assert_eq!(variables["AUDIT_SURFACE_NAME"], "Billing agent");
        assert_eq!(variables["AUDIT_PROTOCOL"], "a2a");
        assert_eq!(variables["AUDIT_AGENT_DID"], "did:web:agent");
        assert_eq!(variables["AUDIT_VIA_FABRIC"], "false");
        assert_eq!(variables["AUDIT_DECISION"], "deny");
        assert_eq!(variables["AUDIT_DENY_REASON"], "caller not recognised");
        assert_eq!(variables["AUDIT_POLICY_NAME"], "Deny unknown callers");
        assert_eq!(variables["AUDIT_POLICY_VERSION"], "3");
        assert_eq!(variables["AUDIT_POLICY_CONTENT_HASH"], "sha256:abc");
        assert_eq!(variables["AUDIT_PRINCIPAL"], "ada@example.com");
        assert_eq!(variables["AUDIT_PRINCIPAL_EMAIL"], "ada@example.com");
        assert_eq!(variables["AUDIT_PRINCIPAL_NAME"], "Ada Lovelace");
        assert_eq!(variables["AUDIT_AUTH_METHOD"], "jwt_bearer");
        assert_eq!(variables["AUDIT_VP_JWT"], "eyJhbGciOiJFZERTQSJ9.eyJ2cCI6e319.sig");
        assert_eq!(variables["AUDIT_VP_FINGERPRINT"], "sha256:vp");

        let record: serde_json::Value = serde_json::from_str(&variables["AUDIT_RECORD"]).unwrap();
        assert_eq!(record, serde_json::to_value(&event).unwrap(), "the record is the VP Audit Log row");
        assert_eq!(record["event"]["policy_decision"]["decision"], "deny");
    }

    #[test]
    fn audit_variables_leave_policy_fields_empty_for_other_categories() {
        let variables = audit_variables(&vp_injected("trace-9"));

        assert_eq!(variables["EVENT_TYPE"], "audit.vp_injected");
        assert_eq!(variables["AUDIT_CATEGORY"], "vp_injected");
        assert_eq!(variables["AUDIT_VIA_FABRIC"], "true");
        assert_eq!(variables["AUDIT_VP_JWT"], "vp-jwt");
        assert_eq!(variables["AUDIT_DECISION"], "");
        assert_eq!(variables["AUDIT_DENY_REASON"], "");
        assert_eq!(variables["AUDIT_POLICY_NAME"], "");
        assert_eq!(variables["AUDIT_POLICY_VERSION"], "");
        assert_eq!(variables["AUDIT_POLICY_CONTENT_HASH"], "");
        assert_eq!(variables["AUDIT_PRINCIPAL"], "", "no caller context means no principal");
        assert_eq!(variables["AUDIT_PRINCIPAL_EMAIL"], "");
        assert_eq!(variables["AUDIT_PRINCIPAL_NAME"], "");
        assert_eq!(variables["AUDIT_AUTH_METHOD"], "");
        assert_eq!(variables["AUDIT_SURFACE_NAME"], "");
        assert_eq!(variables["AUDIT_VP_FINGERPRINT"], "");
    }

    #[test]
    fn allow_decision_has_no_deny_reason() {
        let variables = audit_variables(&policy_decision("allow"));
        assert_eq!(variables["AUDIT_DECISION"], "allow");
        assert_eq!(variables["AUDIT_DENY_REASON"], "");
    }

    #[test]
    fn principal_falls_back_from_email_to_name_to_subject() {
        let with = |caller: AuditCallerContext| {
            let mut event = policy_decision("allow");
            event.caller = Some(caller);
            audit_variables(&event)["AUDIT_PRINCIPAL"].clone()
        };

        assert_eq!(with(jwt_caller(Some("ada@example.com"), Some("Ada"))), "ada@example.com");
        assert_eq!(with(jwt_caller(None, Some("Ada Lovelace"))), "Ada Lovelace");
        assert_eq!(with(jwt_caller(None, None)), "user-123");
        assert_eq!(with(jwt_caller(Some(""), None)), "user-123", "an empty claim is skipped");

        let api_key =
            crate::delegation_vault::audit::build_caller_context(&crate::source_auth::AuthenticatedIdentity::ApiKey {
                key_name: "billing-bot".to_string(),
            });
        let mut event = policy_decision("allow");
        event.caller = Some(api_key);
        let variables = audit_variables(&event);
        assert_eq!(variables["AUDIT_PRINCIPAL"], "billing-bot");
        assert_eq!(variables["AUDIT_AUTH_METHOD"], "api_key");
        assert_eq!(variables["AUDIT_PRINCIPAL_EMAIL"], "");
    }

    #[test]
    fn a_decision_without_caller_context_has_an_empty_principal() {
        let mut event = policy_decision("deny");
        event.caller = None;
        let variables = audit_variables(&event);

        assert_eq!(variables["AUDIT_PRINCIPAL"], "");
        assert_eq!(variables["AUDIT_AUTH_METHOD"], "");
        assert_eq!(variables["AUDIT_POLICY_NAME"], "Deny unknown callers", "policy fields do not need a caller");
    }

    #[test]
    fn policy_name_falls_back_to_the_policy_package() {
        let mut event = policy_decision("allow");
        if let DelegationAuditAction::PolicyDecision {
            policy_name,
            policy_version,
            policy_content_hash,
            ..
        } = &mut event.event
        {
            *policy_name = None;
            *policy_version = None;
            *policy_content_hash = None;
        }
        let variables = audit_variables(&event);

        assert_eq!(variables["AUDIT_POLICY_NAME"], "surface.policy");
        assert_eq!(variables["AUDIT_POLICY_VERSION"], "", "an unversioned policy has no version");
        assert_eq!(variables["AUDIT_POLICY_CONTENT_HASH"], "");
    }

    #[test]
    fn every_audit_variable_is_offered_to_audit_templates() {
        let produced: HashSet<String> = audit_variables(&policy_decision("deny"))
            .into_keys()
            .collect();
        let offered: HashSet<String> =
            crate::integrations::runtime_variables::get_variable_names_for_category(AUDIT_CATEGORY)
                .into_iter()
                .collect();

        let unregistered: Vec<_> = produced
            .difference(&offered)
            .collect();
        assert!(unregistered.is_empty(), "variables templates cannot use: {unregistered:?}");
        let audit_only: HashSet<String> = offered
            .into_iter()
            .filter(|name| name.starts_with("AUDIT_"))
            .collect();
        let never_set: Vec<_> = audit_only
            .difference(&produced)
            .collect();
        assert!(never_set.is_empty(), "offered variables that are never set: {never_set:?}");
    }

    #[test]
    fn only_active_appliance_wide_audit_integrations_receive_records() {
        assert!(receives_audit_records(&integration(Some("audit"), "active", None)));

        assert!(!receives_audit_records(&integration(Some("audit"), "disabled", None)));
        assert!(!receives_audit_records(&integration(Some("audit"), "active", Some("tenant-a"))));
        assert!(!receives_audit_records(&integration(Some("gateway"), "active", None)));
        assert!(!receives_audit_records(&integration(None, "active", None)));

        for integration_type in ["stream", "webhook", "email", "slack"] {
            let mut typed = integration(Some("audit"), "active", None);
            typed.integration_type = integration_type.to_string();
            assert!(receives_audit_records(&typed), "{integration_type}");
        }
    }

    #[test]
    fn is_audit_integration_matches_the_category_only() {
        assert!(is_audit_integration(&integration(Some("audit"), "disabled", Some("tenant-a"))));
        assert!(!is_audit_integration(&integration(Some("x402"), "active", None)));
        assert!(!is_audit_integration(&integration(None, "active", None)));
    }

    /// Adding a `DelegationAuditAction` variant fails this match until the
    /// variant is added to [`every_action`] as well.
    fn listed(action: &DelegationAuditAction) {
        match action {
            DelegationAuditAction::ConsentGranted
            | DelegationAuditAction::TokenInjected
            | DelegationAuditAction::TokenRefreshed
            | DelegationAuditAction::RefreshFailed
            | DelegationAuditAction::ConsentRequired
            | DelegationAuditAction::TokenRevoked
            | DelegationAuditAction::UserTokensRevoked
            | DelegationAuditAction::TokenNotFound
            | DelegationAuditAction::VpInjected
            | DelegationAuditAction::ElicitationSent
            | DelegationAuditAction::ElicitationAccepted
            | DelegationAuditAction::ElicitationDeclined
            | DelegationAuditAction::ElicitationCancelled
            | DelegationAuditAction::ElicitationTimedOut
            | DelegationAuditAction::PolicyDecision { .. }
            | DelegationAuditAction::TrustCheck { .. }
            | DelegationAuditAction::TraceTerminated { .. }
            | DelegationAuditAction::PaymentEvent(_)
            | DelegationAuditAction::AuthFailed { .. }
            | DelegationAuditAction::RateLimited { .. }
            | DelegationAuditAction::RequestRejected { .. }
            | DelegationAuditAction::IdentityBindingFailed { .. }
            | DelegationAuditAction::IdentityBindingVerified { .. }
            | DelegationAuditAction::DelegationFailed { .. }
            | DelegationAuditAction::RequestFailed { .. }
            | DelegationAuditAction::RequestCompleted { .. } => {}
        }
    }

    fn every_action() -> Vec<DelegationAuditAction> {
        vec![
            DelegationAuditAction::ConsentGranted,
            DelegationAuditAction::TokenInjected,
            DelegationAuditAction::TokenRefreshed,
            DelegationAuditAction::RefreshFailed,
            DelegationAuditAction::ConsentRequired,
            DelegationAuditAction::TokenRevoked,
            DelegationAuditAction::UserTokensRevoked,
            DelegationAuditAction::TokenNotFound,
            DelegationAuditAction::VpInjected,
            DelegationAuditAction::ElicitationSent,
            DelegationAuditAction::ElicitationAccepted,
            DelegationAuditAction::ElicitationDeclined,
            DelegationAuditAction::ElicitationCancelled,
            DelegationAuditAction::ElicitationTimedOut,
            policy_decision("allow").event,
            DelegationAuditAction::TrustCheck {
                leg: "caller".to_string(),
                authority_id: None,
                entity_id: None,
                ok: true,
                error_code: None,
            },
            DelegationAuditAction::TraceTerminated {
                own_trace_id: "own".to_string(),
                downstream_trace_id: "downstream".to_string(),
                flow: "access_point".to_string(),
            },
            DelegationAuditAction::PaymentEvent(Box::new(PaymentEventDetails {
                rail: PaymentRail::X402,
                stage: PaymentStage::Settled,
                transaction_id: "tx-1".to_string(),
                amount: None,
                currency: None,
                method: None,
                payer: None,
                error: None,
                delegated: false,
                payment_gateway_id: None,
                payment_surface_id: None,
                remote_status: None,
            })),
            DelegationAuditAction::AuthFailed {
                scheme: AuthScheme::Jwt,
                reason: "expired".to_string(),
                blocking: true,
                client_ip: None,
            },
            DelegationAuditAction::RateLimited {
                scope: RateLimitScope::Surface,
                retry_after_ms: None,
            },
            DelegationAuditAction::RequestRejected {
                stage: RejectionStage::Routing,
                reason: RejectionReason::NoRoute,
                http_status: 404,
                rpc_error_code: None,
            },
            DelegationAuditAction::IdentityBindingFailed {
                outcome: IdentityBindingFailure::Absent,
                agent_did: None,
                issuer_gateway: None,
                error_detail: None,
            },
            DelegationAuditAction::IdentityBindingVerified {
                agent_did: "did:web:agent.example".to_string(),
                issuer_gateway: None,
                assurance: None,
            },
            DelegationAuditAction::DelegationFailed {
                reason: DelegationFailureReason::CredentialsUnavailable,
                provider_id: None,
            },
            DelegationAuditAction::RequestFailed {
                outcome: RequestFailureOutcome::UpstreamError,
                target_kind: TargetKind::Http,
                upstream_status: Some(502),
                latency_ms: 10,
            },
            DelegationAuditAction::RequestCompleted {
                target_kind: TargetKind::Http,
                upstream_status: 200,
                latency_ms: 10,
                request_bytes: 0,
                response_bytes: 0,
                ucp_op: None,
                variant_alias: None,
            },
        ]
    }

    fn category_event_types(category: &crate::config::IntegrationCategory) -> Vec<String> {
        category.metadata["event_types"]
            .as_array()
            .expect("the audit category lists its event types")
            .iter()
            .map(|event| {
                event["event_type"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn audit_category_lists_every_audit_record_category_the_gateway_produces() {
        let unproduced = ["delegation_failed", "request_failed", "request_completed"];
        let actions = every_action();
        actions
            .iter()
            .for_each(listed);
        let produced: HashSet<String> = actions
            .iter()
            .map(action_category)
            .filter(|category| !unproduced.contains(category))
            .map(|category| format!("audit.{category}"))
            .collect();

        let category = audit_integration_category();
        let listed_types = category_event_types(&category);
        let listed_set: HashSet<String> = listed_types
            .iter()
            .cloned()
            .collect();

        assert_eq!(category.enum_value, "audit");
        assert_eq!(listed_types.len(), listed_set.len(), "event types are unique");
        assert_eq!(listed_set, produced, "every audit record category has exactly one event type");
    }

    #[test]
    fn audit_category_lists_the_group_of_each_event_type() {
        let category = audit_integration_category();
        let events = category.metadata["event_types"]
            .as_array()
            .unwrap();
        let group_of = |event_type: &str| {
            events
                .iter()
                .find(|event| event["event_type"] == event_type)
                .and_then(|event| event["group"].as_str())
                .map(str::to_string)
        };
        assert_eq!(group_of("audit.policy_decision").as_deref(), Some("policies"));
        assert_eq!(group_of("audit.token_injected").as_deref(), Some("delegation"));
        assert!(
            events
                .iter()
                .all(|event| event["group"].is_string())
        );
    }

    #[test]
    fn example_gateway_config_carries_the_built_in_audit_category() {
        let example: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config/examples/gateway.example.json"
        )))
        .unwrap();
        let shipped = example["integration"]["categories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|category| category["enum_value"] == AUDIT_CATEGORY)
            .expect("gateway.example.json offers the audit category");

        assert_eq!(*shipped, serde_json::to_value(audit_integration_category()).unwrap());
    }

    #[test]
    fn default_integration_config_offers_the_audit_category() {
        let config = crate::config::IntegrationConfig::default_config();
        assert!(
            config
                .categories
                .iter()
                .any(|category| category.enum_value == AUDIT_CATEGORY)
        );
    }
}
