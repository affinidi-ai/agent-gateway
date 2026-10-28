//! Audit records as integration events: the template variables a record offers and
//! publishing one record to an integration that receives it. Delivery order, retries and
//! selection live in [`crate::audit`].

use std::collections::HashMap;

use anyhow::Context;
use futures::future::BoxFuture;

use crate::delegation_vault::audit::{
    AuditCallerContext, DelegationAuditAction, DelegationAuditEvent, action_category,
};
use crate::integrations::delivery::dispatch::{AuditReceiver, current_routes, deliver};
use crate::integrations::delivery::values::event_values;
use crate::integrations::events::find_event;

/// The catalog event of an audit record: `audit.<category>`, e.g. `audit.policy_decision`.
pub fn audit_event_type(event: &DelegationAuditEvent) -> String {
    format!("audit.{}", action_category(&event.event))
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
        ("AUDIT_SURFACE_VARIANT".to_string(), text(&event.surface_variant)),
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

/// One audit record's delivery values, computed once and shared by every subscribed
/// integration.
#[derive(Debug, Clone)]
pub(crate) struct AuditDelivery {
    values: HashMap<String, String>,
}

impl AuditDelivery {
    pub(crate) fn values(&self) -> &HashMap<String, String> {
        &self.values
    }

    pub(crate) fn from_event(event: &DelegationAuditEvent) -> Self {
        let variables = audit_variables(event);
        let values = match find_event(&audit_event_type(event)) {
            Some(catalog_event) => {
                event_values(catalog_event, variables, crate::storage::settings_store::global_appliance_id_override())
            }
            None => variables,
        };
        Self { values }
    }
}

/// The integration no longer receives audit records: it was disabled, its endpoint was
/// disabled, or its event set no longer holds audit events.
#[derive(Debug, thiserror::Error)]
#[error("integration {0} no longer receives audit records")]
pub(crate) struct NotReceiving(String);

/// Publishes one record to an integration that receives audit records, counted in
/// `agent_gateway_audit_forward_total`. An integration that no longer receives them refuses
/// it with [`NotReceiving`], counted as `not_receiving`, so it is never reported as
/// delivered: its reader retries until the dispatcher pauses the sink, which lets the record
/// go and counts it as paused.
pub(crate) fn publish_audit_delivery(
    integration_id: String,
    delivery: AuditDelivery,
) -> BoxFuture<'static, anyhow::Result<()>> {
    Box::pin(async move {
        let routes = current_routes()
            .await
            .with_context(|| format!("loading audit integration {integration_id}"))?;
        publish_audit_record(routes.audit_receiver(&integration_id), &integration_id, &delivery).await
    })
}

/// [`publish_audit_delivery`] for the integration's audit route, `None` when it no longer
/// receives audit records.
async fn publish_audit_record(
    receiver: Option<AuditReceiver>,
    integration_id: &str,
    delivery: &AuditDelivery,
) -> anyhow::Result<()> {
    use crate::metrics::backends::prometheus::track_audit_forward;

    let Some(receiver) = receiver else {
        track_audit_forward("not_receiving", Some(integration_id));
        return Err(NotReceiving(integration_id.to_string()).into());
    };
    match deliver(&receiver.route, delivery.values()).await {
        Ok(()) => {
            track_audit_forward("delivered", Some(integration_id));
            Ok(())
        }
        Err(e) => {
            track_audit_forward("failed", Some(integration_id));
            Err(e.context(format!("publishing to audit integration {integration_id}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::events::{
        Actor, AuthScheme, DelegationFailureReason, IdentityBindingFailure, PolicyChangeSource, RateLimitScope,
        RejectionReason, RejectionStage, RequestFailureOutcome, TargetKind,
    };
    use crate::delegation_vault::audit::{
        PaymentEventDetails, PaymentRail, PaymentStage, PolicyChangeDetails, audit_event,
    };
    use std::collections::HashSet;

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
        event.surface_variant = Some("beta".to_string());
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
        let stopped = uuid::Uuid::new_v4().to_string();

        let error = publish_audit_record(None, &stopped, &delivery)
            .await
            .unwrap_err();

        assert!(error.is::<NotReceiving>(), "{error:#}");
        assert_eq!(forwards("not_receiving", &stopped), 1);
        assert_eq!(forwards("failed", &stopped), 0);
        assert_eq!(forwards("delivered", &stopped), 0);
    }

    #[test]
    fn a_delivery_carries_the_record_and_the_event_name_summary_and_data() {
        let event = policy_decision("deny");

        let delivery = AuditDelivery::from_event(&event);

        let values = delivery.values();
        assert_eq!(values["EVENT_TYPE"], "audit.policy_decision");
        assert_eq!(values["EVENT_NAME"], "Policy Decision");
        assert_eq!(
            values["EVENT_SUMMARY"],
            "Policy Decision on surface Billing agent: deny by policy Deny unknown callers (caller not recognised) for ada@example.com"
        );
        assert_eq!(values["EVENT_DATA"], values["AUDIT_RECORD"]);
        assert_eq!(values["AUDIT_DECISION"], "deny");
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
        assert_eq!(
            variables
                .get("AUDIT_SURFACE_VARIANT")
                .map(String::as_str),
            Some("beta")
        );
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
        assert_eq!(
            variables
                .get("AUDIT_SURFACE_VARIANT")
                .map(String::as_str),
            Some(""),
            "outside a surface request the variant is empty"
        );
        assert_eq!(variables["AUDIT_VP_FINGERPRINT"], "");
    }

    #[test]
    fn the_surface_variant_variable_carries_the_special_values_as_they_are() {
        for variant in ["_base_", "_unknown_"] {
            let mut event = policy_decision("deny");
            event.surface_variant = Some(variant.to_string());
            assert_eq!(
                audit_variables(&event)
                    .get("AUDIT_SURFACE_VARIANT")
                    .map(String::as_str),
                Some(variant)
            );
        }
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
        let offered: HashSet<String> = find_event("audit.policy_decision")
            .expect("catalog event")
            .variables
            .iter()
            .map(|name| name.to_string())
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
            | DelegationAuditAction::RequestCompleted { .. }
            | DelegationAuditAction::PolicyCreated(_)
            | DelegationAuditAction::PolicyUpdated(_)
            | DelegationAuditAction::PolicyDeleted(_)
            | DelegationAuditAction::PolicyAttached(_)
            | DelegationAuditAction::PolicyDetached(_)
            | DelegationAuditAction::PolicyAttachmentChanged(_)
            | DelegationAuditAction::PolicyChangeRefused(_) => {}
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
                http_status: Some(404),
                rpc_error_code: None,
                requested_variant: None,
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
            },
            DelegationAuditAction::PolicyCreated(policy_change()),
            DelegationAuditAction::PolicyUpdated(policy_change()),
            DelegationAuditAction::PolicyDeleted(policy_change()),
            DelegationAuditAction::PolicyAttached(policy_change()),
            DelegationAuditAction::PolicyDetached(policy_change()),
            DelegationAuditAction::PolicyAttachmentChanged(policy_change()),
            DelegationAuditAction::PolicyChangeRefused(policy_change()),
        ]
    }

    fn policy_change() -> Box<PolicyChangeDetails> {
        Box::new(PolicyChangeDetails::new(Actor::user("u-1"), PolicyChangeSource::Api))
    }

    #[test]
    fn the_event_catalog_lists_every_audit_record_category_the_gateway_produces() {
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

        let listed_ids: HashSet<String> = crate::integrations::events::catalog()
            .iter()
            .filter(|event| event.family == "audit")
            .map(|event| event.id.clone())
            .collect();

        assert_eq!(listed_ids, produced, "every audit record category has exactly one catalog event");
    }

    #[test]
    fn every_audit_event_sits_in_its_audit_group() {
        let group_of = |id: &str| find_event(id).and_then(|event| event.group);
        assert_eq!(group_of("audit.policy_decision"), Some("policies"));
        assert_eq!(group_of("audit.token_injected"), Some("delegation"));
        assert!(
            crate::integrations::events::catalog()
                .iter()
                .filter(|event| event.family == "audit")
                .all(|event| event.group.is_some())
        );
    }
}
