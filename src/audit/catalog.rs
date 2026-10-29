//! The governance audit event catalog: every event a sink can select and the
//! group it is listed under.

use serde::Serialize;

use AuditEventGroup::{Auth, Configuration, Delegation, Identity, Payments, Policies, Requests, Trace, Trust};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventGroup {
    Policies,
    Trust,
    Identity,
    Trace,
    Auth,
    Delegation,
    Payments,
    Requests,
    Configuration,
}

impl AuditEventGroup {
    pub fn id(self) -> &'static str {
        match self {
            Policies => "policies",
            Trust => "trust",
            Identity => "identity",
            Trace => "trace",
            Auth => "auth",
            Delegation => "delegation",
            Payments => "payments",
            Requests => "requests",
            Configuration => "configuration",
        }
    }

    /// The heading the dashboard shows for the group.
    pub fn label(self) -> &'static str {
        match self {
            Policies => "Policies",
            Trust => "Trust",
            Identity => "Identity",
            Trace => "Trace",
            Auth => "Auth",
            Delegation => "Delegation",
            Payments => "Payments",
            Requests => "Requests",
            Configuration => "Configuration",
        }
    }
}

#[derive(Debug)]
pub struct AuditEventSpec {
    pub category: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub group: AuditEventGroup,
}

const fn event(
    category: &'static str,
    name: &'static str,
    description: &'static str,
    group: AuditEventGroup,
) -> AuditEventSpec {
    AuditEventSpec {
        category,
        name,
        description,
        group,
    }
}

/// Every selectable event.
pub const AUDIT_EVENTS: &[AuditEventSpec] = &[
    event(
        "policy_decision",
        "Policy Decision",
        "A gateway, surface, MCP-tool or response OPA policy allowed or denied a request",
        Policies,
    ),
    event("trust_check", "Trust Check", "A TRQP trust-check outcome for the caller or target leg", Trust),
    event("trace_terminated", "Trace Terminated", "A surface terminated the end-to-end trace at its egress", Trace),
    event(
        "vp_injected",
        "VP Injected",
        "A signed identity Verifiable Presentation was injected into a proxied request or response",
        Identity,
    ),
    event(
        "token_injected",
        "Token Injected",
        "A delegated credential from the vault was injected on the caller's behalf",
        Delegation,
    ),
    event(
        "token_refreshed",
        "Token Refreshed",
        "An expired delegated credential was refreshed and injected",
        Delegation,
    ),
    event(
        "refresh_failed",
        "Refresh Failed",
        "A delegated credential could not be refreshed, so consent is required again",
        Delegation,
    ),
    event(
        "consent_granted",
        "Consent Granted",
        "A user completed the OAuth consent flow and a delegation token was stored",
        Delegation,
    ),
    event(
        "consent_required",
        "Consent Required",
        "The caller was asked to grant consent before the request could proceed",
        Delegation,
    ),
    event("token_revoked", "Token Revoked", "A delegation token was revoked through the management API", Delegation),
    event("user_tokens_revoked", "User Tokens Revoked", "Every delegation token for a user was revoked", Delegation),
    event("token_not_found", "Token Not Found", "A delegation token lookup found no match", Delegation),
    event("elicitation_sent", "Elicitation Sent", "An MCP elicitation request was sent to the client", Delegation),
    event("elicitation_accepted", "Elicitation Accepted", "The client accepted an MCP elicitation", Delegation),
    event("elicitation_declined", "Elicitation Declined", "The client declined an MCP elicitation", Delegation),
    event("elicitation_cancelled", "Elicitation Cancelled", "The client cancelled an MCP elicitation", Delegation),
    event(
        "elicitation_timed_out",
        "Elicitation Timed Out",
        "The client did not answer an MCP elicitation in time",
        Delegation,
    ),
    event(
        "payment",
        "Payment Event",
        "An x402 or MPP payment lifecycle event (challenge, verification, settlement)",
        Payments,
    ),
    event(
        "auth_failed",
        "Authentication Failed",
        "A caller's JWT, API key, DID Auth session, mTLS certificate or MCP resource token was not accepted",
        Auth,
    ),
    event(
        "identity_binding_failed",
        "Identity Binding Failed",
        "A request's identity binding Verifiable Presentation was missing or could not be verified",
        Identity,
    ),
    event(
        "identity_binding_verified",
        "Identity Binding Verified",
        "A request's identity binding Verifiable Presentation was verified",
        Identity,
    ),
    event(
        "rate_limited",
        "Rate Limited",
        "A request was refused because a surface rate limit, SSE session cap or Fabric stream capacity was reached",
        Requests,
    ),
    event(
        "request_rejected",
        "Request Rejected",
        "A request was refused at routing, admission or forwarding before it reached the target",
        Requests,
    ),
    event("policy_created", "Policy Created", "A policy definition was created", Policies),
    event("policy_updated", "Policy Updated", "A policy definition was changed, or its owner was reassigned", Policies),
    event("policy_deleted", "Policy Deleted", "A policy definition was deleted", Policies),
    event(
        "policy_attached",
        "Policy Attached",
        "A policy was added to a surface, gateway or appliance-wide plane",
        Policies,
    ),
    event(
        "policy_detached",
        "Policy Detached",
        "A policy was removed from a surface, gateway or appliance-wide plane",
        Policies,
    ),
    event(
        "policy_attachment_changed",
        "Policy Attachment Changed",
        "An attached policy was switched between enforced and monitor-only, or enabled and disabled",
        Policies,
    ),
    event(
        "policy_change_refused",
        "Policy Change Refused",
        "A change to a policy, or to where a policy applies, was refused",
        Policies,
    ),
    event(
        "delegation_failed",
        "Delegation Failed",
        "A credential could not be obtained for a delegation binding: the signed assertion or the token endpoint failed",
        Delegation,
    ),
    event(
        "verification_strategy_changed",
        "Verification Strategy Changed",
        "A JWT verification strategy, a trust anchor for caller tokens, was created, updated, re-pinned or deleted",
        Configuration,
    ),
    event(
        "credential_provider_changed",
        "Credential Provider Changed",
        "A credential provider was created, updated or deleted",
        Configuration,
    ),
    event(
        "target_auth_changed",
        "Target Authentication Changed",
        "The credential a surface presents to its Target was set, changed or removed",
        Configuration,
    ),
];

/// The event's bit in a selection bitmap: its position in [`AUDIT_EVENTS`].
pub fn event_bit(category: &str) -> Option<u32> {
    AUDIT_EVENTS
        .iter()
        .position(|event| event.category == category)
        .and_then(|position| u32::try_from(position).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn a_group_id_is_its_serialized_name() {
        for group in [Policies, Trust, Identity, Trace, Auth, Delegation, Payments, Requests] {
            assert_eq!(serde_json::to_value(group).expect("serializes"), group.id());
        }
    }

    #[test]
    fn each_event_has_its_own_bit_below_64() {
        let bits: HashSet<u32> = AUDIT_EVENTS
            .iter()
            .map(|event| event_bit(event.category).expect("catalog event has a bit"))
            .collect();
        assert_eq!(bits.len(), AUDIT_EVENTS.len());
        assert!(
            bits.iter()
                .all(|bit| *bit < 64),
            "{} events do not fit in a u64",
            AUDIT_EVENTS.len()
        );
    }

    #[test]
    fn unknown_category_has_no_bit() {
        assert_eq!(event_bit("not_an_event"), None);
        assert_eq!(event_bit(""), None);
    }

    #[test]
    fn categories_are_unique() {
        assert!(!AUDIT_EVENTS.is_empty());
        let categories: HashSet<&str> = AUDIT_EVENTS
            .iter()
            .map(|event| event.category)
            .collect();
        assert_eq!(categories.len(), AUDIT_EVENTS.len());
    }

    #[test]
    fn events_are_listed_under_their_group() {
        let group_of = |category: &str| {
            AUDIT_EVENTS
                .iter()
                .find(|event| event.category == category)
                .map(|event| event.group)
        };
        for policies in [
            "policy_decision",
            "policy_created",
            "policy_updated",
            "policy_deleted",
            "policy_attached",
            "policy_detached",
            "policy_attachment_changed",
            "policy_change_refused",
        ] {
            assert_eq!(group_of(policies), Some(AuditEventGroup::Policies), "{policies}");
        }
        assert_eq!(group_of("trust_check"), Some(AuditEventGroup::Trust));
        assert_eq!(group_of("vp_injected"), Some(AuditEventGroup::Identity));
        assert_eq!(group_of("trace_terminated"), Some(AuditEventGroup::Trace));
        assert_eq!(group_of("payment"), Some(AuditEventGroup::Payments));
        assert_eq!(group_of("auth_failed"), Some(AuditEventGroup::Auth));
        assert_eq!(group_of("identity_binding_failed"), Some(AuditEventGroup::Identity));
        assert_eq!(group_of("identity_binding_verified"), Some(AuditEventGroup::Identity));
        for request in ["request_rejected", "rate_limited"] {
            assert_eq!(group_of(request), Some(AuditEventGroup::Requests), "{request}");
        }
        for delegation in [
            "token_injected",
            "token_refreshed",
            "token_not_found",
            "delegation_failed",
            "token_revoked",
            "user_tokens_revoked",
            "refresh_failed",
            "consent_required",
            "consent_granted",
            "elicitation_sent",
            "elicitation_accepted",
            "elicitation_declined",
            "elicitation_cancelled",
            "elicitation_timed_out",
        ] {
            assert_eq!(group_of(delegation), Some(AuditEventGroup::Delegation), "{delegation}");
        }
    }

    #[test]
    fn management_plane_trust_changes_are_listed_under_configuration() {
        for category in ["verification_strategy_changed", "credential_provider_changed", "target_auth_changed"] {
            let entry = AUDIT_EVENTS
                .iter()
                .find(|event| event.category == category)
                .unwrap_or_else(|| panic!("{category} is offered"));
            assert_eq!(entry.group, AuditEventGroup::Configuration, "{category}");
        }
        assert_eq!(AuditEventGroup::Configuration.label(), "Configuration");
    }

    #[test]
    fn record_types_the_gateway_does_not_produce_are_not_offered() {
        for unproduced in ["request_failed", "request_completed"] {
            assert_eq!(event_bit(unproduced), None, "{unproduced}");
        }
    }

    #[test]
    fn group_serializes_as_snake_case() {
        assert_eq!(serde_json::to_value(AuditEventGroup::Payments).unwrap(), "payments");
    }
}
