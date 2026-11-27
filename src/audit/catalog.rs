//! The governance audit event catalog: every event a sink can select and the
//! group it is listed under.

use serde::Serialize;

use AuditEventGroup::{Auth, Delegation, Identity, KeyManagement, Payments, Policies, Requests, Trace, Trust};

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
    KeyManagement,
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
            KeyManagement => "key_management",
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
            KeyManagement => "Key management",
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
        "connector_call",
        "Connector Call",
        "A call through a connector's Transit Point was forwarded with a grant, or refused before it was",
        Delegation,
    ),
    event(
        "consent_granted",
        "Consent Granted",
        "A user completed the OAuth consent flow and a delegation token was stored",
        Delegation,
    ),
    event(
        "consent_expired",
        "Consent Expired",
        "A consent reached its time limit and the stored credential was removed; not a revocation",
        Delegation,
    ),
    event(
        "consent_limited",
        "Consent Limited",
        "An operator brought the end of one stored consent forward through the management API; also recorded wherever Token Revoked is selected",
        Delegation,
    ),
    event("token_revoked", "Token Revoked", "A delegation token was revoked through the management API", Delegation),
    event("user_tokens_revoked", "User Tokens Revoked", "Every delegation token for a user was revoked", Delegation),
    event(
        "payment",
        "Payment Event",
        "An agent-pay payment event (challenge, paid, held for review, rejected, unavailable); legacy x402/MPP settlement records may still appear",
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
        "A request's or a Fabric answer's identity binding Verifiable Presentation was missing or could not be verified",
        Identity,
    ),
    event(
        "identity_binding_verified",
        "Identity Binding Verified",
        "A request's or a Fabric answer's identity binding Verifiable Presentation was verified",
        Identity,
    ),
    event(
        "rate_limited",
        "Rate Limited",
        "A request was refused because a surface rate limit, a Transit Point's per-caller rate limit, SSE session cap \
         or Fabric stream capacity was reached",
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
        "target_auth_changed",
        "Target Authentication Changed",
        "The credential a surface sends to its Target or a Transit Point was added, changed or removed",
        Auth,
    ),
    event(
        "secret_force_deleted",
        "Secret Force-Deleted",
        "A secret was deleted with force, whether or not surfaces, providers or proxies still used it",
        Auth,
    ),
    event(
        "authority_force_deleted",
        "Authority Force-Deleted",
        "An Authority was deleted with force, whether or not Trust Checks or Trust Recorder entries still used it",
        Trust,
    ),
    event(
        "delegation_failed",
        "Delegation Failed",
        "An OAuth consent start or callback was refused, with the reason",
        Delegation,
    ),
    event(
        "mcp_proxy_pin_changed",
        "MCP Proxy Pin Changed",
        "A surface save pinned a Transit Point's grant binding to its MCP Proxy as the proxy is now",
        Delegation,
    ),
    event(
        "browser_origins_changed",
        "Browser Origins Changed",
        "A surface save changed the browser origins whose pages may call the surface",
        Auth,
    ),
    event(
        "trust_agent_connection_created",
        "Trust Agent Connection Created",
        "A Verifiable Trust Agent connection was added",
        KeyManagement,
    ),
    event(
        "trust_agent_connection_updated",
        "Trust Agent Connection Updated",
        "A Verifiable Trust Agent connection was edited, enabled or disabled",
        KeyManagement,
    ),
    event(
        "trust_agent_connection_deleted",
        "Trust Agent Connection Deleted",
        "A Verifiable Trust Agent connection was deleted",
        KeyManagement,
    ),
    event(
        "trust_agent_pairing_started",
        "Trust Agent Pairing Started",
        "Pairing with a Verifiable Trust Agent began and its grant request was issued",
        KeyManagement,
    ),
    event(
        "trust_agent_connection_verified",
        "Trust Agent Connection Verified",
        "The gateway checked a connection's grant on its trust agent, with the state it found",
        KeyManagement,
    ),
    event(
        "trust_agent_connection_revoked",
        "Trust Agent Connection Revoked",
        "The gateway stopped signing through a Verifiable Trust Agent connection",
        KeyManagement,
    ),
    event(
        "trust_agent_signing_key_provisioned",
        "Trust Agent Signing Key Provisioned",
        "A signing key was minted in a trust agent and made a connection's active key",
        KeyManagement,
    ),
    event(
        "trust_agent_signing_key_rotated",
        "Trust Agent Signing Key Rotated",
        "A connection's active signing key was replaced",
        KeyManagement,
    ),
    event(
        "trust_agent_control_key_rotated",
        "Trust Agent Control Key Rotated",
        "A control key rotation, of a connection or of the [vta] block, finished, rolled back, was cancelled or was left running",
        KeyManagement,
    ),
    event(
        "trust_agent_change_refused",
        "Trust Agent Change Refused",
        "A change to a trust agent connection or key was refused (401, 403, 409, or 404 for a connection the caller may not see)",
        KeyManagement,
    ),
    event(
        "signing_change_refused",
        "Signing Change Refused",
        "A surface, issuer or settings save that changed a signing choice was refused for lack of key_management.edit",
        KeyManagement,
    ),
    event(
        "policy_input_capture_started",
        "Policy Input Capture Started",
        "A dashboard user started watching the live, masked policy input of a surface; also recorded wherever Policy Input Capture Stopped is selected",
        Policies,
    ),
    event(
        "policy_input_capture_stopped",
        "Policy Input Capture Stopped",
        "A dashboard user's policy input capture on a surface ended, with why; also recorded wherever Policy Input Capture Started is selected",
        Policies,
    ),
];

/// The delegation events that are written to the gateway log and offered to
/// no audit sink: what the gateway does with a stored credential on each call.
/// What a person or an operator decided (a consent given, ended, refused or
/// revoked) is in [`AUDIT_EVENTS`].
pub const LOGGED_EVENTS: &[&str] = &[
    "token_injected",
    "token_refreshed",
    "refresh_failed",
    "consent_required",
    "token_not_found",
    "elicitation_sent",
    "elicitation_accepted",
    "elicitation_declined",
    "elicitation_cancelled",
    "elicitation_timed_out",
];

/// Events a sink receives together: one that selects the first also receives
/// the second, so a selection made before the second existed still records
/// it. An operator's limit on a consent ends access sooner, as a revocation
/// does, and a consent that ends at its time limit is the end of one that was
/// granted. A policy input capture's start and end are recorded together, so a
/// sink never holds one without the other.
pub const RECEIVED_WITH: &[(&str, &str)] = &[
    ("token_revoked", "consent_limited"),
    ("consent_granted", "consent_expired"),
    ("policy_input_capture_started", "policy_input_capture_stopped"),
    ("policy_input_capture_stopped", "policy_input_capture_started"),
];

/// Warns that `selection` names `dropped`, events the gateway no longer
/// audits: it is used without them, and they are no longer delivered. Each
/// is now a line of the `credential_delegation` log target. Nothing is said
/// when none was dropped.
pub fn warn_logged_only(
    selection: &str,
    dropped: &[&str],
) {
    if dropped.is_empty() {
        return;
    }
    tracing::warn!(
        dropped = %dropped.join(","),
        "{selection} names audit events the gateway now only writes to its log, under the credential_delegation \
         log target; they are no longer recorded or delivered through it"
    );
}

/// Whether `category` is one of the [`LOGGED_EVENTS`].
pub fn is_logged_only(category: &str) -> bool {
    LOGGED_EVENTS.contains(&category)
}

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
        for group in [Policies, Trust, Identity, Trace, Auth, Delegation, Payments, Requests, KeyManagement] {
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

    /// What a person or an operator decided about delegated access is audited;
    /// what the gateway does with a credential on each call is logged.
    #[test]
    fn the_delegation_events_are_split_between_the_audit_and_the_log() {
        let audited: Vec<&str> = AUDIT_EVENTS
            .iter()
            .filter(|event| event.group == Delegation)
            .map(|event| event.category)
            .collect();
        assert_eq!(
            audited,
            [
                "connector_call",
                "consent_granted",
                "consent_expired",
                "consent_limited",
                "token_revoked",
                "user_tokens_revoked",
                "delegation_failed",
                "mcp_proxy_pin_changed"
            ]
        );
        assert_eq!(
            LOGGED_EVENTS,
            [
                "token_injected",
                "token_refreshed",
                "refresh_failed",
                "consent_required",
                "token_not_found",
                "elicitation_sent",
                "elicitation_accepted",
                "elicitation_declined",
                "elicitation_cancelled",
                "elicitation_timed_out"
            ]
        );
        for logged in LOGGED_EVENTS {
            assert!(is_logged_only(logged), "{logged}");
            assert_eq!(event_bit(logged), None, "{logged} can be selected by no audit sink");
        }
        for event in AUDIT_EVENTS {
            assert!(!is_logged_only(event.category), "{}", event.category);
        }
        assert!(!is_logged_only("not_an_event"));
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
            "policy_input_capture_started",
            "policy_input_capture_stopped",
        ] {
            assert_eq!(group_of(policies), Some(AuditEventGroup::Policies), "{policies}");
        }
        assert_eq!(group_of("trust_check"), Some(AuditEventGroup::Trust));
        assert_eq!(group_of("vp_injected"), Some(AuditEventGroup::Identity));
        assert_eq!(group_of("trace_terminated"), Some(AuditEventGroup::Trace));
        assert_eq!(group_of("payment"), Some(AuditEventGroup::Payments));
        assert_eq!(group_of("auth_failed"), Some(AuditEventGroup::Auth));
        assert_eq!(group_of("target_auth_changed"), Some(AuditEventGroup::Auth));
        assert_eq!(group_of("secret_force_deleted"), Some(AuditEventGroup::Auth));
        assert_eq!(group_of("browser_origins_changed"), Some(AuditEventGroup::Auth));
        assert_eq!(group_of("identity_binding_failed"), Some(AuditEventGroup::Identity));
        assert_eq!(group_of("identity_binding_verified"), Some(AuditEventGroup::Identity));
        for security in [
            "trust_agent_connection_created",
            "trust_agent_connection_updated",
            "trust_agent_connection_deleted",
            "trust_agent_pairing_started",
            "trust_agent_connection_verified",
            "trust_agent_connection_revoked",
            "trust_agent_signing_key_provisioned",
            "trust_agent_signing_key_rotated",
            "trust_agent_control_key_rotated",
            "trust_agent_change_refused",
            "signing_change_refused",
        ] {
            assert_eq!(group_of(security), Some(AuditEventGroup::KeyManagement), "{security}");
        }
        for request in ["request_rejected", "rate_limited"] {
            assert_eq!(group_of(request), Some(AuditEventGroup::Requests), "{request}");
        }
        for delegation in [
            "connector_call",
            "token_revoked",
            "user_tokens_revoked",
            "consent_expired",
            "consent_limited",
            "consent_granted",
            "mcp_proxy_pin_changed",
        ] {
            assert_eq!(group_of(delegation), Some(AuditEventGroup::Delegation), "{delegation}");
        }
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
