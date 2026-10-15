//! The integration event catalog: every event the gateway delivers to integrations, the
//! group the dashboard lists it under, and the template variables its delivery fills.

use once_cell::sync::Lazy;
use serde::Serialize;

use crate::audit::catalog::AUDIT_EVENTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VariableSpec {
    pub name: &'static str,
    pub label: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrationEvent {
    pub id: String,
    pub name: String,
    pub description: String,
    pub family: &'static str,
    pub family_label: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_label: Option<&'static str>,
    pub variables: Vec<&'static str>,
}

/// Variables every delivery fills, whatever the event.
pub const COMMON_VARIABLES: &[&str] =
    &["EVENT_TYPE", "EVENT_NAME", "EVENT_SUMMARY", "EVENT_DATA", "TIMESTAMP", "APPLIANCE_ID"];

const fn var(
    name: &'static str,
    label: &'static str,
    description: &'static str,
) -> VariableSpec {
    VariableSpec { name, label, description }
}

const VARIABLES: &[VariableSpec] = &[
    var("EVENT_TYPE", "Event Type", "The event's id, such as gateway.created or audit.policy_decision"),
    var("EVENT_NAME", "Event Name", "The event's display name, such as Gateway Created"),
    var("EVENT_SUMMARY", "Event Summary", "A one-line description of what happened, written for people"),
    var(
        "EVENT_DATA",
        "Event Data",
        "The event's data as JSON. Used as an entire JSON string value (\"data\": \"${EVENT_DATA}\") it is embedded as a JSON object.",
    ),
    var("TIMESTAMP", "Timestamp", "RFC 3339 time the event occurred"),
    var(
        "APPLIANCE_ID",
        "Appliance ID",
        "Appliance ID set in System Settings (e.g. this appliance's id in Agent Watch); empty while none is set",
    ),
    var("OLD_STATE", "Old State", "The resource before the change, as JSON. Empty for a create."),
    var("NEW_STATE", "New State", "The resource after the change, as JSON. Empty for a delete."),
    var("GATEWAY_ID", "Gateway ID", "ID of the gateway"),
    var("GATEWAY_NAME", "Gateway Name", "Name of the gateway"),
    var("GATEWAY_DESCRIPTION", "Gateway Description", "Description of the gateway"),
    var("GATEWAY_DID", "Gateway DID", "DID of the gateway"),
    var("GATEWAY_TYPE", "Gateway Type", "Type of the gateway"),
    var("GATEWAY_STATUS", "Gateway Status", "Status of the gateway after the event"),
    var("GATEWAY_OLD_STATUS", "Previous Gateway Status", "Status of the gateway before the change"),
    var("USER_ID", "User ID", "ID of the user"),
    var("USERNAME", "Username", "Username of the user"),
    var("USER_EMAIL", "User Email", "Email of the user, when known"),
    var("USER_ROLE", "User Role", "Role of the user"),
    var("USER_STATUS", "User Status", "Status of the user"),
    var("CP_ID", "Connection Point ID", "ID of the connection point that received the message"),
    var("CP_NAME", "Connection Point Name", "Name of the connection point"),
    var("CP_DESCRIPTION", "Connection Point Description", "Description of the connection point"),
    var("GATEWAY", "Gateway", "ID of the connection point's gateway"),
    var("MEDIATOR_ID", "Mediator ID", "ID of the mediator the message arrived through"),
    var("MESSAGE_ID", "Message ID", "ID of the received message"),
    var("MESSAGE_TYPE", "Message Type", "DIDComm type of the received message"),
    var("FROM_DID", "Sender DID", "DID of the message sender"),
    var("MESSAGE_BODY", "Message Body", "Body of the received message, as JSON"),
    var("RECEIVED_AT", "Received At", "RFC 3339 time the message was received"),
    var("DATE", "Date", "Delivery date, YYYY-MM-DD"),
    var("TIME", "Time", "Delivery time, HH:MM:SS"),
    var("DATETIME", "Date and Time", "Delivery date and time, YYYY-MM-DD HH:MM:SS"),
    var("CORRELATION_ID", "Correlation ID", "ID correlating the payment's requests"),
    var("SURFACE_ID", "Surface ID", "ID of the Agent Surface that took the payment"),
    var("SURFACE_NAME", "Surface Name", "Name of the Agent Surface that took the payment"),
    var("TX_HASH", "Transaction Hash", "On-chain transaction hash"),
    var("AMOUNT", "Amount", "Amount paid"),
    var("NETWORK", "Network", "Network the payment settled on"),
    var("SETTLEMENT_METHOD", "Settlement Method", "How the payment was settled"),
    var("ERROR_MESSAGE", "Error Message", "Why the payment step failed"),
    var("SEVERITY", "Severity", "info or error"),
    var("TRANSACTIONS_DELETED", "Transactions Deleted", "Number of transactions the cleanup removed"),
    var("RETENTION_DAYS", "Retention Days", "Days transactions are kept before cleanup"),
    var("PAYMENT_METHOD", "Payment Method", "Payment method the caller used"),
    var("RESOURCE_URL", "Resource URL", "URL of the paid resource"),
    var("REFERENCE", "Reference", "Payment reference returned by the verifier"),
    var(
        "AUDIT_RECORD",
        "Audit Record",
        "The complete audit record as JSON, in the same shape as a VP Audit Log entry, including the signed VP. Used as an entire JSON string value (\"record\": \"${AUDIT_RECORD}\") it is embedded as a JSON object; inside other text it is inserted as JSON text.",
    ),
    var(
        "AUDIT_CATEGORY",
        "Audit Category",
        "Category of the audit record (policy_decision, trust_check, …). EVENT_TYPE carries the same value as audit.<category>.",
    ),
    var(
        "AUDIT_TRACE_ID",
        "Trace ID",
        "Request trace ID that correlates every audit record written for the same request",
    ),
    var("AUDIT_SURFACE_ID", "Surface ID", "ID of the Agent Surface the record belongs to"),
    var("AUDIT_SURFACE_NAME", "Surface Name", "Name of the Agent Surface the record belongs to"),
    var("AUDIT_PROTOCOL", "Protocol", "Protocol of the surface (a2a, mcp, …)"),
    var("AUDIT_AGENT_DID", "Agent DID", "DID of the agent the record was written for"),
    var(
        "AUDIT_VIA_FABRIC",
        "Via Fabric",
        "true when the request traversed the gateway-to-gateway fabric, otherwise false",
    ),
    var(
        "AUDIT_PRINCIPAL",
        "Principal",
        "The authenticated caller: their email, else display name, else the authenticated subject. Empty without an authenticated caller.",
    ),
    var(
        "AUDIT_PRINCIPAL_EMAIL",
        "Principal Email",
        "Email of the authenticated caller, when their credential carries one",
    ),
    var(
        "AUDIT_PRINCIPAL_NAME",
        "Principal Name",
        "Display name of the authenticated caller, when their credential carries one",
    ),
    var(
        "AUDIT_AUTH_METHOD",
        "Auth Method",
        "How the caller authenticated (jwt_bearer, api_key, did_auth, mtls, session, access_token); empty without an authenticated caller",
    ),
    var(
        "AUDIT_DECISION",
        "Policy Decision",
        "Policy decision (allow or deny) for policy_decision records; empty for other categories",
    ),
    var(
        "AUDIT_DENY_REASON",
        "Deny Reason",
        "Deny reason reported by the policy for denied policy_decision records; empty otherwise",
    ),
    var(
        "AUDIT_POLICY_NAME",
        "Policy Name",
        "Name of the policy that made the decision for policy_decision records; empty otherwise",
    ),
    var(
        "AUDIT_POLICY_VERSION",
        "Policy Version",
        "Version of the enforced policy revision for policy_decision records, when the policy is versioned",
    ),
    var(
        "AUDIT_POLICY_CONTENT_HASH",
        "Policy Content Hash",
        "sha256:<hex> hash of the exact Rego enforced for policy_decision records, when known",
    ),
    var("AUDIT_VP_JWT", "Signed VP", "Signed Verifiable Presentation (JWT) attached to the record"),
    var("AUDIT_VP_FINGERPRINT", "VP Fingerprint", "sha256:<hex> fingerprint of the signed VP attached to the record"),
];

const GATEWAY_VARIABLES: &[&str] = &[
    "OLD_STATE",
    "NEW_STATE",
    "GATEWAY_ID",
    "GATEWAY_NAME",
    "GATEWAY_DESCRIPTION",
    "GATEWAY_DID",
    "GATEWAY_TYPE",
    "GATEWAY_STATUS",
];
const USER_VARIABLES: &[&str] =
    &["OLD_STATE", "NEW_STATE", "USER_ID", "USERNAME", "USER_EMAIL", "USER_ROLE", "USER_STATUS"];
const MESSAGE_VARIABLES: &[&str] = &[
    "CP_ID",
    "CP_NAME",
    "CP_DESCRIPTION",
    "GATEWAY",
    "GATEWAY_ID",
    "MEDIATOR_ID",
    "MESSAGE_ID",
    "MESSAGE_TYPE",
    "FROM_DID",
    "MESSAGE_BODY",
    "RECEIVED_AT",
    "DATE",
    "TIME",
    "DATETIME",
];
const AUDIT_VARIABLES: &[&str] = &[
    "AUDIT_RECORD",
    "AUDIT_CATEGORY",
    "AUDIT_TRACE_ID",
    "AUDIT_SURFACE_ID",
    "AUDIT_SURFACE_NAME",
    "AUDIT_PROTOCOL",
    "AUDIT_AGENT_DID",
    "AUDIT_VIA_FABRIC",
    "AUDIT_PRINCIPAL",
    "AUDIT_PRINCIPAL_EMAIL",
    "AUDIT_PRINCIPAL_NAME",
    "AUDIT_AUTH_METHOD",
    "AUDIT_DECISION",
    "AUDIT_DENY_REASON",
    "AUDIT_POLICY_NAME",
    "AUDIT_POLICY_VERSION",
    "AUDIT_POLICY_CONTENT_HASH",
    "AUDIT_VP_JWT",
    "AUDIT_VP_FINGERPRINT",
];

struct Family {
    id: &'static str,
    label: &'static str,
}

const GATEWAY: Family = Family {
    id: "gateway",
    label: "Gateway",
};
const USER: Family = Family { id: "user", label: "User" };
const CONNECTION_POINT: Family = Family {
    id: "connection_point",
    label: "Connection Point",
};
const X402: Family = Family {
    id: "x402",
    label: "x402 Payments",
};
const MPP: Family = Family {
    id: "mpp",
    label: "MPP Payments",
};
const AUDIT: Family = Family {
    id: "audit",
    label: "Governance Audit",
};

struct EventSpec {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    family: Family,
    variables: &'static [&'static [&'static str]],
}

const fn spec(
    family: Family,
    id: &'static str,
    name: &'static str,
    description: &'static str,
    variables: &'static [&'static [&'static str]],
) -> EventSpec {
    EventSpec {
        id,
        name,
        description,
        family,
        variables,
    }
}

const EVENTS: &[EventSpec] = &[
    spec(GATEWAY, "gateway.created", "Gateway Created", "A gateway was created", &[GATEWAY_VARIABLES]),
    spec(GATEWAY, "gateway.updated", "Gateway Updated", "A gateway's details were changed", &[GATEWAY_VARIABLES]),
    spec(GATEWAY, "gateway.deleted", "Gateway Deleted", "A gateway was deleted", &[GATEWAY_VARIABLES]),
    spec(
        GATEWAY,
        "gateway.status_changed",
        "Gateway Status Changed",
        "A gateway was enabled or disabled",
        &[GATEWAY_VARIABLES, &["GATEWAY_OLD_STATUS"]],
    ),
    spec(GATEWAY, "gateway.accessed", "Gateway Accessed", "A gateway was viewed", &[GATEWAY_VARIABLES]),
    spec(USER, "user.created", "User Registered", "A user completed registration", &[USER_VARIABLES]),
    spec(USER, "user.approved", "User Approved", "An administrator approved a pending user", &[USER_VARIABLES]),
    spec(USER, "user.updated", "User Updated", "A user's role, status or profile was changed", &[USER_VARIABLES]),
    spec(USER, "user.deleted", "User Deleted", "A user was deleted", &[USER_VARIABLES]),
    spec(USER, "user.login", "User Login", "A user logged in", &[USER_VARIABLES]),
    spec(USER, "user.accessed", "User Profile Accessed", "A user's profile was viewed", &[USER_VARIABLES]),
    spec(
        CONNECTION_POINT,
        "connection_point.message_received",
        "Message Received",
        "A connection point received a message",
        &[MESSAGE_VARIABLES],
    ),
    spec(
        X402,
        "x402.verification.failed",
        "x402 Verification Failed",
        "An x402 payment could not be verified",
        &[&["CORRELATION_ID", "SURFACE_ID", "TX_HASH", "ERROR_MESSAGE", "SEVERITY"]],
    ),
    spec(
        X402,
        "x402.settlement.failed",
        "x402 Settlement Failed",
        "An x402 payment could not be settled",
        &[&["CORRELATION_ID", "SURFACE_ID", "TX_HASH", "SETTLEMENT_METHOD", "ERROR_MESSAGE", "SEVERITY"]],
    ),
    spec(
        X402,
        "x402.transaction.completed",
        "x402 Transaction Completed",
        "An x402 payment completed",
        &[&["CORRELATION_ID", "SURFACE_ID", "TX_HASH", "AMOUNT", "NETWORK", "SETTLEMENT_METHOD", "SEVERITY"]],
    ),
    spec(
        X402,
        "x402.cleanup.completed",
        "x402 Cleanup Completed",
        "Old x402 transactions were removed",
        &[&["TRANSACTIONS_DELETED", "RETENTION_DAYS", "SEVERITY"]],
    ),
    spec(
        MPP,
        "mpp.verification.failed",
        "MPP Verification Failed",
        "An MPP payment could not be verified",
        &[&["SURFACE_ID", "SURFACE_NAME", "PAYMENT_METHOD", "RESOURCE_URL", "ERROR_MESSAGE", "SEVERITY"]],
    ),
    spec(
        MPP,
        "mpp.payment.verified",
        "MPP Payment Verified",
        "An MPP payment was verified",
        &[&["SURFACE_ID", "SURFACE_NAME", "PAYMENT_METHOD", "RESOURCE_URL", "REFERENCE", "SEVERITY"]],
    ),
    spec(
        MPP,
        "mpp.challenge.issued",
        "MPP Challenge Issued",
        "A caller was asked to pay with MPP",
        &[&["SURFACE_ID", "SURFACE_NAME", "RESOURCE_URL", "SEVERITY"]],
    ),
];

fn event_variables(groups: &[&[&'static str]]) -> Vec<&'static str> {
    COMMON_VARIABLES
        .iter()
        .chain(
            groups
                .iter()
                .flat_map(|group| group.iter()),
        )
        .copied()
        .collect()
}

static CATALOG: Lazy<Vec<IntegrationEvent>> = Lazy::new(|| {
    let events = EVENTS
        .iter()
        .map(|spec| IntegrationEvent {
            id: spec.id.to_string(),
            name: spec.name.to_string(),
            description: spec.description.to_string(),
            family: spec.family.id,
            family_label: spec.family.label,
            group: None,
            group_label: None,
            variables: event_variables(spec.variables),
        });
    let audit = AUDIT_EVENTS
        .iter()
        .map(|spec| IntegrationEvent {
            id: format!("audit.{}", spec.category),
            name: spec.name.to_string(),
            description: spec.description.to_string(),
            family: AUDIT.id,
            family_label: AUDIT.label,
            group: Some(spec.group.id()),
            group_label: Some(spec.group.label()),
            variables: event_variables(&[AUDIT_VARIABLES]),
        });
    events.chain(audit).collect()
});

/// Every event an integration can subscribe to.
pub fn catalog() -> &'static [IntegrationEvent] {
    &CATALOG
}

pub fn find_event(id: &str) -> Option<&'static IntegrationEvent> {
    catalog()
        .iter()
        .find(|event| event.id == id)
}

/// Every template variable any event fills.
pub fn variables() -> &'static [VariableSpec] {
    VARIABLES
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ids() -> Vec<&'static str> {
        catalog()
            .iter()
            .map(|event| event.id.as_str())
            .collect()
    }

    #[test]
    fn lists_every_delivered_event_once() {
        let mut expected: Vec<String> = [
            "gateway.created",
            "gateway.updated",
            "gateway.deleted",
            "gateway.status_changed",
            "gateway.accessed",
            "user.created",
            "user.approved",
            "user.updated",
            "user.deleted",
            "user.login",
            "user.accessed",
            "connection_point.message_received",
            "x402.verification.failed",
            "x402.settlement.failed",
            "x402.transaction.completed",
            "x402.cleanup.completed",
            "mpp.verification.failed",
            "mpp.payment.verified",
            "mpp.challenge.issued",
        ]
        .map(String::from)
        .to_vec();
        expected.extend(
            AUDIT_EVENTS
                .iter()
                .map(|spec| format!("audit.{}", spec.category)),
        );

        let mut listed: Vec<String> = ids()
            .into_iter()
            .map(String::from)
            .collect();
        listed.sort();
        expected.sort();

        assert_eq!(listed, expected);
    }

    #[test]
    fn every_event_offers_the_common_variables() {
        assert_eq!(
            COMMON_VARIABLES,
            &["EVENT_TYPE", "EVENT_NAME", "EVENT_SUMMARY", "EVENT_DATA", "TIMESTAMP", "APPLIANCE_ID"]
        );
        for event in catalog() {
            for name in COMMON_VARIABLES {
                assert!(event.variables.contains(name), "{} lacks {name}", event.id);
            }
        }
    }

    #[test]
    fn every_offered_variable_is_described_once() {
        let names: Vec<&str> = VARIABLES
            .iter()
            .map(|variable| variable.name)
            .collect();
        assert_eq!(
            names.len(),
            names
                .iter()
                .collect::<HashSet<_>>()
                .len()
        );
        for event in catalog() {
            for name in &event.variables {
                let spec = variables()
                    .iter()
                    .find(|variable| variable.name == *name)
                    .unwrap_or_else(|| panic!("{name} of {} is not described", event.id));
                assert!(!spec.label.is_empty() && !spec.description.is_empty(), "{name}");
            }
            assert_eq!(
                event.variables.len(),
                event
                    .variables
                    .iter()
                    .collect::<HashSet<_>>()
                    .len(),
                "{} lists a variable twice",
                event.id
            );
        }
    }

    #[test]
    fn gateway_events_offer_the_gateway_and_only_a_status_change_its_old_status() {
        let created = find_event("gateway.created").expect("gateway.created");
        assert_eq!(created.name, "Gateway Created");
        assert_eq!((created.family, created.family_label), ("gateway", "Gateway"));
        assert!(
            created
                .variables
                .contains(&"GATEWAY_NAME")
        );
        assert!(
            created
                .variables
                .contains(&"NEW_STATE")
        );
        assert!(
            !created
                .variables
                .contains(&"GATEWAY_OLD_STATUS")
        );

        let changed = find_event("gateway.status_changed").expect("gateway.status_changed");
        assert!(
            changed
                .variables
                .contains(&"GATEWAY_OLD_STATUS")
        );
    }

    #[test]
    fn audit_events_sit_in_the_audit_family_under_their_audit_group() {
        let decision = find_event("audit.policy_decision").expect("audit.policy_decision");
        assert_eq!(decision.name, "Policy Decision");
        assert_eq!((decision.family, decision.family_label), ("audit", "Governance Audit"));
        assert_eq!((decision.group, decision.group_label), (Some("policies"), Some("Policies")));
        assert!(
            decision
                .variables
                .contains(&"AUDIT_RECORD")
        );
        assert!(
            decision
                .variables
                .contains(&"AUDIT_DECISION")
        );
        assert!(
            !decision
                .variables
                .contains(&"GATEWAY_NAME")
        );
    }

    #[test]
    fn non_audit_events_have_no_group() {
        for event in catalog()
            .iter()
            .filter(|event| event.family != "audit")
        {
            assert_eq!((event.group, event.group_label), (None, None), "{}", event.id);
        }
    }

    #[test]
    fn a_received_message_offers_its_body_and_connection_point() {
        let received = find_event("connection_point.message_received").expect("message_received");
        assert_eq!(received.family, "connection_point");
        for name in ["CP_ID", "CP_NAME", "MESSAGE_BODY", "FROM_DID", "GATEWAY_ID"] {
            assert!(
                received
                    .variables
                    .contains(&name),
                "{name}"
            );
        }
    }

    #[test]
    fn payment_events_offer_only_what_their_trigger_fills() {
        let completed = find_event("x402.transaction.completed").expect("x402 completed");
        assert!(
            completed
                .variables
                .contains(&"AMOUNT")
        );
        assert!(
            !completed
                .variables
                .contains(&"ERROR_MESSAGE")
        );
        let cleanup = find_event("x402.cleanup.completed").expect("x402 cleanup");
        assert!(
            cleanup
                .variables
                .contains(&"TRANSACTIONS_DELETED")
        );
        assert!(
            !cleanup
                .variables
                .contains(&"TX_HASH")
        );
        let verified = find_event("mpp.payment.verified").expect("mpp verified");
        assert!(
            verified
                .variables
                .contains(&"REFERENCE")
        );
    }

    #[test]
    fn an_unknown_event_is_not_found() {
        assert_eq!(find_event("gateway.exploded"), None);
        assert_eq!(find_event("policy_decision"), None);
    }
}
