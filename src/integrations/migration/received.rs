//! Which catalog events a live integration received, so its event set keeps delivering them.
//!
//! Live chose integrations by category, status and attachments: gateway and user events went
//! to `gateway`/`user` or `general` integrations attached to the gateway or the users, x402
//! and MPP events to their category, a connection point's messages to the integrations on its
//! record (whatever their category or status), and audit records to every appliance-wide
//! `audit` integration.

use std::collections::BTreeSet;

use super::legacy::{LegacyAttachment, LegacyIntegration, LegacyRecords};
use crate::integrations::events::catalog;

const GATEWAY_EVENTS: [&str; 5] =
    ["gateway.created", "gateway.updated", "gateway.deleted", "gateway.status_changed", "gateway.accessed"];
const USER_EVENTS: [&str; 6] =
    ["user.created", "user.updated", "user.deleted", "user.approved", "user.login", "user.accessed"];
const X402_EVENTS: [&str; 4] =
    ["x402.verification.failed", "x402.settlement.failed", "x402.transaction.completed", "x402.cleanup.completed"];
const MPP_EVENTS: [&str; 3] = ["mpp.verification.failed", "mpp.payment.verified", "mpp.challenge.issued"];
const CONNECTION_POINT_EVENT: &str = "connection_point.connected";

/// The audit records live's audit writer always wrote.
const UNGATED_AUDIT_EVENTS: [&str; 16] = [
    "trace_terminated",
    "consent_granted",
    "token_injected",
    "token_refreshed",
    "refresh_failed",
    "consent_required",
    "token_revoked",
    "user_tokens_revoked",
    "token_not_found",
    "elicitation_sent",
    "elicitation_accepted",
    "elicitation_declined",
    "elicitation_cancelled",
    "elicitation_timed_out",
    "pre_authorize_blocked",
    "payment",
];

/// The audit records live wrote only while the audit log was on and their category ticked;
/// the settings store now keeps those categories as these events in `audit_events`.
const GATED_AUDIT_EVENTS: [&str; 3] = ["policy_decision", "trust_check", "vp_injected"];

/// The audit records live forwarded, from the audit settings as the settings store upgraded
/// them.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditForwarding {
    events: Vec<&'static str>,
}

impl AuditForwarding {
    pub fn from_settings(
        audit_enabled: bool,
        audit_events: &[String],
    ) -> Self {
        let gated = GATED_AUDIT_EVENTS
            .into_iter()
            .filter(|event| {
                audit_enabled
                    && audit_events
                        .iter()
                        .any(|kept| kept == event)
            });
        Self {
            events: UNGATED_AUDIT_EVENTS
                .into_iter()
                .chain(gated)
                .collect(),
        }
    }
}

/// What a live integration received, as catalog event ids in catalog order, and what about it
/// the report should say.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Received {
    pub events: Vec<String>,
    pub notes: Vec<String>,
}

/// The category live used, with the `channel` → `surface` rename its loader applied.
fn category(integration: &LegacyIntegration) -> &str {
    match integration
        .category
        .as_deref()
    {
        Some("channel") => "surface",
        Some(category) => category,
        None => "",
    }
}

pub fn received_events(
    integration: &LegacyIntegration,
    records: &LegacyRecords,
    audit: &AuditForwarding,
) -> Received {
    let mut picked = BTreeSet::new();
    let mut notes = Vec::new();
    let category = category(integration);
    let attached = |attachment: &&LegacyAttachment| attachment.integration_id == integration.id;

    if matches!(category, "gateway" | "general") {
        let mut gateways = Vec::new();
        for (gateway_id, attachments) in &records.gateway_attachments {
            for attachment in attachments
                .iter()
                .filter(attached)
            {
                gateways.push(gateway_id.as_str());
                pick(&mut picked, &mut notes, attachment, &GATEWAY_EVENTS, "gateway");
            }
        }
        if !gateways.is_empty() {
            notes.push(format!(
                "Received gateway events only from the gateways it was attached to ({}); now from every gateway",
                gateways.join(", ")
            ));
        }
    }
    if matches!(category, "user" | "general") {
        for attachment in records
            .user_attachments
            .iter()
            .filter(attached)
        {
            pick(&mut picked, &mut notes, attachment, &USER_EVENTS, "user");
        }
    }
    let family: &[&str] = match category {
        "x402" => &X402_EVENTS,
        "mpp" => &MPP_EVENTS,
        _ => &[],
    };
    picked.extend(
        family
            .iter()
            .map(|event| event.to_string()),
    );

    let points: Vec<&str> = records
        .connection_points
        .iter()
        .filter(|point| {
            point
                .integration_ids()
                .contains(&integration.id.as_str())
        })
        .map(|point| point.id.as_str())
        .collect();
    if !points.is_empty() {
        picked.insert(CONNECTION_POINT_EVENT.to_string());
        notes.push(format!(
            "Received the messages of the connection points naming it ({}); now {CONNECTION_POINT_EVENT} from every connection point",
            points.join(", ")
        ));
        if integration.status != "active" {
            notes.push(
                "Live delivered those connection point messages although the integration was disabled; it stays disabled"
                    .to_string(),
            );
        }
    }

    if category == "audit"
        && integration
            .tenant_id
            .is_none()
    {
        if integration
            .audit_events
            .is_empty()
        {
            picked.extend(
                audit
                    .events
                    .iter()
                    .map(|event| format!("audit.{event}")),
            );
            let added: Vec<&str> = catalog()
                .iter()
                .filter_map(|event| {
                    event
                        .id
                        .strip_prefix("audit.")
                })
                .filter(|event| !UNGATED_AUDIT_EVENTS.contains(event) && !GATED_AUDIT_EVENTS.contains(event))
                .collect();
            if !added.is_empty() {
                notes.push(format!(
                    "Audit events added since the live version are not selected: {}; add them to its event set to receive them",
                    added.join(", ")
                ));
            }
        } else {
            picked.extend(
                integration
                    .audit_events
                    .iter()
                    .map(|event| format!("audit.{event}")),
            );
        }
    }

    let events: Vec<String> = catalog()
        .iter()
        .filter(|event| picked.contains(event.id.as_str()))
        .map(|event| event.id.to_string())
        .collect();
    let unknown: Vec<&str> = picked
        .iter()
        .map(String::as_str)
        .filter(|event| {
            !events
                .iter()
                .any(|known| known == event)
        })
        .collect();
    if !unknown.is_empty() {
        notes.push(format!("Left out events the catalog does not list: {}", unknown.join(", ")));
    }
    Received { events, notes }
}

/// The events of `kind` an attachment selected: its event types, or every one when it lists
/// none. Event types live never raised for `kind` are left out and noted.
fn pick(
    picked: &mut BTreeSet<String>,
    notes: &mut Vec<String>,
    attachment: &LegacyAttachment,
    events: &[&str],
    kind: &str,
) {
    if attachment
        .event_types
        .is_empty()
    {
        picked.extend(
            events
                .iter()
                .map(|event| event.to_string()),
        );
        return;
    }
    for event in &attachment.event_types {
        if events.contains(&event.as_str()) {
            picked.insert(event.clone());
        } else {
            notes.push(format!("Left out {event}, which live never raised for {kind} attachments"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::migration::legacy::{LegacyConnectionPoint, LegacyConnectionPointIntegration};
    use serde_json::json;
    use std::collections::HashMap;

    const ID: &str = "6f1c2a7e-3b9d-4c55-9a51-0d7e8f2b4c11";

    fn live(category: Option<&str>) -> LegacyIntegration {
        LegacyIntegration {
            id: ID.to_string(),
            tenant_id: None,
            name: "Ops".to_string(),
            description: String::new(),
            integration_type: "slack".to_string(),
            category: category.map(str::to_string),
            configuration: json!({}),
            content: json!({}),
            status: "active".to_string(),
            created_at: String::new(),
            updated_at: String::new(),
            audit_events: Vec::new(),
            audit_drop_after_secs: None,
            audit_max_attempts: None,
        }
    }

    fn attachment(event_types: &[&str]) -> LegacyAttachment {
        LegacyAttachment {
            integration_id: ID.to_string(),
            variables: HashMap::new(),
            event_types: event_types
                .iter()
                .map(|event| event.to_string())
                .collect(),
        }
    }

    fn connection_point(id: &str) -> LegacyConnectionPoint {
        LegacyConnectionPoint {
            id: id.to_string(),
            gateway_id: "gw-1".to_string(),
            integrations: vec![LegacyConnectionPointIntegration {
                integration_id: ID.to_string(),
                variables: json!({}),
            }],
            integration_id: None,
        }
    }

    fn no_audit() -> AuditForwarding {
        AuditForwarding::from_settings(false, &[])
    }

    fn events(received: &Received) -> Vec<&str> {
        received
            .events
            .iter()
            .map(String::as_str)
            .collect()
    }

    /// Removed from the audit writer after the live version; reported as left out.
    const REMOVED_AUDIT_EVENT: &str = "audit.pre_authorize_blocked";

    #[test]
    fn the_baseline_events_are_in_the_catalog_except_the_one_removed_since() {
        let known: Vec<&str> = catalog()
            .iter()
            .map(|event| event.id.as_str())
            .collect();
        let audit = UNGATED_AUDIT_EVENTS
            .iter()
            .chain(&GATED_AUDIT_EVENTS)
            .map(|event| format!("audit.{event}"));
        let delivered = GATEWAY_EVENTS
            .iter()
            .chain(&USER_EVENTS)
            .chain(&X402_EVENTS)
            .chain(&MPP_EVENTS)
            .chain(&[CONNECTION_POINT_EVENT])
            .map(|event| event.to_string());

        for event in delivered.chain(audit) {
            assert_eq!(known.contains(&event.as_str()), event != REMOVED_AUDIT_EVENT, "{event}");
        }
    }

    #[test]
    fn gateway_attachments_give_their_event_types_and_an_empty_list_every_gateway_event() {
        let records = LegacyRecords {
            gateway_attachments: vec![
                ("gw-1".to_string(), vec![attachment(&["gateway.created", "gateway.deleted"])]),
                ("gw-2".to_string(), vec![attachment(&["gateway.created"])]),
            ],
            ..LegacyRecords::default()
        };

        let picked = received_events(&live(Some("gateway")), &records, &no_audit());
        assert_eq!(events(&picked), ["gateway.created", "gateway.deleted"]);

        let everything = LegacyRecords {
            gateway_attachments: vec![("gw-1".to_string(), vec![attachment(&[])])],
            ..LegacyRecords::default()
        };
        assert_eq!(events(&received_events(&live(Some("general")), &everything, &no_audit())), GATEWAY_EVENTS);
    }

    #[test]
    fn attachments_count_only_for_the_categories_live_delivered_them_to() {
        let records = LegacyRecords {
            gateway_attachments: vec![("gw-1".to_string(), vec![attachment(&[])])],
            user_attachments: vec![attachment(&["user.login"])],
            ..LegacyRecords::default()
        };

        assert_eq!(events(&received_events(&live(Some("user")), &records, &no_audit())), ["user.login"]);
        assert_eq!(
            events(&received_events(&live(Some("general")), &records, &no_audit())),
            [GATEWAY_EVENTS.as_slice(), &["user.login"]].concat()
        );
        assert!(
            received_events(&live(Some("surface")), &records, &no_audit())
                .events
                .is_empty()
        );
    }

    #[test]
    fn an_event_type_live_never_raised_is_left_out_and_reported() {
        let records = LegacyRecords {
            gateway_attachments: vec![("gw-1".to_string(), vec![attachment(&["gateway.created", "gateway.exploded"])])],
            ..LegacyRecords::default()
        };

        let received = received_events(&live(Some("gateway")), &records, &no_audit());

        assert_eq!(events(&received), ["gateway.created"]);
        assert!(
            received
                .notes
                .iter()
                .any(|note| note.contains("gateway.exploded")),
            "{:?}",
            received.notes
        );
    }

    #[test]
    fn x402_and_mpp_categories_receive_all_their_events() {
        let records = LegacyRecords::default();

        assert_eq!(events(&received_events(&live(Some("x402")), &records, &no_audit())), X402_EVENTS);
        assert_eq!(events(&received_events(&live(Some("mpp")), &records, &no_audit())), MPP_EVENTS);
    }

    #[test]
    fn a_connection_point_naming_the_integration_gives_its_connected_event_whatever_the_category() {
        let records = LegacyRecords {
            connection_points: vec![connection_point("cp-1"), connection_point("cp-2")],
            ..LegacyRecords::default()
        };

        let mut disabled = live(Some("surface"));
        disabled.status = "disabled".to_string();
        let received = received_events(&disabled, &records, &no_audit());

        assert_eq!(events(&received), [CONNECTION_POINT_EVENT]);
        assert!(
            received
                .notes
                .iter()
                .any(|note| note.contains("disabled")),
            "live delivered connection point messages to it although it was disabled: {:?}",
            received.notes
        );
    }

    #[test]
    fn some_gateways_or_connection_points_now_means_all_and_is_reported() {
        let records = LegacyRecords {
            gateway_attachments: vec![("gw-1".to_string(), vec![attachment(&[])])],
            connection_points: vec![connection_point("cp-1")],
            ..LegacyRecords::default()
        };

        let received = received_events(&live(Some("gateway")), &records, &no_audit());

        assert!(
            received
                .notes
                .iter()
                .any(|note| note.contains("gw-1")),
            "{:?}",
            received.notes
        );
        assert!(
            received
                .notes
                .iter()
                .any(|note| note.contains("cp-1")),
            "{:?}",
            received.notes
        );
    }

    #[test]
    fn an_audit_integration_receives_what_the_baseline_forwarded() {
        let records = LegacyRecords::default();
        let audit = live(Some("audit"));

        let off =
            received_events(&audit, &records, &AuditForwarding::from_settings(false, &["policy_decision".into()]));
        assert_eq!(off.events.len(), 15, "the 16 ungated ones but the one removed since");
        assert!(
            !off.events
                .contains(&"audit.policy_decision".to_string())
        );
        assert!(
            off.notes
                .iter()
                .any(|note| note.contains(REMOVED_AUDIT_EVENT)),
            "{:?}",
            off.notes
        );

        let on = received_events(
            &audit,
            &records,
            &AuditForwarding::from_settings(true, &["policy_decision".into(), "vp_injected".into()]),
        );
        assert_eq!(on.events.len(), 17);
        assert!(
            on.events
                .contains(&"audit.policy_decision".to_string())
        );
        assert!(
            on.events
                .contains(&"audit.vp_injected".to_string())
        );
        assert!(
            !on.events
                .contains(&"audit.trust_check".to_string())
        );
        assert!(
            on.notes
                .iter()
                .any(|note| note.contains("auth_failed")),
            "names the audit events added after the baseline: {:?}",
            on.notes
        );
    }

    #[test]
    fn a_tenant_owned_audit_integration_received_nothing() {
        let mut tenant = live(Some("audit"));
        tenant.tenant_id = Some("team-a".to_string());

        let received = received_events(&tenant, &LegacyRecords::default(), &AuditForwarding::from_settings(true, &[]));

        assert!(received.events.is_empty());
    }

    #[test]
    fn audit_events_a_later_main_stored_are_used_as_they_are() {
        let mut later = live(Some("audit"));
        later.audit_events = vec!["policy_decision".to_string(), "auth_failed".to_string()];

        let received = received_events(&later, &LegacyRecords::default(), &no_audit());

        let mut picked = events(&received);
        picked.sort();
        assert_eq!(picked, ["audit.auth_failed", "audit.policy_decision"]);
        assert!(received.notes.is_empty(), "{:?}", received.notes);
    }

    #[test]
    fn an_integration_nothing_reached_receives_nothing() {
        for category in [None, Some("general"), Some("surface"), Some("identity"), Some("connection_point")] {
            assert!(
                received_events(&live(category), &LegacyRecords::default(), &no_audit())
                    .events
                    .is_empty(),
                "{category:?}"
            );
        }
    }

    #[test]
    fn identity_attachments_and_other_integrations_attachments_give_nothing() {
        let mut other = attachment(&[]);
        other.integration_id = "someone-else".to_string();
        let records = LegacyRecords {
            gateway_attachments: vec![("gw-1".to_string(), vec![other])],
            identity_attachments: vec![attachment(&[])],
            ..LegacyRecords::default()
        };

        assert!(
            received_events(&live(Some("general")), &records, &no_audit())
                .events
                .is_empty()
        );
    }
}
