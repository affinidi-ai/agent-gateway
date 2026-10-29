//! The values one delivery of an event fills.

use std::collections::HashMap;

use super::render::{Escaping, render};
use crate::integrations::events::{COMMON_VARIABLES, IntegrationEvent};

/// What a delivery of `event` fills: the values its trigger supplied for the event's own
/// variables, its id and name, a one-line summary, its data as JSON, and the Appliance ID
/// from System Settings. A trigger cannot supply the computed values itself.
pub fn event_values(
    event: &IntegrationEvent,
    trigger: HashMap<String, String>,
    appliance_id: Option<String>,
) -> HashMap<String, String> {
    let mut values: HashMap<String, String> = trigger
        .into_iter()
        .filter(|(name, _)| {
            !COMPUTED.contains(&name.as_str())
                && event
                    .variables
                    .contains(&name.as_str())
        })
        .collect();
    values
        .entry("TIMESTAMP".to_string())
        .or_insert_with(|| chrono::Utc::now().to_rfc3339());
    values.insert("EVENT_TYPE".to_string(), event.id.clone());
    values.insert("EVENT_NAME".to_string(), event.name.clone());
    values.insert("EVENT_DATA".to_string(), event_data(event, &values));
    values.insert("EVENT_SUMMARY".to_string(), summary(event, &values));
    if let Some(appliance_id) = appliance_id {
        values.insert("APPLIANCE_ID".to_string(), appliance_id);
    }
    values
}

/// Stand-in values for each of `event`'s own variables, for test messages: `{}` for JSON
/// ones, `sample-<name>` for the rest.
pub fn sample_trigger_values(event: &IntegrationEvent) -> HashMap<String, String> {
    event
        .variables
        .iter()
        .filter(|name| !COMMON_VARIABLES.contains(name))
        .map(|name| {
            let value = if JSON_TEXT_VARIABLES.contains(name) || *name == "AUDIT_RECORD" {
                "{}".to_string()
            } else {
                format!("sample-{}", name.to_lowercase())
            };
            (name.to_string(), value)
        })
        .collect()
}

/// Values every delivery computes, never taken from a trigger.
const COMPUTED: &[&str] = &["EVENT_TYPE", "EVENT_NAME", "EVENT_SUMMARY", "EVENT_DATA", "APPLIANCE_ID"];

/// Variables holding JSON text, embedded in `EVENT_DATA` as JSON.
const JSON_TEXT_VARIABLES: &[&str] = &["OLD_STATE", "NEW_STATE", "MESSAGE_BODY"];

/// The audit record for an audit event; otherwise the event's own variables as an object
/// with lower-case keys.
fn event_data(
    event: &IntegrationEvent,
    values: &HashMap<String, String>,
) -> String {
    if event.family == "audit" {
        return values
            .get("AUDIT_RECORD")
            .cloned()
            .unwrap_or_else(|| "{}".to_string());
    }
    let data: serde_json::Map<String, serde_json::Value> = event
        .variables
        .iter()
        .filter(|name| !COMMON_VARIABLES.contains(name))
        .filter_map(|name| {
            let value = values.get(*name)?;
            let json = if JSON_TEXT_VARIABLES.contains(name) {
                if value.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_str(value).unwrap_or_else(|_| serde_json::Value::String(value.clone()))
                }
            } else {
                serde_json::Value::String(value.clone())
            };
            Some((name.to_lowercase(), json))
        })
        .collect();
    serde_json::Value::Object(data).to_string()
}

fn summary(
    event: &IntegrationEvent,
    values: &HashMap<String, String>,
) -> String {
    if event.family == "audit" {
        return audit_summary(event, values);
    }
    let template = match event.id.as_str() {
        "gateway.created" => "Gateway ${GATEWAY_NAME} was created",
        "gateway.updated" => "Gateway ${GATEWAY_NAME} was updated",
        "gateway.deleted" => "Gateway ${GATEWAY_NAME} was deleted",
        "gateway.status_changed" => {
            "Gateway ${GATEWAY_NAME} status changed from ${GATEWAY_OLD_STATUS} to ${GATEWAY_STATUS}"
        }
        "gateway.accessed" => "Gateway ${GATEWAY_NAME} was viewed",
        "user.created" => "User ${USERNAME} registered",
        "user.approved" => "User ${USERNAME} was approved",
        "user.updated" => "User ${USERNAME} was updated",
        "user.deleted" => "User ${USERNAME} was deleted",
        "user.login" => "User ${USERNAME} logged in",
        "user.accessed" => "User ${USERNAME}'s profile was viewed",
        "connection_point.connected" => "${FROM_DID} connected through connection point ${CP_NAME}",
        "x402.verification.failed" => {
            "x402 payment ${TX_HASH} on surface ${SURFACE_ID} failed verification: ${ERROR_MESSAGE}"
        }
        "x402.settlement.failed" => {
            "x402 payment ${TX_HASH} on surface ${SURFACE_ID} failed to settle: ${ERROR_MESSAGE}"
        }
        "x402.transaction.completed" => "x402 payment ${TX_HASH} of ${AMOUNT} completed on ${NETWORK}",
        "x402.cleanup.completed" => {
            "x402 cleanup removed ${TRANSACTIONS_DELETED} transactions older than ${RETENTION_DAYS} days"
        }
        "mpp.verification.failed" => {
            "MPP payment for ${RESOURCE_URL} on surface ${SURFACE_NAME} failed verification: ${ERROR_MESSAGE}"
        }
        "mpp.payment.verified" => {
            "MPP payment ${REFERENCE} for ${RESOURCE_URL} on surface ${SURFACE_NAME} was verified"
        }
        "mpp.challenge.issued" => "MPP payment requested for ${RESOURCE_URL} on surface ${SURFACE_NAME}",
        "payment.challenge_issued" => "Payment requested for ${RESOURCE} on surface ${SURFACE_ID}",
        "payment.paid" => "Payment for ${RESOURCE} on surface ${SURFACE_ID} was accepted",
        "payment.held" => "Payment for ${RESOURCE} on surface ${SURFACE_ID} was held for review (case ${CASE_ID})",
        "payment.rejected" => "Payment for ${RESOURCE} on surface ${SURFACE_ID} was rejected: ${REASON}",
        "payment.unconfirmed" => "Payment for ${RESOURCE} on surface ${SURFACE_ID} is unconfirmed: ${REASON}",
        "payment.unavailable" => "Payment gateway unavailable for ${RESOURCE} on surface ${SURFACE_ID}: ${REASON}",
        "payment.authorized" => "Funds for ${RESOURCE} on surface ${SURFACE_ID} are held until delivery",
        "payment.voided" => "Held funds for ${RESOURCE} on surface ${SURFACE_ID} were released: ${REASON}",
        "payment.capture_failed" => "Capturing held funds for ${RESOURCE} on surface ${SURFACE_ID} failed: ${REASON}",
        "payment.reconcile_failed" => "A payment for ${RESOURCE} on surface ${SURFACE_ID} was not settled: ${REASON}",
        _ => return event.name.clone(),
    };
    render(&serde_json::Value::String(template.to_string()), values, Escaping::None, false)
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The event's name, then whichever of the surface, decision, policy, reason and caller the
/// record holds.
fn audit_summary(
    event: &IntegrationEvent,
    values: &HashMap<String, String>,
) -> String {
    let set = |name: &str| {
        values
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    };
    let mut summary = event.name.clone();
    if let Some(surface) = set("AUDIT_SURFACE_NAME") {
        summary.push_str(&format!(" on surface {surface}"));
    }
    if let Some(decision) = set("AUDIT_DECISION") {
        summary.push_str(&format!(": {decision}"));
        if let Some(policy) = set("AUDIT_POLICY_NAME") {
            summary.push_str(&format!(" by policy {policy}"));
        }
        if let Some(reason) = set("AUDIT_DENY_REASON") {
            summary.push_str(&format!(" ({reason})"));
        }
    }
    if let Some(principal) = set("AUDIT_PRINCIPAL") {
        summary.push_str(&format!(" for {principal}"));
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::events::{catalog, find_event};

    fn trigger(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    fn event(id: &str) -> &'static IntegrationEvent {
        find_event(id).expect("catalog event")
    }

    #[test]
    fn a_gateway_event_gets_its_name_summary_and_data() {
        let values = event_values(
            event("gateway.created"),
            trigger(&[
                ("EVENT_TYPE", "gateway.created"),
                ("TIMESTAMP", "2026-10-15T00:00:00Z"),
                ("GATEWAY_ID", "gw-1"),
                ("GATEWAY_NAME", "edge"),
                ("NEW_STATE", r#"{"id":"gw-1"}"#),
                ("OLD_STATE", ""),
            ]),
            Some("appliance-7".to_string()),
        );

        assert_eq!(values["EVENT_TYPE"], "gateway.created");
        assert_eq!(values["EVENT_NAME"], "Gateway Created");
        assert_eq!(values["EVENT_SUMMARY"], "Gateway edge was created");
        assert_eq!(values["APPLIANCE_ID"], "appliance-7");
        assert_eq!(values["TIMESTAMP"], "2026-10-15T00:00:00Z");
        let data: serde_json::Value = serde_json::from_str(&values["EVENT_DATA"]).expect("json");
        assert_eq!(data["gateway_id"], "gw-1");
        assert_eq!(data["gateway_name"], "edge");
        assert_eq!(data["new_state"], serde_json::json!({"id": "gw-1"}));
        assert_eq!(data["old_state"], serde_json::Value::Null);
        assert!(
            data.get("event_type")
                .is_none()
        );
    }

    #[test]
    fn a_trigger_cannot_supply_computed_values_or_variables_outside_its_event() {
        let values = event_values(
            event("user.login"),
            trigger(&[
                ("USERNAME", "jane"),
                ("APPLIANCE_ID", "forged"),
                ("EVENT_SUMMARY", "forged"),
                ("EVENT_NAME", "forged"),
                ("EVENT_TYPE", "audit.policy_decision"),
                ("GATEWAY_NAME", "not a user variable"),
            ]),
            None,
        );

        assert_eq!(values["EVENT_TYPE"], "user.login");
        assert_eq!(values["EVENT_NAME"], "User Login");
        assert_eq!(values["EVENT_SUMMARY"], "User jane logged in");
        assert!(!values.contains_key("APPLIANCE_ID"));
        assert!(!values.contains_key("GATEWAY_NAME"));
        assert!(values.contains_key("TIMESTAMP"));
    }

    #[test]
    fn a_status_change_summary_names_both_statuses() {
        let values = event_values(
            event("gateway.status_changed"),
            trigger(&[("GATEWAY_NAME", "edge"), ("GATEWAY_OLD_STATUS", "Active"), ("GATEWAY_STATUS", "Disabled")]),
            None,
        );

        assert_eq!(values["EVENT_SUMMARY"], "Gateway edge status changed from Active to Disabled");
    }

    #[test]
    fn an_audit_event_carries_its_record_as_data_and_summarises_the_decision() {
        let record = r#"{"category":"policy_decision","decision":"deny"}"#;
        let values = event_values(
            event("audit.policy_decision"),
            trigger(&[
                ("AUDIT_RECORD", record),
                ("AUDIT_SURFACE_NAME", "Payments"),
                ("AUDIT_DECISION", "deny"),
                ("AUDIT_POLICY_NAME", "no-external-tools"),
                ("AUDIT_DENY_REASON", "tool not allowed"),
                ("AUDIT_PRINCIPAL", "jane@example.com"),
            ]),
            None,
        );

        assert_eq!(values["EVENT_DATA"], record);
        assert_eq!(
            values["EVENT_SUMMARY"],
            "Policy Decision on surface Payments: deny by policy no-external-tools (tool not allowed) for jane@example.com"
        );
    }

    #[test]
    fn a_connection_summary_names_who_connected_and_where() {
        let values = event_values(
            event("connection_point.connected"),
            trigger(&[("CP_NAME", "Orders"), ("FROM_DID", "did:peer:partner")]),
            None,
        );

        assert_eq!(values["EVENT_SUMMARY"], "did:peer:partner connected through connection point Orders");
    }

    #[test]
    fn an_audit_summary_leaves_out_what_the_record_lacks() {
        let values = event_values(event("audit.trust_check"), trigger(&[]), None);

        assert_eq!(values["EVENT_SUMMARY"], "Trust Check");
    }

    #[test]
    fn every_event_has_a_summary() {
        for event in catalog() {
            let filled = event
                .variables
                .iter()
                .map(|name| (name.to_string(), "x".to_string()))
                .collect();
            let values = event_values(event, filled, None);
            assert!(
                values["EVENT_SUMMARY"].contains('x') || event.family == "audit",
                "{}: {}",
                event.id,
                values["EVENT_SUMMARY"]
            );
        }
    }

    #[test]
    fn sample_values_fill_each_of_the_events_own_variables() {
        let sample = sample_trigger_values(event("gateway.status_changed"));

        assert_eq!(sample["GATEWAY_NAME"], "sample-gateway_name");
        assert_eq!(sample["GATEWAY_OLD_STATUS"], "sample-gateway_old_status");
        assert_eq!(sample["NEW_STATE"], "{}");
        assert_eq!(sample["OLD_STATE"], "{}");
        assert!(!sample.contains_key("EVENT_SUMMARY"));
        assert!(!sample.contains_key("TIMESTAMP"));

        let audit = sample_trigger_values(event("audit.policy_decision"));
        assert_eq!(audit["AUDIT_RECORD"], "{}");
        assert_eq!(audit["AUDIT_DECISION"], "sample-audit_decision");
    }
}
