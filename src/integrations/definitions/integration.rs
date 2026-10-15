use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{Definition, EventSet, Status, now};
use crate::storage::filesystem::StorableEntity;

/// Delivers the events of one event set to one endpoint, rendered through its template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Integration {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub endpoint_id: String,
    pub event_set_id: String,
    pub content: JsonValue,
    pub status: Status,
    /// Audit records older than this many seconds are skipped instead of delivered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_drop_after_secs: Option<u64>,
    /// An audit record this integration failed to accept this many times is skipped instead
    /// of retried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_max_attempts: Option<u32>,
    pub created_at: String,
    pub updated_at: String,
}

impl Integration {
    pub fn new(
        name: String,
        description: String,
        endpoint_id: String,
        event_set_id: String,
        content: JsonValue,
    ) -> Self {
        let created_at = now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description,
            endpoint_id,
            event_set_id,
            content,
            status: Status::Active,
            audit_drop_after_secs: None,
            audit_max_attempts: None,
            updated_at: created_at.clone(),
            created_at,
        }
    }

    /// Whether the integration can deliver `event_set`: its template is an object using only
    /// variables the set's events fill, and its audit delivery limits are at least 1 and set
    /// only when the set holds audit events.
    pub fn check_against(
        &self,
        event_set: &EventSet,
    ) -> Result<(), String> {
        if !self.content.is_object() {
            return Err("The template must be an object".to_string());
        }
        let unfilled = event_set.unknown_template_variables(&self.content);
        if !unfilled.is_empty() {
            return Err(format!("No event of the event set fills these template variables: {}", unfilled.join(", ")));
        }
        check_audit_limit(event_set, "audit_drop_after_secs", self.audit_drop_after_secs)?;
        check_audit_limit(
            event_set,
            "audit_max_attempts",
            self.audit_max_attempts
                .map(u64::from),
        )
    }
}

fn check_audit_limit(
    event_set: &EventSet,
    field: &str,
    value: Option<u64>,
) -> Result<(), String> {
    match value {
        None => Ok(()),
        Some(_) if !event_set.has_audit_events() => {
            Err(format!("Only an integration delivering audit events accepts {field}"))
        }
        Some(0) => Err(format!("{field} must be at least 1")),
        Some(_) => Ok(()),
    }
}

impl StorableEntity for Integration {
    fn id(&self) -> &str {
        &self.id
    }
}

impl Definition for Integration {
    fn created_at(&self) -> &str {
        &self.created_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn integration() -> Integration {
        Integration::new(
            "Ops alerts".to_string(),
            String::new(),
            "endpoint-1".to_string(),
            "event-set-1".to_string(),
            json!({"text": "${EVENT_SUMMARY}"}),
        )
    }

    #[test]
    fn a_new_integration_links_its_endpoint_and_event_set_and_is_active() {
        let first = integration();

        assert_eq!(first.endpoint_id, "endpoint-1");
        assert_eq!(first.event_set_id, "event-set-1");
        assert_eq!(first.content["text"], "${EVENT_SUMMARY}");
        assert_eq!(first.status, Status::Active);
        assert_eq!(first.audit_drop_after_secs, None);
        assert!(uuid::Uuid::parse_str(&first.id).is_ok());
        assert_ne!(first.id, integration().id);
        assert_eq!(first.created_at, first.updated_at);
    }

    #[test]
    fn leaves_out_an_unset_audit_drop_age() {
        let mut value = serde_json::to_value(integration()).expect("serializes");
        assert!(
            value
                .get("audit_drop_after_secs")
                .is_none()
        );

        value["audit_drop_after_secs"] = json!(600);
        let parsed: Integration = serde_json::from_value(value).expect("parses");
        assert_eq!(parsed.audit_drop_after_secs, Some(600));
    }

    fn event_set(events: &[&str]) -> EventSet {
        EventSet::new(
            "Set".to_string(),
            String::new(),
            events
                .iter()
                .map(|event| event.to_string())
                .collect(),
        )
        .expect("valid set")
    }

    #[test]
    fn fits_an_event_set_whose_events_fill_its_template() {
        let mut fitting = integration();
        fitting.content = json!({"text": "${EVENT_SUMMARY} by ${AUDIT_PRINCIPAL}"});
        fitting.audit_drop_after_secs = Some(600);
        fitting.audit_max_attempts = Some(5);

        assert_eq!(fitting.check_against(&event_set(&["audit.policy_decision"])), Ok(()));
    }

    #[test]
    fn names_the_template_variables_no_event_fills() {
        let mut unfilled = integration();
        unfilled.content = json!({"text": "${USERNAME} ${GATEWAY_NAME} ${AMOUNT}"});

        assert_eq!(
            unfilled.check_against(&event_set(&["gateway.created"])),
            Err("No event of the event set fills these template variables: AMOUNT, USERNAME".to_string())
        );
    }

    #[test]
    fn needs_a_template_object() {
        let mut text = integration();
        text.content = json!("${EVENT_SUMMARY}");

        assert_eq!(
            text.check_against(&event_set(&["gateway.created"])),
            Err("The template must be an object".to_string())
        );
    }

    #[test]
    fn takes_audit_delivery_limits_only_with_audit_events_and_from_one() {
        let mut drop_age = integration();
        drop_age.audit_drop_after_secs = Some(600);
        assert_eq!(
            drop_age.check_against(&event_set(&["gateway.created"])),
            Err("Only an integration delivering audit events accepts audit_drop_after_secs".to_string())
        );

        let mut attempts = integration();
        attempts.audit_max_attempts = Some(0);
        assert_eq!(
            attempts.check_against(&event_set(&["gateway.created", "audit.trust_check"])),
            Err("audit_max_attempts must be at least 1".to_string())
        );
    }
}
