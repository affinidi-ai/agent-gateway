use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{Definition, now};
use crate::integrations::events::{catalog, find_event};
use crate::integrations::runtime_variables::patterns;
use crate::storage::filesystem::StorableEntity;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventSetError {
    #[error("An event set needs at least one event")]
    Empty,
    #[error("Unknown event: {0}")]
    UnknownEvent(String),
}

/// The events an integration delivers, picked from the integration event catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSet {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub events: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl EventSet {
    pub fn new(
        name: String,
        description: String,
        events: Vec<String>,
    ) -> Result<Self, EventSetError> {
        let created_at = now();
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description,
            events: validate_events(events)?,
            updated_at: created_at.clone(),
            created_at,
        })
    }

    pub fn contains(
        &self,
        event_id: &str,
    ) -> bool {
        self.events
            .iter()
            .any(|event| event == event_id)
    }

    pub fn has_audit_events(&self) -> bool {
        self.events
            .iter()
            .any(|event| event.starts_with(AUDIT_EVENT_PREFIX))
    }

    /// Template variables in `content` that no event of the set fills, sorted.
    pub fn unknown_template_variables(
        &self,
        content: &JsonValue,
    ) -> Vec<String> {
        let filled: BTreeSet<&str> = self
            .events
            .iter()
            .filter_map(|event| find_event(event))
            .flat_map(|event| {
                event
                    .variables
                    .iter()
                    .copied()
            })
            .collect();
        let mut used = BTreeSet::new();
        collect_template_variables(content, &mut used);
        used.into_iter()
            .filter(|name| !filled.contains(name.as_str()))
            .collect()
    }
}

const AUDIT_EVENT_PREFIX: &str = "audit.";

fn collect_template_variables(
    value: &JsonValue,
    used: &mut BTreeSet<String>,
) {
    match value {
        JsonValue::String(text) => used.extend(
            patterns()
                .regex
                .captures_iter(text)
                .map(|capture| capture[1].trim().to_string()),
        ),
        JsonValue::Array(items) => items
            .iter()
            .for_each(|item| collect_template_variables(item, used)),
        JsonValue::Object(fields) => fields
            .values()
            .for_each(|field| collect_template_variables(field, used)),
        _ => {}
    }
}

/// `events` without repeats, in the order given, when every one is in the catalog.
pub fn validate_events(events: Vec<String>) -> Result<Vec<String>, EventSetError> {
    if events.is_empty() {
        return Err(EventSetError::Empty);
    }
    let mut unique: Vec<String> = Vec::with_capacity(events.len().min(catalog().len()));
    for event in events {
        if find_event(&event).is_none() {
            return Err(EventSetError::UnknownEvent(event));
        }
        if !unique.contains(&event) {
            unique.push(event);
        }
    }
    Ok(unique)
}

impl StorableEntity for EventSet {
    fn id(&self) -> &str {
        &self.id
    }
}

impl Definition for EventSet {
    fn created_at(&self) -> &str {
        &self.created_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(ids: &[&str]) -> Vec<String> {
        ids.iter()
            .map(|id| id.to_string())
            .collect()
    }

    #[test]
    fn a_new_event_set_keeps_its_events_in_order_without_repeats() {
        let set = EventSet::new(
            "Ops".to_string(),
            String::new(),
            events(&["gateway.created", "audit.policy_decision", "gateway.created"]),
        )
        .expect("valid set");

        assert_eq!(set.events, ["gateway.created", "audit.policy_decision"]);
        assert!(uuid::Uuid::parse_str(&set.id).is_ok());
        assert_eq!(set.created_at, set.updated_at);
    }

    #[test]
    fn mixes_audit_and_other_events() {
        assert_eq!(
            validate_events(events(&["user.login", "audit.trust_check", "x402.transaction.completed"])),
            Ok(events(&["user.login", "audit.trust_check", "x402.transaction.completed"]))
        );
    }

    #[test]
    fn many_repeats_of_one_event_yield_one_event() {
        let repeated = vec!["gateway.created".to_string(); 10_000];

        assert_eq!(validate_events(repeated), Ok(events(&["gateway.created"])));
    }

    #[test]
    fn a_list_longer_than_the_catalog_is_accepted_after_removing_repeats() {
        let every_event: Vec<String> = catalog()
            .iter()
            .map(|event| event.id.to_string())
            .collect();
        let mut longer = every_event.clone();
        longer.extend(every_event.iter().cloned());
        longer.extend(every_event.iter().cloned());
        assert!(longer.len() > catalog().len());

        assert_eq!(validate_events(longer), Ok(every_event));
    }

    #[test]
    fn refuses_an_empty_set() {
        assert_eq!(validate_events(Vec::new()), Err(EventSetError::Empty));
        assert_eq!(EventSet::new("Empty".to_string(), String::new(), Vec::new()), Err(EventSetError::Empty));
    }

    #[test]
    fn refuses_an_event_outside_the_catalog() {
        assert_eq!(
            validate_events(events(&["gateway.created", "identity.created"])),
            Err(EventSetError::UnknownEvent("identity.created".to_string()))
        );
        assert_eq!(
            validate_events(events(&["policy_decision"])),
            Err(EventSetError::UnknownEvent("policy_decision".to_string()))
        );
    }

    #[test]
    fn contains_only_its_own_events() {
        let set = EventSet::new("Ops".to_string(), String::new(), events(&["gateway.created"])).expect("valid set");

        assert!(set.contains("gateway.created"));
        assert!(!set.contains("gateway.deleted"));
    }

    fn set(ids: &[&str]) -> EventSet {
        EventSet::new("Set".to_string(), String::new(), events(ids)).expect("valid set")
    }

    #[test]
    fn knows_whether_it_holds_audit_events() {
        assert!(set(&["gateway.created", "audit.trust_check"]).has_audit_events());
        assert!(!set(&["gateway.created", "user.login"]).has_audit_events());
    }

    #[test]
    fn a_template_may_use_any_variable_some_event_of_the_set_fills() {
        let mixed = set(&["gateway.created", "audit.policy_decision"]);
        let content = serde_json::json!({
            "text": "${EVENT_SUMMARY} on ${GATEWAY_NAME}",
            "decision": "${AUDIT_DECISION:Decision}",
            "data": "${EVENT_DATA}"
        });

        assert!(
            mixed
                .unknown_template_variables(&content)
                .is_empty()
        );
    }

    #[test]
    fn reports_each_variable_no_event_of_the_set_fills_once() {
        let gateways = set(&["gateway.created"]);
        let content = serde_json::json!({
            "subject": "${USERNAME} ${GATEWAY_NAME}",
            "lines": ["${_TEAM}", {"nested": "${USERNAME} ${AMOUNT}"}],
            "count": 3
        });

        assert_eq!(gateways.unknown_template_variables(&content), ["AMOUNT", "USERNAME", "_TEAM"]);
    }
}
