use std::collections::{BTreeSet, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{Definition, now};
use crate::integrations::events::find_event;
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
    pub events: HashSet<String>,
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
        self.events.contains(event_id)
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

/// The distinct `events`, when there is at least one and every one is in the catalog.
pub fn validate_events(events: Vec<String>) -> Result<HashSet<String>, EventSetError> {
    if events.is_empty() {
        return Err(EventSetError::Empty);
    }
    // Sized by what it keeps, never by the caller's list: it grows to at most the catalog.
    let mut unique = HashSet::new();
    for event in events {
        if find_event(&event).is_none() {
            return Err(EventSetError::UnknownEvent(event));
        }
        unique.insert(event);
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
    use crate::integrations::events::catalog;

    fn events(ids: &[&str]) -> Vec<String> {
        ids.iter()
            .map(|id| id.to_string())
            .collect()
    }

    fn unique(ids: &[&str]) -> HashSet<String> {
        ids.iter()
            .map(|id| id.to_string())
            .collect()
    }

    #[test]
    fn a_new_event_set_holds_each_event_once() {
        let set = EventSet::new(
            "Ops".to_string(),
            String::new(),
            events(&["gateway.created", "audit.policy_decision", "gateway.created"]),
        )
        .expect("valid set");

        assert_eq!(set.events, unique(&["gateway.created", "audit.policy_decision"]));
        assert!(uuid::Uuid::parse_str(&set.id).is_ok());
        assert_eq!(set.created_at, set.updated_at);
    }

    #[test]
    fn the_order_events_are_given_in_does_not_matter() {
        let one = validate_events(events(&["user.login", "gateway.created"]));
        let other = validate_events(events(&["gateway.created", "user.login", "user.login"]));

        assert_eq!(one, other);
        let set = set(&["user.login", "gateway.created"]);
        let stored: EventSet = serde_json::from_value(serde_json::to_value(&set).expect("json")).expect("event set");
        assert_eq!(stored, set, "a stored set reads back as the same set");
    }

    #[test]
    fn mixes_audit_and_other_events() {
        assert_eq!(
            validate_events(events(&["user.login", "audit.trust_check", "x402.transaction.completed"])),
            Ok(unique(&["user.login", "audit.trust_check", "x402.transaction.completed"]))
        );
    }

    #[test]
    fn many_repeats_of_one_event_yield_one_event() {
        let repeated = vec!["gateway.created".to_string(); 10_000];

        assert_eq!(validate_events(repeated), Ok(unique(&["gateway.created"])));
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

        assert_eq!(
            validate_events(longer),
            Ok(every_event
                .into_iter()
                .collect())
        );
    }

    #[test]
    fn a_stored_list_with_repeats_reads_as_a_set() {
        let stored = serde_json::json!({
            "id": "4b7d2c0e-8f7a-4f0e-9a51-0c1f3b2a6d10",
            "name": "Ops",
            "events": ["user.login", "gateway.created", "user.login"],
            "created_at": "2026-10-15T00:00:00Z",
            "updated_at": "2026-10-15T00:00:00Z"
        });

        let set: EventSet = serde_json::from_value(stored).expect("stored event set");

        assert_eq!(set.events, unique(&["gateway.created", "user.login"]));
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
