use serde::{Deserialize, Serialize};

use super::{Definition, now};
use crate::integrations::events::find_event;
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
}

/// `events` without repeats, in the order given, when every one is in the catalog.
pub fn validate_events(events: Vec<String>) -> Result<Vec<String>, EventSetError> {
    if events.is_empty() {
        return Err(EventSetError::Empty);
    }
    let mut unique: Vec<String> = Vec::with_capacity(events.len());
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
}
