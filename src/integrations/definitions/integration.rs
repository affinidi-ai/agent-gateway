use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{Definition, Status, now};
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
            updated_at: created_at.clone(),
            created_at,
        }
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
}
