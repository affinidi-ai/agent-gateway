use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::{Definition, Status, now};
use crate::storage::filesystem::StorableEntity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointType {
    Email,
    Slack,
    Webhook,
    Stream,
}

/// Where an integration delivers: the transport, its destination and its credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "type")]
    pub endpoint_type: EndpointType,
    pub configuration: JsonValue,
    pub status: Status,
    pub created_at: String,
    pub updated_at: String,
}

impl Endpoint {
    pub fn new(
        name: String,
        description: String,
        endpoint_type: EndpointType,
        configuration: JsonValue,
    ) -> Self {
        let created_at = now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description,
            endpoint_type,
            configuration,
            status: Status::Active,
            updated_at: created_at.clone(),
            created_at,
        }
    }
}

impl StorableEntity for Endpoint {
    fn id(&self) -> &str {
        &self.id
    }
}

impl Definition for Endpoint {
    fn created_at(&self) -> &str {
        &self.created_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn webhook() -> Endpoint {
        Endpoint::new(
            "Ops webhook".to_string(),
            "Posts to ops".to_string(),
            EndpointType::Webhook,
            json!({"url": "https://ops.example.com/hook"}),
        )
    }

    #[test]
    fn a_new_endpoint_is_active_with_its_own_id() {
        let first = webhook();
        let second = webhook();

        assert_eq!(first.status, Status::Active);
        assert_eq!(first.name, "Ops webhook");
        assert_eq!(first.configuration["url"], "https://ops.example.com/hook");
        assert!(uuid::Uuid::parse_str(&first.id).is_ok());
        assert_ne!(first.id, second.id);
        assert_eq!(first.created_at, first.updated_at);
    }

    #[test]
    fn serializes_its_type_and_status_by_name() {
        let value = serde_json::to_value(webhook()).expect("serializes");

        assert_eq!(value["type"], "webhook");
        assert_eq!(value["status"], "active");
        assert!(
            value
                .get("endpoint_type")
                .is_none()
        );
    }

    #[test]
    fn refuses_an_unknown_type() {
        let mut value = serde_json::to_value(webhook()).expect("serializes");
        value["type"] = json!("sms");

        assert!(serde_json::from_value::<Endpoint>(value).is_err());
    }
}
