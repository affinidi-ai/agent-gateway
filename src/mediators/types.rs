use serde::{Deserialize, Serialize};

use crate::storage::filesystem::StorableEntity;

/// Represents the status of a mediator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MediatorStatus {
    #[default]
    Active,
    Disabled,
}

/// Represents a mediator record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mediator {
    /// Unique identifier for this mediator
    pub id: String,

    /// Management-plane tenant ownership. Missing means appliance-global.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Mediator name
    pub name: String,

    /// Mediator description
    pub description: String,

    /// Decentralized Identifier (DID) for this mediator
    pub did: String,

    /// Status of the mediator
    pub status: MediatorStatus,

    /// Resolved DID Document (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,

    /// Our DID for connecting to this mediator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_did: Option<String>,

    /// Secrets for our DID (stored as JSON array)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_secrets: Option<serde_json::Value>,

    /// Timestamp when this record was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when this record was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl StorableEntity for Mediator {
    fn id(&self) -> &str {
        &self.id
    }
}

impl Mediator {
    pub fn new(
        name: String,
        description: String,
        did: String,
        did_document: Option<serde_json::Value>,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: None,
            name,
            description,
            did,
            status: MediatorStatus::Active,
            did_document,
            our_did: None,
            our_secrets: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Response-only projection of a [`Mediator`] with no `our_secrets` field, so private
/// key material cannot reach the wire. The exhaustive destructuring in `From` makes a
/// new `Mediator` field a compile error here until it is deliberately exposed or dropped.
#[derive(Debug, Clone, Serialize)]
pub struct MediatorResponse {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    pub did: String,
    pub status: MediatorStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_did: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<Mediator> for MediatorResponse {
    fn from(mediator: Mediator) -> Self {
        let Mediator {
            id,
            tenant_id,
            name,
            description,
            did,
            status,
            did_document,
            our_did,
            our_secrets: _,
            created_at,
            updated_at,
        } = mediator;
        Self {
            id,
            tenant_id,
            name,
            description,
            did,
            status,
            did_document,
            our_did,
            created_at,
            updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mediator_with_secrets() -> Mediator {
        let mut mediator = Mediator::new(
            "Test Mediator".to_string(),
            "description".to_string(),
            "did:web:example.com".to_string(),
            Some(json!({ "id": "did:web:example.com" })),
        );
        mediator.tenant_id = Some("tenant-a".to_string());
        mediator.our_did = Some("did:peer:2.abc".to_string());
        mediator.our_secrets = Some(json!([
            {
                "id": "did:peer:2.abc#key-1",
                "type": "JsonWebKey2020",
                "privateKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "public-component",
                    "d": "PRIVATE_KEY_MATERIAL"
                }
            }
        ]));
        mediator
    }

    #[test]
    fn response_json_omits_our_secrets_and_private_key_material() {
        let response = MediatorResponse::from(mediator_with_secrets());

        let value = serde_json::to_value(&response).expect("serialize response");
        assert!(
            value
                .get("our_secrets")
                .is_none()
        );
        assert_eq!(value["our_did"], json!("did:peer:2.abc"));

        let serialized = value.to_string();
        assert!(!serialized.contains("our_secrets"));
        assert!(!serialized.contains("privateKeyJwk"));
        assert!(!serialized.contains("PRIVATE_KEY_MATERIAL"));
    }

    #[test]
    fn entity_json_still_carries_our_secrets_for_storage() {
        let value = serde_json::to_value(mediator_with_secrets()).expect("serialize mediator");

        assert!(
            value
                .get("our_secrets")
                .is_some()
        );
    }

    #[test]
    fn response_json_preserves_public_fields() {
        let original = mediator_with_secrets();
        let value = serde_json::to_value(MediatorResponse::from(original.clone())).expect("serialize response");

        assert_eq!(value["id"], json!(original.id));
        assert_eq!(value["tenant_id"], json!("tenant-a"));
        assert_eq!(value["name"], json!("Test Mediator"));
        assert_eq!(value["description"], json!("description"));
        assert_eq!(value["did"], json!("did:web:example.com"));
        assert_eq!(value["status"], json!("active"));
        assert_eq!(value["did_document"], json!({ "id": "did:web:example.com" }));
        assert_eq!(value["created_at"], json!(original.created_at));
        assert_eq!(value["updated_at"], json!(original.updated_at));
    }
}
