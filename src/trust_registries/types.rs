use super::did_manager::DidMethod;
use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

/// Represents the status of a trust registry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TrustRegistryStatus {
    #[default]
    Active,
    Disabled,
}

/// Represents the connection status of a trust registry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TrustRegistryConnectionStatus {
    /// Connection is being established via OOB handshake
    #[default]
    Connecting,
    /// Setup message sent, waiting for TR admin to approve the connection
    #[serde(rename = "awaiting_approval")]
    AwaitingApproval,
    /// Connection established and ready for communication
    Connected,
    /// Connection was previously established but is now disconnected
    Disconnected,
    /// Connection attempt failed
    Failed,
}

/// Represents a trust registry record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRegistry {
    /// Unique identifier for this trust registry
    pub id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Trust registry name
    pub name: String,

    /// Trust registry description
    pub description: String,

    /// OOB invitation URL from the trust registry's connection point
    pub oob_url: String,

    /// The trust registry's DID (discovered from OOB handshake)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,

    /// The canonical DID of the trust registry (extracted from OOB URL `main_did` query param).
    /// This is the DID that agents reference in their trust-registry extensions.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub main_did: Option<String>,

    /// The gateway's per-registry did:web identity (created during OOB handshake)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_did: Option<String>,

    /// The trust registry's secure DID (discovered from OOB handshake connection-accepted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_did: Option<String>,

    /// Mediator URL extracted from OOB invitation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediator_url: Option<String>,

    /// Mediator DID resolved from the mediator URL during OOB handshake
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediator_did: Option<String>,

    /// DID method to use for the per-registry identity (web or peer)
    #[serde(default)]
    pub did_method: DidMethod,

    /// Connection status of the trust registry
    pub connection_status: TrustRegistryConnectionStatus,

    /// Status of the trust registry
    pub status: TrustRegistryStatus,

    /// Timestamp when this record was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when this record was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl TrustRegistry {
    pub fn new(
        name: String,
        description: String,
        oob_url: String,
        did_method: DidMethod,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: None,
            name,
            description,
            oob_url,
            did: None,
            main_did: None,
            our_did: None,
            registry_did: None,
            mediator_url: None,
            mediator_did: None,
            did_method,
            connection_status: TrustRegistryConnectionStatus::Connecting,
            status: TrustRegistryStatus::Active,
            created_at: now,
            updated_at: now,
        }
    }
}

impl StorableEntity for TrustRegistry {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Request body for a TRQP query (authorization or recognition)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrqpQueryRequest {
    /// The DID of the authority who authorised/recognised the entity
    pub authority_id: String,
    /// The DID of the entity being verified
    pub entity_id: String,
    /// The action the entity is authorised/recognised to perform
    pub action: String,
    /// The resource identifier where the entity can perform the action
    pub resource: String,
}

/// Response body for a TRQP authorization query.
///
/// Per the [TRQP authorization response schema][spec], the registry echoes
/// the query fields (`authority_id`/`entity_id`/`action`/`resource`)
/// alongside the `authorized` decision. They are modelled as optional so
/// registries that omit them still parse, but when a registry does return
/// them we validate they match the request via
/// [`Self::validate_echoes_request`] — a mismatch means the registry
/// answered a different question than we asked, which we surface as a
/// parse error rather than silently trusting the decision.
///
/// [spec]: https://trustoverip.github.io/tswg-trust-registry-protocol/approved/#authorization-response-schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrqpAuthorizationResponse {
    pub authorized: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_requested: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_evaluated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl TrqpAuthorizationResponse {
    /// If the registry echoed any of the query fields, they MUST match the
    /// request. Absent echoes are tolerated (some registries return only
    /// the decision). Returns the first mismatching field on failure.
    pub fn validate_echoes_request(
        &self,
        request: &TrqpQueryRequest,
    ) -> Result<(), TrqpEchoMismatch> {
        check_echo("authority_id", self.authority_id.as_deref(), &request.authority_id)?;
        check_echo("entity_id", self.entity_id.as_deref(), &request.entity_id)?;
        check_echo("action", self.action.as_deref(), &request.action)?;
        check_echo("resource", self.resource.as_deref(), &request.resource)?;
        Ok(())
    }
}

/// Response body for a TRQP recognition query.
///
/// Same shape as [`TrqpAuthorizationResponse`] but keyed on `recognized`.
/// See that type for the echo-validation contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrqpRecognitionResponse {
    pub recognized: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_requested: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_evaluated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl TrqpRecognitionResponse {
    /// See [`TrqpAuthorizationResponse::validate_echoes_request`].
    pub fn validate_echoes_request(
        &self,
        request: &TrqpQueryRequest,
    ) -> Result<(), TrqpEchoMismatch> {
        check_echo("authority_id", self.authority_id.as_deref(), &request.authority_id)?;
        check_echo("entity_id", self.entity_id.as_deref(), &request.entity_id)?;
        check_echo("action", self.action.as_deref(), &request.action)?;
        check_echo("resource", self.resource.as_deref(), &request.resource)?;
        Ok(())
    }
}

/// A TRQP response echoed one of the query fields with a value that does
/// not match what the gateway asked. Surfaces as a parse error at the
/// transport boundary so the caller sees "the registry answered a
/// different question" rather than silently accepting the decision.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("trqp response echoed {field}='{got}' but request had '{expected}'")]
pub struct TrqpEchoMismatch {
    pub field: &'static str,
    pub expected: String,
    pub got: String,
}

fn check_echo(
    field: &'static str,
    got: Option<&str>,
    expected: &str,
) -> Result<(), TrqpEchoMismatch> {
    if let Some(got) = got
        && got != expected
    {
        return Err(TrqpEchoMismatch {
            field,
            expected: expected.to_string(),
            got: got.to_string(),
        });
    }
    Ok(())
}

/// Request body for TR Admin create/update record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrAdminRecordRequest {
    pub authority_id: String,
    pub entity_id: String,
    pub action: String,
    pub resource: String,
    pub record_type: String,
    pub authorized: bool,
    pub recognized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// Response body for TR Admin record operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrAdminRecordResponse {
    pub authority_id: String,
    pub entity_id: String,
    pub action: String,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recognized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

/// Response body for TR Admin list records
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrAdminListRecordsResponse {
    pub count: usize,
    pub records: Vec<TrAdminRecordResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRegistryListRecordsResponse {
    pub count: usize,
    pub records: Vec<TrAdminRecordResponse>,
    pub round_trip_ms: u64,
}

impl TrustRegistryListRecordsResponse {
    pub fn from_list_records(
        response: TrAdminListRecordsResponse,
        round_trip_ms: u64,
    ) -> Self {
        Self {
            count: response.count,
            records: response.records,
            round_trip_ms,
        }
    }
}

/// Alias for a trust registry record returned from search_records / list_records.
/// Uses the same shape as TrAdminRecordResponse for consistency.
#[allow(dead_code)]
pub type TrustRecord = TrAdminRecordResponse;

/// DIDComm problem report for trust registry errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrProblemReport {
    pub code: String,
    pub comment: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Some trust registries return only the decision boolean on the
    /// not-matched path (`{ "recognized": false }`). The decision field is
    /// the registry's only TRQP obligation, so a minimal payload must parse.
    #[test]
    fn recognition_response_parses_with_only_decision_field() {
        let body = serde_json::json!({ "recognized": false });
        let parsed: TrqpRecognitionResponse =
            serde_json::from_value(body).expect("minimal recognition response must parse");
        assert!(!parsed.recognized);
    }

    /// Same contract for the authorization variant.
    #[test]
    fn authorization_response_parses_with_only_decision_field() {
        let body = serde_json::json!({ "authorized": true });
        let parsed: TrqpAuthorizationResponse =
            serde_json::from_value(body).expect("minimal authorization response must parse");
        assert!(parsed.authorized);
    }

    /// Registry-supplied echo fields (`authority_id`/`entity_id`/`action`/
    /// `resource`) are optional per the TRQP spec. When present they parse
    /// into the response struct so callers can validate them against the
    /// request via [`TrqpRecognitionResponse::validate_echoes_request`].
    #[test]
    fn recognition_response_parses_echo_fields() {
        let body = serde_json::json!({
            "authority_id": "did:web:auth",
            "entity_id": "did:web:ent",
            "action": "is",
            "resource": "ownedAgent",
            "recognized": true,
        });
        let parsed: TrqpRecognitionResponse =
            serde_json::from_value(body).expect("populated recognition response must parse");
        assert!(parsed.recognized);
        assert_eq!(parsed.authority_id.as_deref(), Some("did:web:auth"));
        assert_eq!(parsed.entity_id.as_deref(), Some("did:web:ent"));
        assert_eq!(parsed.action.as_deref(), Some("is"));
        assert_eq!(parsed.resource.as_deref(), Some("ownedAgent"));
    }

    /// Absent echo fields must not trip the validator — some registries
    /// return only the decision.
    #[test]
    fn validate_echoes_request_accepts_absent_echoes() {
        let request = TrqpQueryRequest {
            authority_id: "did:web:auth".to_string(),
            entity_id: "did:web:ent".to_string(),
            action: "is".to_string(),
            resource: "ownedAgent".to_string(),
        };
        let resp: TrqpRecognitionResponse = serde_json::from_value(serde_json::json!({ "recognized": true })).unwrap();
        assert!(
            resp.validate_echoes_request(&request)
                .is_ok()
        );
    }

    /// A present echo field that does not match the request is rejected —
    /// the registry answered a different question than we asked.
    #[test]
    fn validate_echoes_request_rejects_mismatched_echo() {
        let request = TrqpQueryRequest {
            authority_id: "did:web:auth".to_string(),
            entity_id: "did:web:ent".to_string(),
            action: "is".to_string(),
            resource: "ownedAgent".to_string(),
        };
        let resp: TrqpAuthorizationResponse = serde_json::from_value(serde_json::json!({
            "authorized": true,
            "entity_id": "did:web:someone-else",
        }))
        .unwrap();
        let err = resp
            .validate_echoes_request(&request)
            .expect_err("mismatched entity_id must be rejected");
        assert_eq!(err.field, "entity_id");
        assert_eq!(err.expected, "did:web:ent");
        assert_eq!(err.got, "did:web:someone-else");
    }

    /// A response missing the decision field must still be rejected —
    /// echoes are decorative, but the decision is the contract.
    #[test]
    fn recognition_response_rejects_missing_decision_field() {
        let body = serde_json::json!({ "authority_id": "did:web:auth" });
        let result: Result<TrqpRecognitionResponse, _> = serde_json::from_value(body);
        assert!(result.is_err(), "missing `recognized` must remain a parse error");
    }
}
