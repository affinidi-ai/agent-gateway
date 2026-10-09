use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

/// Represents the type of gateway
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GatewayType {
    /// The local gateway (this instance)
    #[serde(rename = "self")]
    SelfGateway,
    /// A remote gateway
    #[default]
    Remote,
}

/// Represents the status of a gateway
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GatewayStatus {
    #[default]
    Active,
    Pending,
    #[serde(rename = "awaiting-approval")]
    AwaitingApproval,
    Disabled,
    Failed,
}

/// Represents how the gateway record was created
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum GatewayCreationType {
    /// Created by user accepting an OOB invitation
    #[default]
    User,
    /// Created automatically when remote accepted our connection point
    System,
}

/// Gateway-level OPA policy configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayOpaPolicyConfig {
    /// Whether the gateway-level OPA policy is enabled
    pub enabled: bool,

    /// Rego policy content
    #[serde(default)]
    pub policy: String,

    /// ID of the policy definition this config was created from (UI state for round-tripping)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_definition_id: Option<String>,

    /// Additional policy definition ids enforced as a deny-overrides set
    /// alongside `policy_definition_id` (all must allow; any deny blocks).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_definition_ids: Vec<String>,
}

/// Which local surfaces a Remote gateway may reach over Fabric. The tenant
/// rule applies on top of every mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExposureMode {
    /// Every active surface.
    All,
    /// No surface.
    None,
    /// Only the surfaces in `exposed_channels`.
    List,
}

/// How a remote gateway's attested `issuer_did` was established.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IssuerDidSource {
    /// Verified from the issuer attestation carried in the pairing handshake.
    Handshake,
    /// Verified from a `gateway-issuer-response` to a later issuer request.
    Exchange,
}

/// The issuer DIDs a remote gateway's identity presentations may come from:
/// the attested one plus any an operator trusts for that connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIssuers {
    pub attested: Option<String>,
    pub trusted: Vec<String>,
}

impl PeerIssuers {
    pub fn accepts(
        &self,
        issuer_did: &str,
    ) -> bool {
        self.attested.as_deref() == Some(issuer_did)
            || self
                .trusted
                .iter()
                .any(|trusted| trusted == issuer_did)
    }
}

impl std::fmt::Display for PeerIssuers {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let mut issuers: Vec<&str> = self
            .attested
            .iter()
            .map(String::as_str)
            .collect();
        issuers.extend(
            self.trusted
                .iter()
                .map(String::as_str),
        );
        write!(f, "[{}]", issuers.join(", "))
    }
}

/// Represents a gateway record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    /// Unique identifier for this gateway
    pub id: String,

    /// Management-plane tenant ownership. Missing means appliance-global.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Gateway name
    pub name: String,

    /// Gateway description
    pub description: String,

    /// Decentralized Identifier (DID) for this gateway
    pub did: String,

    /// For a remote gateway: the DID the peer signs identity credentials
    /// with, proven by a verified issuer attestation. `None` until the
    /// attestation has been exchanged. Established by the gateway, never
    /// set by an operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,

    /// How `issuer_did` was established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did_source: Option<IssuerDidSource>,

    /// For a remote gateway: issuer DIDs an operator trusts for identity
    /// presentations arriving over **this** connection, in addition to the
    /// attested `issuer_did`. Scoped to the connection: the same DID must be
    /// added on every connection it should be accepted from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_issuer_dids: Vec<String>,

    /// Type of gateway (self or remote)
    pub gateway_type: GatewayType,

    /// Status of the gateway
    pub status: GatewayStatus,

    /// How this gateway record was created (user or system)
    #[serde(default)]
    pub creation_type: GatewayCreationType,

    /// Timestamp when this record was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when this record was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Surface ids exposed to this remote gateway in `List` mode.
    #[serde(default)]
    pub exposed_channels: Vec<String>,

    /// Exposure mode of a remote gateway. Missing on records that predate the
    /// mode until the boot migration persists it; see `exposure`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure_mode: Option<ExposureMode>,

    /// Gateway-level OPA policy configuration
    /// For self gateway: enforced on ALL inbound traffic
    /// For remote gateways: enforced on outbound traffic to that gateway
    #[serde(default)]
    pub opa_policy_config: Option<GatewayOpaPolicyConfig>,
}

impl Gateway {
    pub fn new(
        name: String,
        description: String,
        did: String,
        gateway_type: GatewayType,
    ) -> Self {
        Self::new_with_creation_type(name, description, did, gateway_type, GatewayCreationType::User)
    }

    pub fn new_with_creation_type(
        name: String,
        description: String,
        did: String,
        gateway_type: GatewayType,
        creation_type: GatewayCreationType,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: None,
            name,
            description,
            did,
            issuer_did: None,
            issuer_did_source: None,
            trusted_issuer_dids: Vec::new(),
            status: GatewayStatus::Active,
            creation_type,
            created_at: now,
            updated_at: now,
            exposed_channels: Vec::new(),
            exposure_mode: (gateway_type == GatewayType::Remote).then_some(ExposureMode::None),
            gateway_type,
            opa_policy_config: None,
        }
    }

    /// The effective exposure mode. A record without a stored mode keeps the
    /// meaning it had before the mode existed: an empty list is `All`, a
    /// non-empty list is `List`.
    pub fn exposure(&self) -> ExposureMode {
        self.exposure_mode.unwrap_or(
            if self
                .exposed_channels
                .is_empty()
            {
                ExposureMode::All
            } else {
                ExposureMode::List
            },
        )
    }

    /// Whether this peer's exposure admits `surface_id`. The tenant rule is
    /// checked separately.
    pub fn exposes_surface(
        &self,
        surface_id: &str,
    ) -> bool {
        match self.exposure() {
            ExposureMode::All => true,
            ExposureMode::None => false,
            ExposureMode::List => self
                .exposed_channels
                .iter()
                .any(|exposed| exposed == surface_id),
        }
    }

    /// Persist the effective mode of a remote record that predates it.
    /// Returns whether the record changed.
    pub fn migrate_exposure_mode(&mut self) -> bool {
        if self.gateway_type != GatewayType::Remote || self.exposure_mode.is_some() {
            return false;
        }
        self.exposure_mode = Some(self.exposure());
        true
    }
}

impl StorableEntity for Gateway {
    fn id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pre_issuer_did_record_json() -> serde_json::Value {
        serde_json::json!({
            "id": "gw-1",
            "name": "peer",
            "description": "a remote gateway",
            "did": "did:web:peer.example:connection-points:1111",
            "gateway_type": "remote",
            "status": "active",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        })
    }

    #[test]
    fn gateway_json_without_issuer_did_deserialises_to_none() {
        let gateway: Gateway = serde_json::from_value(pre_issuer_did_record_json()).unwrap();

        assert_eq!(gateway.issuer_did, None);
        assert_eq!(gateway.did, "did:web:peer.example:connection-points:1111");
    }

    #[test]
    fn gateway_issuer_did_round_trips() {
        let mut gateway: Gateway = serde_json::from_value(pre_issuer_did_record_json()).unwrap();
        gateway.issuer_did = Some("did:web:peer.example".to_string());

        let json = serde_json::to_value(&gateway).unwrap();
        let restored: Gateway = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(json["issuer_did"], "did:web:peer.example");
        assert_eq!(restored.issuer_did, Some("did:web:peer.example".to_string()));
    }

    #[test]
    fn gateway_json_without_trusted_issuers_deserialises_to_empty() {
        let gateway: Gateway = serde_json::from_value(pre_issuer_did_record_json()).unwrap();

        assert_eq!(gateway.issuer_did_source, None);
        assert!(
            gateway
                .trusted_issuer_dids
                .is_empty()
        );
    }

    #[test]
    fn gateway_trusted_issuers_and_source_round_trip() {
        let mut gateway: Gateway = serde_json::from_value(pre_issuer_did_record_json()).unwrap();
        gateway.issuer_did = Some("did:web:peer.example".to_string());
        gateway.issuer_did_source = Some(IssuerDidSource::Exchange);
        gateway.trusted_issuer_dids = vec!["did:web:relay.example".to_string()];

        let json = serde_json::to_value(&gateway).unwrap();
        let restored: Gateway = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(json["issuer_did_source"], "exchange");
        assert_eq!(json["trusted_issuer_dids"], serde_json::json!(["did:web:relay.example"]));
        assert_eq!(restored.issuer_did_source, Some(IssuerDidSource::Exchange));
        assert_eq!(restored.trusted_issuer_dids, vec!["did:web:relay.example".to_string()]);
    }

    #[test]
    fn new_remote_gateway_exposes_nothing() {
        let gateway = Gateway::new("peer".into(), String::new(), "did:web:peer.example".into(), GatewayType::Remote);

        assert_eq!(gateway.exposure_mode, Some(ExposureMode::None));
        assert!(!gateway.exposes_surface("alpha"));
        assert_eq!(serde_json::to_value(&gateway).unwrap()["exposure_mode"], "none");
    }

    #[test]
    fn new_self_gateway_has_no_exposure_mode() {
        let gateway =
            Gateway::new("self".into(), String::new(), "did:web:self.example".into(), GatewayType::SelfGateway);

        assert_eq!(gateway.exposure_mode, None);
        assert!(
            serde_json::to_value(&gateway)
                .unwrap()
                .get("exposure_mode")
                .is_none()
        );
    }

    #[test]
    fn exposure_modes_admit_the_expected_surfaces() {
        let mut gateway =
            Gateway::new("peer".into(), String::new(), "did:web:peer.example".into(), GatewayType::Remote);
        gateway.exposed_channels = vec!["alpha".into()];

        gateway.exposure_mode = Some(ExposureMode::All);
        assert!(gateway.exposes_surface("alpha"));
        assert!(gateway.exposes_surface("beta"));

        gateway.exposure_mode = Some(ExposureMode::None);
        assert!(!gateway.exposes_surface("alpha"));

        gateway.exposure_mode = Some(ExposureMode::List);
        assert!(gateway.exposes_surface("alpha"));
        assert!(!gateway.exposes_surface("beta"));

        gateway
            .exposed_channels
            .clear();
        assert!(!gateway.exposes_surface("alpha"), "an empty list in list mode reaches nothing");
    }

    #[test]
    fn record_without_mode_keeps_its_previous_meaning() {
        let mut gateway: Gateway = serde_json::from_value(pre_issuer_did_record_json()).unwrap();
        assert_eq!(gateway.exposure_mode, None);
        assert_eq!(gateway.exposure(), ExposureMode::All);
        assert!(gateway.exposes_surface("alpha"));

        gateway.exposed_channels = vec!["alpha".into()];
        assert_eq!(gateway.exposure(), ExposureMode::List);
        assert!(gateway.exposes_surface("alpha"));
        assert!(!gateway.exposes_surface("beta"));
    }

    #[test]
    fn migration_persists_all_for_an_empty_list() {
        let mut gateway: Gateway = serde_json::from_value(pre_issuer_did_record_json()).unwrap();

        assert!(gateway.migrate_exposure_mode());
        assert_eq!(gateway.exposure_mode, Some(ExposureMode::All));
        assert!(
            gateway
                .exposed_channels
                .is_empty()
        );
        assert_eq!(serde_json::to_value(&gateway).unwrap()["exposure_mode"], "all");
    }

    #[test]
    fn migration_keeps_a_non_empty_list_as_list_mode() {
        let mut record = pre_issuer_did_record_json();
        record["exposed_channels"] = serde_json::json!(["alpha", "beta"]);
        let mut gateway: Gateway = serde_json::from_value(record).unwrap();

        assert!(gateway.migrate_exposure_mode());
        assert_eq!(gateway.exposure_mode, Some(ExposureMode::List));
        assert_eq!(gateway.exposed_channels, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn migration_leaves_migrated_and_self_records_unchanged() {
        let mut record = pre_issuer_did_record_json();
        record["exposure_mode"] = serde_json::json!("none");
        let mut migrated: Gateway = serde_json::from_value(record).unwrap();
        assert!(!migrated.migrate_exposure_mode());
        assert_eq!(migrated.exposure_mode, Some(ExposureMode::None));

        let mut self_record = pre_issuer_did_record_json();
        self_record["gateway_type"] = serde_json::json!("self");
        let mut self_gateway: Gateway = serde_json::from_value(self_record).unwrap();
        assert!(!self_gateway.migrate_exposure_mode());
        assert_eq!(self_gateway.exposure_mode, None);
    }

    #[test]
    fn peer_issuers_accept_the_attested_or_a_trusted_issuer_only() {
        let issuers = PeerIssuers {
            attested: Some("did:web:peer.example".to_string()),
            trusted: vec!["did:web:relay.example".to_string()],
        };

        assert!(issuers.accepts("did:web:peer.example"));
        assert!(issuers.accepts("did:web:relay.example"));
        assert!(!issuers.accepts("did:web:other.example"));
        assert_eq!(issuers.to_string(), "[did:web:peer.example, did:web:relay.example]");
    }

    #[test]
    fn peer_issuers_without_attested_or_trusted_accept_nothing() {
        let issuers = PeerIssuers {
            attested: None,
            trusted: Vec::new(),
        };

        assert!(!issuers.accepts("did:web:peer.example"));
        assert_eq!(issuers.to_string(), "[]");
    }

    #[test]
    fn gateway_without_issuer_did_omits_the_field() {
        let gateway = Gateway::new(
            "peer".to_string(),
            String::new(),
            "did:web:peer.example:connection-points:1111".to_string(),
            GatewayType::Remote,
        );

        let json = serde_json::to_value(&gateway).unwrap();

        assert_eq!(gateway.issuer_did, None);
        assert!(
            json.get("issuer_did")
                .is_none(),
            "{json}"
        );
        assert!(
            json.get("issuer_did_source")
                .is_none(),
            "{json}"
        );
        assert!(
            json.get("trusted_issuer_dids")
                .is_none(),
            "{json}"
        );
    }
}
