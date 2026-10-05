use std::collections::HashMap;

use crate::bdd_support::admin_client::AdminApiClient;
use cucumber::World;

pub use crate::bdd_support::admin_client::RecordedResponse;

use crate::bdd_support::actors::{
    ActorRegistry, PRIMARY_COLLABORATOR_KEY, RuntimeRegistry, SECONDARY_COLLABORATOR_KEY, TargetActorKind,
};
use crate::bdd_support::gateway_process::GatewayProcess;
use crate::bdd_support::jwt::JwksServer;
use crate::bdd_support::mock_server::{MockResponse, MockServer, ReceivedRequest};
use crate::bdd_support::temp::TempDirGuard;

pub use crate::bdd_support::config::single_surface_fixture::{
    ApiKeyProviderSourceAuthConfig, ApiKeySourceAuthConfig, CredentialProviderKind, DelegatedCredentialInjection,
    JwtSourceAuthConfig, RequestPolicyFixture, SurfaceConfigBuilder, SurfaceCredentialDelegationConfig,
    SurfaceCustomMetadataConfig, SurfaceSourceAuthConfig, SurfaceTargetAuthConfig, SurfaceTransitPointConfig,
    TransitPointHeaderMetadataMappingRow, TransitPointManagedIdentityConfig,
};

use tempfile::TempDir;

#[derive(Debug, Clone, Default)]
pub struct TargetObservations {
    pub requests: Vec<ReceivedRequest>,
}

impl TargetObservations {
    pub(crate) fn from_requests(requests: Vec<ReceivedRequest>) -> Self {
        Self { requests }
    }
}

#[derive(Debug, Clone)]
pub struct ObservedTarget {
    pub configured_response: MockResponse,
    pub observations: Option<TargetObservations>,
    pub unreachable: bool,
}

impl ObservedTarget {
    pub(crate) fn with_response(response: impl Into<MockResponse>) -> Self {
        Self {
            configured_response: response.into(),
            observations: None,
            unreachable: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MockCollaborator {
    pub name: String,
    pub kind: Option<TargetActorKind>,
    pub target: ObservedTarget,
}

impl MockCollaborator {
    pub(crate) fn new(
        name: &str,
        kind: Option<TargetActorKind>,
        response: impl Into<MockResponse>,
    ) -> Self {
        Self {
            name: name.to_string(),
            kind,
            target: ObservedTarget::with_response(response),
        }
    }
}

pub fn get_default_temp_dir() -> TempDir {
    let mut builder = tempfile::Builder::default();
    //get prefix from env variable or use default
    let prefix = std::env::var("BDD_TEMP_DIR_PREFIX").unwrap_or_else(|_| "bdd-test-".to_string());
    builder.prefix(&prefix);

    let temp_dir_root = std::env::var("BDD_TEMP_DIR_ROOT");
    if let Ok(temp_dir_root) = temp_dir_root {
        std::fs::create_dir_all(&temp_dir_root).expect("Temporary directory root should be created");
        builder
            .tempdir_in(temp_dir_root)
            .expect("Temporary directory should be created in BDD_TEMP_DIR_ROOT")
    } else {
        builder
            .tempdir()
            .expect("Temporary directory should be created")
    }
}

#[derive(Debug, World)]
#[world(init = Self::new)]
pub struct SurfaceWorld {
    pub actors: ActorRegistry,
    pub collaborators: HashMap<String, MockCollaborator>,
    pub infra: Option<ScenarioInfra>,
    pub surface_config: SurfaceConfigBuilder,
    pub sent_body: Option<serde_json::Value>,
    pub caller_response: Option<RecordedResponse>,
    pub admin_client: Option<AdminApiClient>,
    pub created_surface_id: Option<String>,
    pub surface_under_test_id: Option<String>,
    pub admin_response: Option<RecordedResponse>,
    pub surface_lookup_response: Option<RecordedResponse>,
    pub collected_dids: Vec<String>,
    pub caller_claims: HashMap<String, serde_json::Map<String, serde_json::Value>>,
    pub sts_client_secrets: HashMap<String, String>,
    pub sts_assertions: HashMap<String, String>,
    pub sts_id_jags: HashMap<String, String>,
    pub sts_issued_tokens: HashMap<String, String>,
    pub gateway_issuer_did: Option<String>,
    pub operator_roles: HashMap<String, String>,
    pub operator_clients: HashMap<String, AdminApiClient>,
    pub human_clients: HashMap<String, Vec<AdminApiClient>>,
    pub terms_enabled: bool,
    pub affinidi_cache_seeded: bool,
    pub affinidi_well_available: bool,
    pub affinidi_terms_manifest: serde_json::Value,
    pub caller_did: Option<String>,
    pub external_agent_card_did: Option<String>,
    pub derived_identity_schema: Option<serde_json::Value>,
    pub captured_mcp_identity_schema: Option<serde_json::Value>,
    pub sse_endpoint_path: Option<String>,
    pub sse_responses: Vec<serde_json::Value>,
    /// A modern MCP response read incrementally by later steps.
    pub mcp_stream: Option<reqwest::Response>,
    pub mcp_stream_buffer: String,
    pub mcp_stream_closed_after_final: bool,
    /// The query of the last OAuth callback sent with a gateway-issued state.
    pub oauth_callback_query: Option<String>,
    pub temp_dir: TempDir,
    pub debug: bool,
    pub runtimes: RuntimeRegistry,
}

impl SurfaceWorld {
    pub(crate) fn new() -> Self {
        let default_response = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": "ok"});
        let is_debug = std::env::var("DEBUG")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

        Self {
            actors: ActorRegistry::default(),
            collaborators: default_collaborators(default_response.clone()),
            infra: None,
            surface_config: SurfaceConfigBuilder::default(),
            sent_body: None,
            caller_response: None,
            admin_client: None,
            created_surface_id: None,
            surface_under_test_id: None,
            admin_response: None,
            surface_lookup_response: None,
            collected_dids: Vec::new(),
            caller_claims: HashMap::new(),
            sts_client_secrets: HashMap::new(),
            sts_assertions: HashMap::new(),
            sts_id_jags: HashMap::new(),
            sts_issued_tokens: HashMap::new(),
            gateway_issuer_did: None,
            operator_roles: HashMap::new(),
            operator_clients: HashMap::new(),
            human_clients: HashMap::new(),
            terms_enabled: false,
            affinidi_cache_seeded: false,
            affinidi_well_available: true,
            affinidi_terms_manifest: serde_json::json!({
                "schema_version": 1,
                "publication_sequence": 1,
                "document_id": "affinidi-terms",
                "version_id": "affinidi:3.2",
                "version": "3.2",
                "title": "Affinidi Terms and Conditions",
                "url": "https://www.affinidi.com/files/Affinidi_Terms_and_Conditions.pdf",
                "requires_reconsent": true,
                "published_at": "2026-08-31T13:24:23Z"
            }),
            caller_did: None,
            external_agent_card_did: None,
            derived_identity_schema: None,
            captured_mcp_identity_schema: None,
            sse_endpoint_path: None,
            sse_responses: Vec::new(),
            mcp_stream: None,
            mcp_stream_buffer: String::new(),
            mcp_stream_closed_after_final: false,
            oauth_callback_query: None,
            temp_dir: get_default_temp_dir(),
            debug: is_debug,
            runtimes: RuntimeRegistry::default(),
        }
    }

    pub(crate) fn set_primary_target_response(
        &mut self,
        response: impl Into<MockResponse>,
    ) {
        let response = response.into();
        self.collaborator_mut(PRIMARY_COLLABORATOR_KEY)
            .target
            .configured_response = response;
    }

    pub(crate) fn set_secondary_target_response(
        &mut self,
        response: impl Into<MockResponse>,
    ) {
        let response = response.into();
        let (name, kind) = self
            .collaborators
            .get(SECONDARY_COLLABORATOR_KEY)
            .map(|collaborator| (collaborator.name.clone(), collaborator.kind))
            .unwrap_or_else(|| ("alternate target".to_string(), None));
        self.collaborators
            .insert(SECONDARY_COLLABORATOR_KEY.to_string(), MockCollaborator::new(&name, kind, response));
    }

    pub(crate) fn register_primary_collaborator(
        &mut self,
        name: &str,
        kind: TargetActorKind,
    ) {
        self.register_collaborator(PRIMARY_COLLABORATOR_KEY, name, kind);
    }

    pub(crate) fn register_secondary_collaborator(
        &mut self,
        name: &str,
        kind: TargetActorKind,
    ) {
        self.register_collaborator(SECONDARY_COLLABORATOR_KEY, name, kind);
    }

    pub(crate) fn collaborator_target(
        &self,
        key: &str,
    ) -> &ObservedTarget {
        &self.collaborator(key).target
    }

    pub(crate) fn mark_target_unreachable(
        &mut self,
        actor_name: &str,
    ) {
        let key = self
            .actors
            .target_collaborator_key(actor_name)
            .to_string();
        self.collaborator_mut(&key)
            .target
            .unreachable = true;
    }

    pub(crate) fn target_is_unreachable(
        &self,
        key: &str,
    ) -> bool {
        self.collaborators
            .get(key)
            .map(|collaborator| {
                collaborator
                    .target
                    .unreachable
            })
            .unwrap_or(false)
    }

    pub(crate) fn mock_for_target(
        &self,
        actor_name: &str,
    ) -> &MockServer {
        let collaborator_key = self
            .actors
            .target_collaborator_key(actor_name);
        let infra = self
            .infra
            .as_ref()
            .expect("scenario infra must exist before configuring a target mock");
        match collaborator_key {
            key if key == PRIMARY_COLLABORATOR_KEY => &infra.mock,
            key if key == SECONDARY_COLLABORATOR_KEY => infra
                .replacement_mock
                .as_ref()
                .expect("replacement mock must exist before configuring a secondary target"),
            other => panic!("no mock server registered for collaborator key '{}' (actor '{}')", other, actor_name),
        }
    }

    pub(crate) fn record_primary_observations(
        &mut self,
        observations: TargetObservations,
    ) {
        self.collaborator_mut(PRIMARY_COLLABORATOR_KEY)
            .target
            .observations = Some(observations);
    }

    pub(crate) fn record_secondary_observations(
        &mut self,
        observations: Option<TargetObservations>,
    ) {
        if !self
            .collaborators
            .contains_key(SECONDARY_COLLABORATOR_KEY)
        {
            self.collaborators.insert(
                SECONDARY_COLLABORATOR_KEY.to_string(),
                MockCollaborator::new("secondary", None, serde_json::json!({"ok": true})),
            );
        }
        if let Some(collaborator) = self
            .collaborators
            .get_mut(SECONDARY_COLLABORATOR_KEY)
        {
            collaborator
                .target
                .observations = observations;
        }
    }

    fn register_collaborator(
        &mut self,
        key: &str,
        name: &str,
        kind: TargetActorKind,
    ) {
        let collaborator = self.collaborator_mut(key);
        collaborator.name = name.to_string();
        collaborator.kind = Some(kind);
    }

    pub(crate) fn collaborator(
        &self,
        key: &str,
    ) -> &MockCollaborator {
        self.collaborators
            .get(key)
            .unwrap_or_else(|| {
                panic!("unknown mock collaborator key '{}'; registered keys: {:?}", key, self.collaborator_keys())
            })
    }

    fn collaborator_mut(
        &mut self,
        key: &str,
    ) -> &mut MockCollaborator {
        if !self
            .collaborators
            .contains_key(key)
        {
            let response = self
                .collaborators
                .get(PRIMARY_COLLABORATOR_KEY)
                .expect("primary collaborator must exist")
                .target
                .configured_response
                .clone();
            self.collaborators
                .insert(key.to_string(), MockCollaborator::new(key, None, response));
        }
        self.collaborators
            .get_mut(key)
            .expect("mock collaborator should exist after insertion")
    }

    fn collaborator_keys(&self) -> Vec<&str> {
        let mut keys: Vec<&str> = self
            .collaborators
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    pub fn actors_mut(&mut self) -> &mut ActorRegistry {
        &mut self.actors
    }
}

pub(crate) fn mcp_identity_schema_with_field(
    field: &str,
    selected: bool,
) -> serde_json::Value {
    match field {
        "softwareInfo.name" => serde_json::json!({
            "type": "object",
            "properties": {
                "softwareInfo": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "x-identity": selected
                        }
                    }
                }
            }
        }),
        other => panic!("unsupported MCP identity schema field '{other}'"),
    }
}

pub(crate) fn select_identity_schema_field(
    schema: &mut serde_json::Value,
    field: &str,
) {
    match field {
        "softwareInfo.name" => {
            schema["properties"]["softwareInfo"]["properties"]["name"]["x-identity"] = serde_json::json!(true);
        }
        other => panic!("unsupported MCP identity schema field '{other}'"),
    }
}

pub(crate) fn identity_schema_has_field(
    schema: &serde_json::Value,
    field: &str,
) -> bool {
    match field {
        "softwareInfo.name" => schema
            .pointer("/properties/softwareInfo/properties/name")
            .is_some(),
        other => panic!("unsupported MCP identity schema field '{other}'"),
    }
}

fn default_collaborators(default_response: serde_json::Value) -> HashMap<String, MockCollaborator> {
    HashMap::from([(PRIMARY_COLLABORATOR_KEY.to_string(), MockCollaborator::new("target", None, default_response))])
}

pub struct ScenarioInfra {
    pub _temp_dir: TempDirGuard,
    pub gateway: GatewayProcess,
    pub mock: MockServer,
    pub replacement_mock: Option<MockServer>,
    pub affinidi_well: Option<MockServer>,
    pub _jwks_server: Option<JwksServer>,
    pub gateway_port: u16,
    pub outbound_port: u16,
}

impl std::fmt::Debug for ScenarioInfra {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("ScenarioInfra")
            .field("gateway_port", &self.gateway_port)
            .field("outbound_port", &self.outbound_port)
            .finish()
    }
}

pub fn debug_line(
    world: &SurfaceWorld,
    message: &str,
) {
    if world.debug {
        eprintln!("[debug] {}", message);
    }
}
