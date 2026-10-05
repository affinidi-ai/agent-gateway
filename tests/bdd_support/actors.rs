use crate::bdd_support::config::ReservedPort;
use crate::bdd_support::config::agent_surface::TransitPointFixture;
use std::collections::HashMap;
use std::fmt::Debug;

use crate::bdd_support::config::agent_surface::AgentSurfaceFixture;
use crate::bdd_support::config::config_tree::{GatewayBootstrapFixture, PolicyDefinitionFixture};
use crate::bdd_support::gateway_process::GatewayProcess;
use crate::bdd_support::mock_server::{MockAgentFixture, MockServer};

pub const PRIMARY_COLLABORATOR_KEY: &str = "primary";
pub const SECONDARY_COLLABORATOR_KEY: &str = "secondary";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetActorKind {
    ManagedAgent,
    McpServer,
    RestApi,
    ExternalAgent,
}

impl TargetActorKind {
    pub fn from_gherkin_label(label: &str) -> Self {
        match label {
            "managed agent" => Self::ManagedAgent,
            "MCP server" => Self::McpServer,
            "REST API" => Self::RestApi,
            "external agent" => Self::ExternalAgent,
            _ => panic!("unknown target actor kind '{label}'"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetActor {
    pub key: String,
    pub kind: TargetActorKind,
    pub collaborator_key: String,
    pub fixture: Option<MockAgentFixture>,
}

impl PartialEq for TargetActor {
    fn eq(
        &self,
        other: &Self,
    ) -> bool {
        self.key == other.key && self.kind == other.kind && self.collaborator_key == other.collaborator_key
    }
}

impl Eq for TargetActor {}

#[derive(Debug, Clone)]
pub struct SurfaceActor {
    pub key: String,
    pub protocol: String,
    pub route: Option<String>,
    pub target_name: Option<String>,
    pub surface_id: Option<String>,
    pub gateway_binding: Option<String>,
    pub bootstrapped: bool,
    pub fixture: Option<AgentSurfaceFixture>,
}

impl Default for SurfaceActor {
    fn default() -> Self {
        Self {
            key: "default_key".to_string(),
            protocol: "default_protocol".to_string(),
            route: None,
            target_name: None,
            surface_id: None,
            gateway_binding: None,
            bootstrapped: false,
            fixture: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSurfaceBinding {
    pub gateway_index: usize,
    pub surface_id: String,
}

impl TargetSurfaceBinding {
    pub fn new(
        gateway_index: usize,
        surface_id: impl Into<String>,
    ) -> Self {
        Self {
            gateway_index,
            surface_id: surface_id.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyActor {
    pub key: String,
    pub fixture: Option<PolicyDefinitionFixture>,
    pub bootstrapped: bool,
    pub gateway_binding: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TransitPointActor {
    pub key: String,
    pub fixture: Option<TransitPointFixture>,
    pub bootstrapped: bool,
    pub surface_binding: Option<String>,
    pub target_binding: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GatewayInstanceActor {
    pub key: String,
    pub index: usize,
    pub fixture: Option<GatewayBootstrapFixture>,
}

impl PartialEq for GatewayInstanceActor {
    fn eq(
        &self,
        other: &Self,
    ) -> bool {
        self.key == other.key && self.index == other.index
    }
}
impl Eq for GatewayInstanceActor {}

#[derive(Debug, Default, Clone)]
pub struct ActorRegistry {
    surfaces: HashMap<String, SurfaceActor>,
    targets: HashMap<String, TargetActor>,
    target_surface_bindings: HashMap<String, TargetSurfaceBinding>,
    gateway_instances: HashMap<String, GatewayInstanceActor>,
    policies: HashMap<String, PolicyActor>,
    transit_points: HashMap<String, TransitPointActor>,
}

#[derive(Default)]
pub struct RuntimeRegistry {
    pub gateway_instances: HashMap<String, GatewayProcess>,
    pub reserved_ports: HashMap<u16, ReservedPort>,
    pub targets: HashMap<String, MockServer>,
}

impl Debug for RuntimeRegistry {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("RuntimeRegistry")
            .field("gateway_instances", &self.gateway_instances.keys())
            .field("reserved_ports", &self.reserved_ports)
            .field("targets", &self.targets.keys())
            .finish()
    }
}

impl ActorRegistry {
    pub fn put_transit_point(
        &mut self,
        transit_point: TransitPointActor,
    ) {
        if self
            .transit_points
            .contains_key(&transit_point.key)
        {
            panic!("transit point actor '{}' is already registered", transit_point.key);
        }
        self.transit_points
            .insert(transit_point.key.clone(), transit_point);
    }
    pub fn put_policy(
        &mut self,
        policy: PolicyActor,
    ) {
        if self
            .policies
            .contains_key(&policy.key)
        {
            panic!("policy actor '{}' is already registered", policy.key);
        }
        self.policies
            .insert(policy.key.clone(), policy);
    }

    pub fn put_surface(
        &mut self,
        surface: SurfaceActor,
    ) {
        if self
            .surfaces
            .contains_key(&surface.key)
        {
            panic!("surface actor '{}' is already registered", surface.key);
        }
        self.surfaces
            .insert(surface.key.clone(), surface);
    }

    pub fn put_target(
        &mut self,
        target: TargetActor,
    ) {
        if self
            .targets
            .contains_key(&target.key)
        {
            panic!("target actor '{}' is already registered", target.key);
        }
        self.targets
            .insert(target.key.clone(), target);
    }

    pub fn put_gateway_instance(
        &mut self,
        gateway_instance: GatewayInstanceActor,
    ) {
        if self
            .gateway_instances
            .contains_key(&gateway_instance.key)
        {
            panic!("gateway instance actor '{}' is already registered", gateway_instance.key);
        }
        self.gateway_instances
            .insert(gateway_instance.key.clone(), gateway_instance);
    }

    pub fn transit_point_mut(
        &mut self,
        name: &str,
    ) -> Option<&mut TransitPointActor> {
        self.transit_points
            .get_mut(name)
    }

    pub fn surface_mut(
        &mut self,
        name: &str,
    ) -> Option<&mut SurfaceActor> {
        self.surfaces.get_mut(name)
    }

    pub fn target_mut(
        &mut self,
        name: &str,
    ) -> Option<&mut TargetActor> {
        self.targets.get_mut(name)
    }

    pub fn gateway_instance_mut(
        &mut self,
        name: &str,
    ) -> Option<&mut GatewayInstanceActor> {
        self.gateway_instances
            .get_mut(name)
    }

    pub fn policy_mut(
        &mut self,
        key: &str,
    ) -> Option<&mut PolicyActor> {
        self.policies.get_mut(key)
    }

    pub fn surface(
        &self,
        name: &str,
    ) -> Option<&SurfaceActor> {
        self.surfaces.get(name)
    }

    pub fn target(
        &self,
        name: &str,
    ) -> Option<&TargetActor> {
        self.targets.get(name)
    }

    pub fn targets(&self) -> &HashMap<String, TargetActor> {
        &self.targets
    }

    pub fn targets_mut(&mut self) -> &mut HashMap<String, TargetActor> {
        &mut self.targets
    }

    pub fn gateway_instance(
        &self,
        name: &str,
    ) -> Option<&GatewayInstanceActor> {
        self.gateway_instances
            .get(name)
    }

    pub fn gateway_instances(&self) -> &HashMap<String, GatewayInstanceActor> {
        &self.gateway_instances
    }

    pub fn gateway_instances_mut(&mut self) -> &mut HashMap<String, GatewayInstanceActor> {
        &mut self.gateway_instances
    }

    pub fn policy(
        &self,
        key: &str,
    ) -> Option<&PolicyActor> {
        self.policies.get(key)
    }

    pub fn transit_point(
        &self,
        name: &str,
    ) -> Option<&TransitPointActor> {
        self.transit_points.get(name)
    }
    pub fn register_surface_with_target(
        &mut self,
        name: &str,
        protocol: &str,
        route: Option<&str>,
        target_name: Option<&str>,
    ) {
        if let Some(target_name) = target_name {
            self.expect_target(target_name);
        }

        let candidate = SurfaceActor {
            key: name.to_string(),
            protocol: protocol.to_string(),
            route: route.map(str::to_string),
            target_name: target_name.map(str::to_string),
            surface_id: None,
            gateway_binding: None,
            bootstrapped: false,
            fixture: None,
        };

        match self.surfaces.get(name) {
            Some(existing) => assert_compatible_surface(existing, &candidate),
            None => {
                self.surfaces
                    .insert(name.to_string(), candidate);
            }
        }
    }

    pub fn record_surface_id(
        &mut self,
        name: &str,
        surface_id: &str,
    ) {
        if !self
            .surfaces
            .contains_key(name)
        {
            panic!("unknown surface actor '{}'; registered surfaces: {:?}", name, sorted_keys(&self.surfaces));
        }
        self.surfaces
            .get_mut(name)
            .expect("surface actor should exist after contains check")
            .surface_id = Some(surface_id.to_string());
    }

    pub fn surface_id(
        &self,
        name: &str,
    ) -> Option<&str> {
        self.surfaces
            .get(name)
            .unwrap_or_else(|| {
                panic!("unknown surface actor '{}'; registered surfaces: {:?}", name, sorted_keys(&self.surfaces))
            })
            .surface_id
            .as_deref()
    }

    pub fn register_primary_target_with_kind(
        &mut self,
        name: &str,
        kind: TargetActorKind,
    ) {
        self.register_target(name, kind, PRIMARY_COLLABORATOR_KEY);
    }

    pub fn register_secondary_managed_agent(
        &mut self,
        name: &str,
    ) {
        self.register_target(name, TargetActorKind::ManagedAgent, SECONDARY_COLLABORATOR_KEY);
    }

    pub fn register_target_with_key(
        &mut self,
        name: &str,
        kind: TargetActorKind,
        collaborator_key: &str,
    ) {
        self.register_target(name, kind, collaborator_key);
    }

    pub fn target_collaborator_key(
        &self,
        name: &str,
    ) -> &str {
        &self
            .expect_target(name)
            .collaborator_key
    }

    pub fn expect_target_kind(
        &self,
        name: &str,
        kind: TargetActorKind,
    ) {
        let target = self.expect_target(name);
        assert_eq!(target.kind, kind, "target actor '{}' is {:?}, not {:?}", name, target.kind, kind);
    }

    pub fn bind_target_to_surface(
        &mut self,
        name: &str,
        gateway_index: usize,
        surface_id: &str,
    ) {
        self.expect_target(name);
        let candidate = TargetSurfaceBinding::new(gateway_index, surface_id);
        match self
            .target_surface_bindings
            .get(name)
        {
            Some(existing) if existing == &candidate => {}
            Some(existing) => panic!(
                "target actor '{}' is already bound to gateway {} surface '{}', cannot bind to gateway {} surface '{}'",
                name, existing.gateway_index, existing.surface_id, candidate.gateway_index, candidate.surface_id
            ),
            None => {
                self.target_surface_bindings
                    .insert(name.to_string(), candidate);
            }
        }
    }

    pub fn target_surface_binding(
        &self,
        name: &str,
    ) -> &TargetSurfaceBinding {
        self.expect_target(name);
        self.target_surface_bindings
            .get(name)
            .unwrap_or_else(|| {
                panic!(
                    "target actor '{}' is not bound to a surface; bound target actors: {:?}",
                    name,
                    sorted_keys(&self.target_surface_bindings)
                )
            })
    }

    pub fn register_gateway_instance(
        &mut self,
        name: &str,
        index: usize,
    ) {
        let candidate = GatewayInstanceActor {
            key: name.to_string(),
            index,
            fixture: None,
        };
        match self
            .gateway_instances
            .get(name)
        {
            Some(existing) if existing == &candidate => {}
            Some(existing) => panic!(
                "gateway instance actor '{}' is already registered at index {}, cannot use index {}",
                name, existing.index, index
            ),
            None => {
                self.gateway_instances
                    .insert(name.to_string(), candidate);
            }
        }
    }

    pub fn gateway_instance_index(
        &self,
        name: &str,
    ) -> usize {
        self.gateway_instances
            .get(name)
            .unwrap_or_else(|| {
                panic!(
                    "unknown gateway instance actor '{}'; registered gateway instances: {:?}",
                    name,
                    sorted_keys(&self.gateway_instances)
                )
            })
            .index
    }

    fn register_target(
        &mut self,
        name: &str,
        kind: TargetActorKind,
        collaborator_key: &str,
    ) {
        let candidate = TargetActor {
            key: name.to_string(),
            kind,
            collaborator_key: collaborator_key.to_string(),
            fixture: None,
        };
        match self.targets.get(name) {
            Some(existing) if existing == &candidate => {}
            Some(existing) => panic!(
                "target actor '{}' is already registered as {:?}, cannot register as {:?}",
                name, existing, candidate
            ),
            None => {
                self.targets
                    .insert(name.to_string(), candidate);
            }
        }
    }

    fn expect_target(
        &self,
        name: &str,
    ) -> &TargetActor {
        self.targets
            .get(name)
            .unwrap_or_else(|| {
                panic!("unknown target actor '{}'; registered target actors: {:?}", name, sorted_keys(&self.targets))
            })
    }

    fn registered_target_names(&self) -> Vec<&str> {
        sorted_keys(&self.targets)
    }
}

fn assert_compatible_surface(
    existing: &SurfaceActor,
    candidate: &SurfaceActor,
) {
    assert_optional_field_compatible("surface protocol", &existing.protocol, &candidate.protocol, &existing.key);
    assert_optional_field_compatible(
        "surface route",
        existing
            .route
            .as_deref()
            .unwrap_or_default(),
        candidate
            .route
            .as_deref()
            .unwrap_or_default(),
        &existing.key,
    );
    assert_optional_field_compatible(
        "surface target",
        existing
            .target_name
            .as_deref()
            .unwrap_or_default(),
        candidate
            .target_name
            .as_deref()
            .unwrap_or_default(),
        &existing.key,
    );
}

fn assert_optional_field_compatible(
    field: &str,
    existing: &str,
    candidate: &str,
    actor_key: &str,
) {
    if !existing.is_empty() && !candidate.is_empty() && existing != candidate {
        panic!("{} for actor '{}' is already '{}', cannot use '{}'", field, actor_key, existing, candidate);
    }
}

fn sorted_keys<T>(map: &HashMap<String, T>) -> Vec<&str> {
    let mut names: Vec<&str> = map
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    names
}

#[cfg(test)]
mod tests {
    #[test]
    fn registry_resolves_named_target_slots() {
        let mut registry = super::ActorRegistry::default();

        registry.register_primary_target_with_kind("bravo", super::TargetActorKind::ManagedAgent);
        registry.register_secondary_managed_agent("charlie");

        assert_eq!(registry.target_collaborator_key("bravo"), super::PRIMARY_COLLABORATOR_KEY);
        assert_eq!(registry.target_collaborator_key("charlie"), super::SECONDARY_COLLABORATOR_KEY);
    }

    #[test]
    #[should_panic(expected = "unknown target actor 'charlie'")]
    fn registry_rejects_unknown_target_names() {
        let registry = super::ActorRegistry::default();

        registry.target_collaborator_key("charlie");
    }

    #[test]
    #[should_panic(expected = "target actor 'bravo' is already registered")]
    fn registry_rejects_conflicting_target_slots() {
        let mut registry = super::ActorRegistry::default();

        registry.register_primary_target_with_kind("bravo", super::TargetActorKind::ManagedAgent);
        registry.register_secondary_managed_agent("bravo");
    }

    #[test]
    fn registry_registers_surface_target() {
        let mut registry = super::ActorRegistry::default();

        registry.register_primary_target_with_kind("bravo", super::TargetActorKind::McpServer);
        registry.register_surface_with_target("alpha", "mcp", Some("/mcp"), Some("bravo"));
        registry.register_surface_with_target("alpha", "mcp", Some("/mcp"), Some("bravo"));
    }

    #[test]
    fn registry_records_surface_id() {
        let mut registry = super::ActorRegistry::default();

        registry.register_primary_target_with_kind("bravo", super::TargetActorKind::ManagedAgent);
        registry.register_surface_with_target("alpha", "a2a", Some("/example"), Some("bravo"));
        registry.record_surface_id("alpha", "surface-123");

        assert_eq!(registry.surface_id("alpha"), Some("surface-123"));
    }

    #[test]
    #[should_panic(expected = "surface protocol for actor 'alpha' is already 'a2a', cannot use 'mcp'")]
    fn registry_rejects_surface_protocol_mismatch() {
        let mut registry = super::ActorRegistry::default();

        registry.register_primary_target_with_kind("bravo", super::TargetActorKind::ManagedAgent);
        registry.register_surface_with_target("alpha", "a2a", Some("/example"), Some("bravo"));
        registry.register_surface_with_target("alpha", "mcp", Some("/example"), Some("bravo"));
    }

    #[test]
    #[should_panic(expected = "target actor 'bravo' is ManagedAgent, not McpServer")]
    fn registry_rejects_target_kind_mismatch() {
        let mut registry = super::ActorRegistry::default();

        registry.register_primary_target_with_kind("bravo", super::TargetActorKind::ManagedAgent);

        registry.expect_target_kind("bravo", super::TargetActorKind::McpServer);
    }

    #[test]
    #[should_panic(expected = "unknown target actor 'bravo'")]
    fn registry_rejects_surface_target_before_target_registration() {
        let mut registry = super::ActorRegistry::default();

        registry.register_surface_with_target("alpha", "mcp", Some("/mcp"), Some("bravo"));
    }

    #[test]
    fn registry_binds_target_actor_to_g2g_surface() {
        let mut registry = super::ActorRegistry::default();

        registry.register_target_with_key("bravo", super::TargetActorKind::ManagedAgent, "alpha");
        registry.bind_target_to_surface("bravo", 2, "alpha");
        registry.bind_target_to_surface("bravo", 2, "alpha");

        let binding = registry.target_surface_binding("bravo");
        assert_eq!(binding.gateway_index, 2);
        assert_eq!(binding.surface_id, "alpha");
    }

    #[test]
    #[should_panic(expected = "target actor 'bravo' is already bound to gateway 2 surface 'alpha'")]
    fn registry_rejects_conflicting_target_surface_binding() {
        let mut registry = super::ActorRegistry::default();

        registry.register_target_with_key("bravo", super::TargetActorKind::ManagedAgent, "alpha");
        registry.bind_target_to_surface("bravo", 2, "alpha");
        registry.bind_target_to_surface("bravo", 3, "alpha");
    }

    #[test]
    #[should_panic(expected = "target actor 'bravo' is not bound to a surface")]
    fn registry_rejects_unbound_target_surface_lookup() {
        let mut registry = super::ActorRegistry::default();

        registry.register_target_with_key("bravo", super::TargetActorKind::ManagedAgent, "alpha");

        registry.target_surface_binding("bravo");
    }

    #[test]
    fn registry_registers_gateway_instance_actor() {
        let mut registry = super::ActorRegistry::default();

        registry.register_gateway_instance("gateway alpha", 1);
        registry.register_gateway_instance("gateway alpha", 1);

        assert_eq!(registry.gateway_instance_index("gateway alpha"), 1);
    }

    #[test]
    #[should_panic(
        expected = "gateway instance actor 'gateway alpha' is already registered at index 1, cannot use index 2"
    )]
    fn registry_rejects_gateway_instance_index_mismatch() {
        let mut registry = super::ActorRegistry::default();

        registry.register_gateway_instance("gateway alpha", 1);
        registry.register_gateway_instance("gateway alpha", 2);
    }
}
