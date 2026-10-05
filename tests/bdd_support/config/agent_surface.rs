use std::{collections::HashMap, path::Path};

use serde_json::{Map, Value, json};

#[derive(Debug, Clone)]
pub struct AgentSurfaceFixture {
    pub surface_id: String,
    pub name: String,
    pub description: String,
    pub status: String,
    pub access_point: AccessPointFixture,
    pub target: TargetFixture,
    pub outbound_credentials: Vec<Value>,
    pub transit: Option<Value>,
    pub identity_slots: HashMap<String, Value>,
    pub transit_points: HashMap<String, TransitPointFixture>,
    pub mcp_protocol_mode: Option<String>,
    pub mcp_http: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct AccessPointFixture {
    pub listen_address: String,
    pub route: String,
    pub protocol: String,
    pub caller_authentication_methods: Vec<Value>,
    pub inbound_policy_definition_id: Option<String>,
    pub agent_card_path: Option<String>,
    pub didwebvh_identity_id: Option<String>,
    pub caller_trust_check_list: Vec<Value>,
}
impl Default for AccessPointFixture {
    fn default() -> Self {
        Self {
            listen_address: "".to_string(),
            route: "".to_string(),
            protocol: "".to_string(),
            caller_authentication_methods: Vec::new(),
            inbound_policy_definition_id: None,
            agent_card_path: None,
            didwebvh_identity_id: None,
            caller_trust_check_list: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransitPointFixture {
    pub key: String,
    pub name: String,
    pub target_endpoint: Option<String>,
    pub listen_address: Option<String>,
    pub listen_path: Option<String>,
    pub policy: Option<String>,
}

impl Default for TransitPointFixture {
    fn default() -> Self {
        Self {
            key: "default-tp".to_string(),
            name: "default-tp".to_string(),
            target_endpoint: None,
            listen_address: None,
            listen_path: None,
            policy: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetFixture {
    pub endpoint: String,
    pub auth: Option<Value>,
    pub mcp_proxy_id: Option<String>,
    pub a2a_proxy_id: Option<String>,
    pub policy_definition_id: Option<String>,
    pub mcp_tool_policies: Vec<Value>,
    pub mcp_tool_policies_enabled: bool,
    pub mcp_tool_gating: Option<Value>,
    pub identity_injection: Option<Value>,
    pub custom_metadata: Option<Value>,
    pub policy: Option<String>,
    pub response_policy: Option<String>,
    pub trust_check_list: Vec<Value>,
}

impl Default for TargetFixture {
    fn default() -> Self {
        Self {
            endpoint: "".to_string(),
            auth: None,
            mcp_proxy_id: None,
            a2a_proxy_id: None,
            policy_definition_id: None,
            mcp_tool_policies: Vec::new(),
            mcp_tool_policies_enabled: false,
            mcp_tool_gating: None,
            identity_injection: None,
            custom_metadata: None,
            policy: None,
            response_policy: None,
            trust_check_list: Vec::new(),
        }
    }
}

impl AgentSurfaceFixture {
    pub fn new(
        surface_id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        listen_address: impl Into<String>,
        route: impl Into<String>,
        protocol: impl Into<String>,
        target_endpoint: impl Into<String>,
    ) -> Self {
        Self {
            surface_id: surface_id.into(),
            name: name.into(),
            description: description.into(),
            status: "active".to_string(),
            access_point: AccessPointFixture {
                listen_address: listen_address.into(),
                route: route.into(),
                protocol: protocol.into(),
                caller_authentication_methods: Vec::new(),
                inbound_policy_definition_id: None,
                agent_card_path: None,
                didwebvh_identity_id: None,
                caller_trust_check_list: Vec::new(),
            },
            target: TargetFixture {
                endpoint: target_endpoint.into(),
                auth: None,
                mcp_proxy_id: None,
                a2a_proxy_id: None,
                policy_definition_id: None,
                mcp_tool_policies: Vec::new(),
                mcp_tool_policies_enabled: false,
                mcp_tool_gating: None,
                identity_injection: None,
                custom_metadata: None,
                policy: None,
                response_policy: None,
                trust_check_list: Vec::new(),
            },
            outbound_credentials: Vec::new(),
            transit: None,
            identity_slots: HashMap::new(),
            transit_points: HashMap::new(),
            mcp_protocol_mode: None,
            mcp_http: None,
        }
    }

    pub fn with_caller_auth_method(
        mut self,
        method: Value,
    ) -> Self {
        self.access_point
            .caller_authentication_methods
            .push(method);
        self
    }

    pub fn with_inbound_policy_definition_id(
        mut self,
        policy_definition_id: impl Into<String>,
    ) -> Self {
        self.access_point
            .inbound_policy_definition_id = Some(policy_definition_id.into());
        self
    }

    pub fn with_agent_card_path(
        mut self,
        agent_card_path: impl Into<String>,
    ) -> Self {
        self.access_point
            .agent_card_path = Some(agent_card_path.into());
        self
    }

    pub fn with_didwebvh_identity_id(
        mut self,
        identity_id: impl Into<String>,
    ) -> Self {
        self.access_point
            .didwebvh_identity_id = Some(identity_id.into());
        self
    }

    pub fn with_caller_trust_check_element(
        mut self,
        element: Value,
    ) -> Self {
        self.access_point
            .caller_trust_check_list
            .push(element);
        self
    }

    pub fn with_target_trust_check_element(
        mut self,
        element: Value,
    ) -> Self {
        self.target
            .trust_check_list
            .push(element);
        self
    }

    pub fn with_target_auth(
        mut self,
        target_auth: Value,
    ) -> Self {
        self.target.auth = Some(target_auth);
        self
    }

    pub fn with_mcp_proxy_id(
        mut self,
        proxy_id: impl Into<String>,
    ) -> Self {
        self.target.mcp_proxy_id = Some(proxy_id.into());
        self
    }

    pub fn with_a2a_proxy_id(
        mut self,
        proxy_id: impl Into<String>,
    ) -> Self {
        self.target.a2a_proxy_id = Some(proxy_id.into());
        self
    }

    pub fn with_target_policy_definition_id(
        mut self,
        policy_definition_id: impl Into<String>,
    ) -> Self {
        self.target
            .policy_definition_id = Some(policy_definition_id.into());
        self
    }

    pub fn with_mcp_tool_policy(
        mut self,
        tool_name: impl Into<String>,
        policy_definition_id: impl Into<String>,
    ) -> Self {
        self.target
            .mcp_tool_policies
            .push(json!({
                "tool_name": tool_name.into(),
                "policy_definition_id": policy_definition_id.into(),
            }));
        self.target
            .mcp_tool_policies_enabled = true;
        self
    }

    pub fn with_mcp_tool_gating(
        mut self,
        gating: Value,
    ) -> Self {
        self.target.mcp_tool_gating = Some(gating);
        self
    }

    pub fn with_mcp_protocol_mode(
        mut self,
        mode: impl Into<String>,
    ) -> Self {
        self.mcp_protocol_mode = Some(mode.into());
        self
    }

    pub fn with_mcp_http(
        mut self,
        mcp_http: Value,
    ) -> Self {
        self.mcp_http = Some(mcp_http);
        self
    }

    pub fn with_target_identity_injection(
        mut self,
        identity_injection: Value,
    ) -> Self {
        self.target.identity_injection = Some(identity_injection);
        self
    }

    pub fn with_custom_metadata(
        mut self,
        custom_metadata: Value,
    ) -> Self {
        self.target.custom_metadata = Some(custom_metadata);
        self
    }

    pub fn with_identity_slot(
        mut self,
        slot: impl Into<String>,
        value: Value,
    ) -> Self {
        self.identity_slots
            .insert(slot.into(), value);
        self
    }

    pub fn with_outbound_credential(
        mut self,
        value: Value,
    ) -> Self {
        self.outbound_credentials
            .push(value);
        self
    }

    pub fn with_transit(
        mut self,
        value: Value,
    ) -> Self {
        self.transit = Some(value);
        self
    }

    pub fn to_json(&self) -> Value {
        let mut access_point = json!({
            "listen_address": self.access_point.listen_address,
            "route": self.access_point.route,
            "protocol": self.access_point.protocol,
            "publish_to_did_document": false
        });
        if !self
            .access_point
            .caller_authentication_methods
            .is_empty()
        {
            access_point["caller_authentication"] = json!({
                "methods": self.access_point.caller_authentication_methods,
            });
        }
        if let Some(policy_definition_id) = &self
            .access_point
            .inbound_policy_definition_id
        {
            access_point["inbound_policy"] = json!({
                "policy_definition_id": policy_definition_id,
            });
        }
        if let Some(agent_card_path) = &self
            .access_point
            .agent_card_path
        {
            access_point["agent_card_path"] = json!(agent_card_path);
        }
        if let Some(identity_id) = &self
            .access_point
            .didwebvh_identity_id
        {
            access_point["didwebvh_identity"] = json!({ "identity_id": identity_id });
        }
        if !self
            .access_point
            .caller_trust_check_list
            .is_empty()
        {
            access_point["trust_check_list"] = Value::Array(
                self.access_point
                    .caller_trust_check_list
                    .clone(),
            );
        }

        let mut target = json!({
            "endpoint": self.target.endpoint,
            "policy": serde_json::Value::Null,
            "response_policy": serde_json::Value::Null,
            "mcp_tool_policies_enabled": false,
            "identity_injection": {
                 "inject_vp": false
            },
            "mpp_auto_pay": false
        });
        if let Some(auth) = &self.target.auth {
            target["auth"] = auth.clone();
        }
        if let Some(proxy_id) = &self.target.mcp_proxy_id {
            target["mcp_proxy_id"] = json!(proxy_id);
        }
        if let Some(proxy_id) = &self.target.a2a_proxy_id {
            target["a2a_proxy_id"] = json!(proxy_id);
        }
        if let Some(policy_definition_id) = &self
            .target
            .policy_definition_id
        {
            target["policy"] = json!({
                "policy_definition_id": policy_definition_id,
            });
        }
        if self
            .target
            .mcp_tool_policies_enabled
        {
            target["mcp_tool_policies"] = Value::Array(
                self.target
                    .mcp_tool_policies
                    .clone(),
            );
            target["mcp_tool_policies_enabled"] = json!(true);
        }
        if let Some(gating) = &self.target.mcp_tool_gating {
            target["mcp_tool_gating"] = gating.clone();
        }
        if let Some(identity_injection) = &self.target.identity_injection {
            target["identity_injection"] = identity_injection.clone();
        }
        if let Some(custom_metadata) = &self.target.custom_metadata {
            target["custom_metadata"] = custom_metadata.clone();
        }
        if !self
            .target
            .trust_check_list
            .is_empty()
        {
            target["trust_check_list"] = Value::Array(
                self.target
                    .trust_check_list
                    .clone(),
            );
        }

        let mut surface = json!({
            "surface_id": self.surface_id,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "access_point": access_point,
            "target": target,
        });
        if !self
            .outbound_credentials
            .is_empty()
        {
            surface["outbound_credentials"] = Value::Array(
                self.outbound_credentials
                    .clone(),
            );
        }
        if let Some(transit) = &self.transit {
            surface["transit"] = transit.clone();
        }
        if let Some(mode) = &self.mcp_protocol_mode {
            surface["mcp_protocol_mode"] = json!(mode);
        }
        if let Some(mcp_http) = &self.mcp_http {
            surface["mcp_http"] = mcp_http.clone();
        }
        if !self.identity_slots.is_empty() {
            surface["identity_slots"] = Value::Object(
                self.identity_slots
                    .clone()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<Map<String, Value>>(),
            );
        }
        if !self.transit_points.is_empty() {
            let transit_points_json = self
                .transit_points
                .values()
                .map(|tp| {
                    let mut tp_json = serde_json::json!({
                        "id": tp.key.clone(),
                        "alias": tp.name.clone(),
                        "name": tp.name.clone(),
                        "target_endpoint": tp.target_endpoint.clone().unwrap_or_default(),
                        "protocol": "a2a",
                        "listen_address": tp.listen_address.clone().unwrap_or_default(),
                        "listen_path": tp.listen_path.clone().unwrap_or_default(),
                        "require_transit_token": false,
                    });
                    if let Some(policy) = &tp.policy {
                        tp_json["policy"] = serde_json::json!({
                            "policy_definition_id": policy,
                        });
                    }
                    tp_json
                })
                .collect::<Vec<serde_json::Value>>();

            let mut transit = self
                .transit
                .clone()
                .unwrap_or_else(|| serde_json::json!({}));
            if !transit.is_object() {
                transit = serde_json::json!({});
            }
            transit["sign_requests"] = serde_json::json!(true);
            transit["transit_token_mode"] = serde_json::json!("embedded");
            transit["points"] = serde_json::json!(transit_points_json);
            surface["transit"] = transit;
        }
        if let Some(policy) = &self.target.policy {
            surface["target"]["policy"] = serde_json::json!({
                "policy_definition_id": policy,
            });
        }
        if let Some(response_policy) = &self.target.response_policy {
            surface["target"]["response_policy"] = serde_json::json!({
                "policy_definition_id": response_policy,
            });
        }

        surface
    }
}

impl Default for AgentSurfaceFixture {
    fn default() -> Self {
        Self {
            surface_id: "".to_string(),
            name: "".to_string(),
            description: "".to_string(),
            status: "".to_string(),
            access_point: AccessPointFixture {
                listen_address: "".to_string(),
                route: "".to_string(),
                protocol: "".to_string(),
                caller_authentication_methods: Vec::new(),
                inbound_policy_definition_id: None,
                agent_card_path: None,
                didwebvh_identity_id: None,
                caller_trust_check_list: Vec::new(),
            },
            target: TargetFixture {
                endpoint: "".to_string(),
                auth: None,
                mcp_proxy_id: None,
                a2a_proxy_id: None,
                policy_definition_id: None,
                mcp_tool_policies: Vec::new(),
                mcp_tool_policies_enabled: false,
                mcp_tool_gating: None,
                identity_injection: None,
                custom_metadata: None,
                policy: None,
                response_policy: None,
                trust_check_list: Vec::new(),
            },
            outbound_credentials: Vec::new(),
            transit: None,
            identity_slots: HashMap::new(),
            transit_points: HashMap::new(),
            mcp_protocol_mode: None,
            mcp_http: None,
        }
    }
}

pub fn write_agent_surface_fixture(
    surfaces_dir: &Path,
    fixture: &AgentSurfaceFixture,
) {
    std::fs::write(
        surfaces_dir.join(format!("{}.json", fixture.surface_id)),
        serde_json::to_string_pretty(&fixture.to_json()).unwrap(),
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    #[test]
    fn agent_surface_fixture_builds_shared_surface_shape_with_auth_policy_proxy_and_identity() {
        let surface = super::AgentSurfaceFixture::new(
            "alpha",
            "Alpha",
            "BDD surface",
            "http://localhost:32001",
            "/alpha",
            "mcp",
            "proxy://rest-api",
        )
        .with_caller_auth_method(crate::bdd_support::config::source_auth::api_key_source_auth_method_json(
            "x-api-key",
            "source-secret",
        ))
        .with_inbound_policy_definition_id("alpha-inbound-policy")
        .with_target_auth(crate::bdd_support::config::target_auth::static_secret_target_auth_json(
            "target-secret",
            "x-target-api-key",
            "Bearer {secret}",
            "reject",
        ))
        .with_mcp_proxy_id("rest-api")
        .with_target_identity_injection(serde_json::json!({
            "inject_vp": true,
            "type": "from_payload",
            "meta_field": "agentIdentity",
            "json_schema": { "type": "object" }
        }))
        .with_identity_slot(
            "protected",
            serde_json::json!({
                "type": "payload_extraction",
                "meta_field": "serverIdentity",
                "json_schema": { "type": "object" }
            }),
        );

        let surface_json = surface.to_json();

        assert_eq!(surface_json["surface_id"], "alpha");
        assert_eq!(surface_json["name"], "Alpha");
        assert_eq!(surface_json["status"], "active");
        assert_eq!(surface_json["access_point"]["listen_address"], "http://localhost:32001");
        assert_eq!(surface_json["access_point"]["route"], "/alpha");
        assert_eq!(surface_json["access_point"]["protocol"], "mcp");
        assert_eq!(surface_json["access_point"]["caller_authentication"]["methods"][0]["type"], "api_key");
        assert_eq!(surface_json["access_point"]["inbound_policy"]["policy_definition_id"], "alpha-inbound-policy");
        assert_eq!(surface_json["target"]["endpoint"], "proxy://rest-api");
        assert_eq!(surface_json["target"]["mcp_proxy_id"], "rest-api");
        assert_eq!(surface_json["target"]["auth"]["method"]["static_secret"]["secret_id"], "target-secret");
        assert_eq!(surface_json["target"]["identity_injection"]["meta_field"], "agentIdentity");
        assert_eq!(surface_json["identity_slots"]["protected"]["meta_field"], "serverIdentity");
    }

    #[test]
    fn agent_surface_fixture_emits_agent_card_path_only_when_set() {
        let default_surface = super::AgentSurfaceFixture::new(
            "alpha",
            "Alpha",
            "BDD surface",
            "http://localhost:32001",
            "/alpha",
            "a2a",
            "http://upstream.local",
        );
        let default_json = default_surface.to_json();
        assert!(
            default_json["access_point"]
                .get("agent_card_path")
                .is_none(),
            "agent_card_path should be omitted when not set"
        );

        let overridden = super::AgentSurfaceFixture::new(
            "alpha",
            "Alpha",
            "BDD surface",
            "http://localhost:32001",
            "/alpha",
            "a2a",
            "http://upstream.local",
        )
        .with_agent_card_path("/agents/alpha/card.json");
        let overridden_json = overridden.to_json();
        assert_eq!(
            overridden_json["access_point"]["agent_card_path"], "/agents/alpha/card.json",
            "agent_card_path should round-trip into the access_point object"
        );
    }
}
