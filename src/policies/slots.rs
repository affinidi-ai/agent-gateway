//! Every place a surface names a policy definition, as stored, keyed by where
//! it sits, so two versions of a surface can be compared slot by slot. The
//! slots follow what a user wrote on the base surface and in each variant's
//! overrides, not what a request resolves to.

use std::collections::{BTreeMap, HashMap};

use crate::audit::events::PolicySlot;
use crate::config::agent_surface::{AgentSurface, McpToolGatingConfig, McpToolPolicyEntry, PolicyRef, TransitPoint};
use crate::config::agent_surface_variants::SurfaceVariant;
use crate::observability::PolicyScope;

/// Where on a surface a policy is named. Variants and gates are keyed by id, so
/// renaming one is not a policy change. Transit points are keyed by alias: a
/// point saved without its id is given a new one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotKey {
    /// The variant's id, for a variant override.
    pub variant: Option<String>,
    pub slot: PolicySlot,
    /// The decision scope the slot produces ([`PolicyScope::as_str`]).
    pub scope: &'static str,
    /// The alias of the transit point the slot sits on.
    pub point: Option<String>,
    /// The tool's name or the gate's id. Each entry of a list is enforced, so
    /// a name or id repeated in one list is numbered from its second use
    /// (`search#2`).
    pub place: Option<String>,
}

/// The policy named at a slot, with the labels a change record shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotPolicy {
    pub policy_definition_id: String,
    /// The alias of the variant whose override names the policy, or `_base_`
    /// for a base slot.
    pub surface_variant: String,
    /// The tool's name or the gate's name.
    pub place_label: Option<String>,
}

/// Every policy reference of `surface` and of each variant override, as
/// stored. The shared `transit_policy` is left out: nothing ever reads it.
pub fn policy_slots(surface: &AgentSurface) -> BTreeMap<SlotKey, SlotPolicy> {
    let mut slots = Slots {
        found: BTreeMap::new(),
        variant: None,
        point: None,
    };
    let target = &surface.target;
    slots.policy(
        PolicySlot::Inbound,
        PolicyScope::Surface,
        surface
            .access_point
            .inbound_policy
            .as_ref(),
    );
    slots.policy(PolicySlot::Target, PolicyScope::Surface, target.policy.as_ref());
    slots.policy(
        PolicySlot::Response,
        PolicyScope::Response,
        target
            .response_policy
            .as_ref(),
    );
    slots.tools(&target.mcp_tool_policies);
    slots.gates(
        target
            .mcp_tool_gating
            .as_ref(),
    );
    if let Some(transit) = surface.transit.as_ref() {
        slots.transit(
            transit
                .shared
                .opa_policy_definition_id
                .as_deref(),
        );
        slots.points(&transit.points);
    }

    for variant in &surface.variants {
        slots.variant = Some((variant.id.clone(), variant.alias.clone()));
        let overrides = &variant.overrides;
        if let Some(access_point) = overrides
            .access_point
            .as_ref()
        {
            slots.policy(
                PolicySlot::Inbound,
                PolicyScope::Surface,
                access_point
                    .inbound_policy
                    .as_ref(),
            );
        }
        if let Some(target) = overrides.target.as_ref() {
            slots.policy(PolicySlot::Target, PolicyScope::Surface, target.policy.as_ref());
            slots.policy(
                PolicySlot::Response,
                PolicyScope::Response,
                target
                    .response_policy
                    .as_ref(),
            );
            if let Some(tools) = target
                .mcp_tool_policies
                .as_ref()
            {
                slots.tools(tools);
            }
            slots.gates(
                target
                    .mcp_tool_gating
                    .as_ref(),
            );
        }
        if let Some(transit) = overrides.transit.as_ref() {
            if let Some(shared) = transit.shared.as_ref() {
                slots.transit(
                    shared
                        .opa_policy_definition_id
                        .as_deref(),
                );
            }
            if let Some(points) = transit.points.as_ref() {
                slots.points(points);
            }
        }
    }
    slots.found
}

struct Slots {
    found: BTreeMap<SlotKey, SlotPolicy>,
    /// The id and alias of the variant being walked.
    variant: Option<(String, String)>,
    /// The alias of the transit point being walked.
    point: Option<String>,
}

/// `name` as a place key: itself on its first use in a list, numbered after.
fn numbered<'a>(
    seen: &mut HashMap<&'a str, usize>,
    name: &'a str,
) -> String {
    let count = seen.entry(name).or_default();
    *count += 1;
    match *count {
        1 => name.to_string(),
        n => format!("{name}#{n}"),
    }
}

impl Slots {
    fn add(
        &mut self,
        slot: PolicySlot,
        scope: PolicyScope,
        place: Option<(String, &str)>,
        policy_definition_id: &str,
    ) {
        if policy_definition_id.is_empty() {
            return;
        }
        let key = SlotKey {
            variant: self
                .variant
                .as_ref()
                .map(|(id, _)| id.clone()),
            slot,
            scope: scope.as_str(),
            point: self.point.clone(),
            place: place
                .as_ref()
                .map(|(key, _)| key.clone()),
        };
        let policy = SlotPolicy {
            policy_definition_id: policy_definition_id.to_string(),
            surface_variant: self
                .variant
                .as_ref()
                .map_or(SurfaceVariant::BASE, |(_, alias)| alias.as_str())
                .to_string(),
            place_label: place.map(|(_, label)| label.to_string()),
        };
        self.found.insert(key, policy);
    }

    fn policy(
        &mut self,
        slot: PolicySlot,
        scope: PolicyScope,
        policy: Option<&PolicyRef>,
    ) {
        if let Some(policy) = policy {
            self.add(slot, scope, None, &policy.policy_definition_id);
        }
    }

    fn transit(
        &mut self,
        policy_definition_id: Option<&str>,
    ) {
        if let Some(id) = policy_definition_id {
            self.add(PolicySlot::Transit, PolicyScope::Surface, None, id);
        }
    }

    fn tools(
        &mut self,
        tools: &[McpToolPolicyEntry],
    ) {
        let mut seen = HashMap::new();
        for tool in tools {
            let name = tool.tool_name.as_str();
            let place = numbered(&mut seen, name);
            self.add(PolicySlot::McpTool, PolicyScope::McpTool, Some((place, name)), &tool.policy_definition_id);
        }
    }

    fn gates(
        &mut self,
        gating: Option<&McpToolGatingConfig>,
    ) {
        let mut seen = HashMap::new();
        for gate in gating
            .into_iter()
            .flat_map(|gating| &gating.gates)
        {
            if let Some(id) = gate
                .condition_policy_definition_id
                .as_deref()
            {
                let label = if gate.name.is_empty() {
                    &gate.id
                } else {
                    &gate.name
                };
                let place = numbered(&mut seen, &gate.id);
                self.add(PolicySlot::McpToolGate, PolicyScope::McpTool, Some((place, label)), id);
            }
        }
    }

    fn points(
        &mut self,
        points: &[TransitPoint],
    ) {
        for point in points {
            self.point = Some(point.alias.clone());
            for (scope, policy) in
                [(PolicyScope::Surface, point.policy.as_ref()), (PolicyScope::Response, point.response_policy.as_ref())]
            {
                if let Some(policy) = policy {
                    self.add(PolicySlot::TransitPoint, scope, None, &policy.policy_definition_id);
                }
            }
            self.gates(point.mcp_tool_gating.as_ref());
        }
        self.point = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: &str = "0.0.0.0:8443";

    fn surface(extra: serde_json::Value) -> AgentSurface {
        let mut value = serde_json::json!({
            "surface_id": "s-1",
            "name": "test",
            "access_point": { "listen_address": AP, "route": "/test", "protocol": "mcp" },
            "target": { "endpoint": "https://upstream" },
        });
        merge(&mut value, extra);
        serde_json::from_value(value).unwrap()
    }

    fn merge(
        base: &mut serde_json::Value,
        extra: serde_json::Value,
    ) {
        match (base, extra) {
            (serde_json::Value::Object(base), serde_json::Value::Object(extra)) => {
                for (key, value) in extra {
                    merge(
                        base.entry(key)
                            .or_insert(serde_json::Value::Null),
                        value,
                    );
                }
            }
            (base, extra) => *base = extra,
        }
    }

    fn key(
        variant: Option<&str>,
        slot: PolicySlot,
        scope: PolicyScope,
        place: Option<&str>,
    ) -> SlotKey {
        SlotKey {
            variant: variant.map(str::to_string),
            slot,
            scope: scope.as_str(),
            point: None,
            place: place.map(str::to_string),
        }
    }

    /// `key` on the transit point `alias`.
    fn at_point(
        key: SlotKey,
        alias: &str,
    ) -> SlotKey {
        SlotKey {
            point: Some(alias.to_string()),
            ..key
        }
    }

    fn named(
        slots: &BTreeMap<SlotKey, SlotPolicy>,
        key: &SlotKey,
    ) -> Option<String> {
        slots.get(key).map(|policy| {
            policy
                .policy_definition_id
                .clone()
        })
    }

    #[test]
    fn a_surface_without_policies_has_no_slots() {
        assert!(policy_slots(&surface(serde_json::json!({}))).is_empty());
    }

    #[test]
    fn each_base_slot_names_its_policy_with_the_scope_it_decides_in() {
        let slots = policy_slots(&surface(serde_json::json!({
            "access_point": { "inbound_policy": { "policy_definition_id": "inbound" } },
            "target": {
                "policy": { "policy_definition_id": "target" },
                "response_policy": { "policy_definition_id": "response" },
                "mcp_tool_policies": [{ "tool_name": "search", "policy_definition_id": "tool" }],
                "mcp_tool_gating": { "gates": [{
                    "id": "g-1", "name": "Office hours",
                    "condition_policy_definition_id": "gate",
                    "action": { "effect": "deny", "patterns": ["*"] },
                }]},
            },
            "transit": {
                "points": [{
                    "id": "tp-id", "alias": "billing", "target_endpoint": "https://dest",
                    "policy": { "policy_definition_id": "tp-request" },
                    "response_policy": { "policy_definition_id": "tp-response" },
                }],
                "opa_policy_definition_id": "transit",
                "transit_policy": { "policy_definition_id": "not-enforced" },
            },
        })));

        let expected = [
            (key(None, PolicySlot::Inbound, PolicyScope::Surface, None), "inbound"),
            (key(None, PolicySlot::Target, PolicyScope::Surface, None), "target"),
            (key(None, PolicySlot::Response, PolicyScope::Response, None), "response"),
            (key(None, PolicySlot::McpTool, PolicyScope::McpTool, Some("search")), "tool"),
            (key(None, PolicySlot::McpToolGate, PolicyScope::McpTool, Some("g-1")), "gate"),
            (key(None, PolicySlot::Transit, PolicyScope::Surface, None), "transit"),
            (at_point(key(None, PolicySlot::TransitPoint, PolicyScope::Surface, None), "billing"), "tp-request"),
            (at_point(key(None, PolicySlot::TransitPoint, PolicyScope::Response, None), "billing"), "tp-response"),
        ];
        for (key, policy) in &expected {
            assert_eq!(named(&slots, key).as_deref(), Some(*policy), "{key:?}");
        }
        assert_eq!(slots.len(), expected.len(), "only enforced references: {slots:?}");
        let gate = &slots[&key(None, PolicySlot::McpToolGate, PolicyScope::McpTool, Some("g-1"))];
        assert_eq!(gate.place_label.as_deref(), Some("Office hours"));
    }

    #[test]
    fn a_variant_override_is_its_own_slot_keyed_by_the_variant_id() {
        let mut s = surface(serde_json::json!({
            "target": { "policy": { "policy_definition_id": "base" } },
        }));
        s.variants.push(
            serde_json::from_value(serde_json::json!({
                "id": "v-1", "alias": "beta", "name": "Beta",
                "overrides": {
                    "access_point": { "inbound_policy": { "policy_definition_id": "v-inbound" } },
                    "target": {
                        "policy": { "policy_definition_id": "v-target" },
                        "response_policy": { "policy_definition_id": "v-response" },
                        "mcp_tool_policies": [{ "tool_name": "search", "policy_definition_id": "v-tool" }],
                    },
                    "transit": {
                        "shared": { "opa_policy_definition_id": "v-transit" },
                        "points": [{
                            "id": "tp-id", "alias": "billing", "target_endpoint": "https://dest",
                            "policy": { "policy_definition_id": "v-tp" },
                        }],
                    },
                }
            }))
            .unwrap(),
        );

        let slots = policy_slots(&s);

        let v = Some("v-1");
        for (key, policy) in [
            (key(None, PolicySlot::Target, PolicyScope::Surface, None), "base"),
            (key(v, PolicySlot::Inbound, PolicyScope::Surface, None), "v-inbound"),
            (key(v, PolicySlot::Target, PolicyScope::Surface, None), "v-target"),
            (key(v, PolicySlot::Response, PolicyScope::Response, None), "v-response"),
            (key(v, PolicySlot::McpTool, PolicyScope::McpTool, Some("search")), "v-tool"),
            (key(v, PolicySlot::Transit, PolicyScope::Surface, None), "v-transit"),
            (at_point(key(v, PolicySlot::TransitPoint, PolicyScope::Surface, None), "billing"), "v-tp"),
        ] {
            assert_eq!(named(&slots, &key).as_deref(), Some(policy), "{key:?}");
        }
        let inbound = &slots[&key(v, PolicySlot::Inbound, PolicyScope::Surface, None)];
        assert_eq!(inbound.surface_variant, "beta");
        assert_eq!(
            slots[&key(None, PolicySlot::Target, PolicyScope::Surface, None)].surface_variant,
            "_base_",
            "a base slot is the base surface's"
        );
    }

    #[test]
    fn a_transit_point_saved_without_its_id_keeps_its_slot() {
        let point = serde_json::json!({
            "transit": { "points": [{
                "alias": "billing", "target_endpoint": "https://dest",
                "policy": { "policy_definition_id": "tp" },
            }]},
        });

        let first = policy_slots(&surface(point.clone()));
        let second = policy_slots(&surface(point));

        assert_eq!(first.len(), 1);
        assert_eq!(first, second);
    }

    #[test]
    fn a_gate_on_a_transit_point_has_its_own_slot_beside_a_target_gate_of_the_same_id() {
        let gate = |policy: &str| {
            serde_json::json!({ "gates": [{
                "id": "g-1", "condition_policy_definition_id": policy,
                "action": { "effect": "deny", "patterns": ["*"] },
            }]})
        };
        let slots = policy_slots(&surface(serde_json::json!({
            "target": { "mcp_tool_gating": gate("target-gate") },
            "transit": { "points": [{
                "alias": "billing", "target_endpoint": "https://dest",
                "mcp_tool_gating": gate("point-gate"),
            }]},
        })));

        assert_eq!(
            named(&slots, &key(None, PolicySlot::McpToolGate, PolicyScope::McpTool, Some("g-1"))).as_deref(),
            Some("target-gate")
        );
        assert_eq!(
            named(&slots, &at_point(key(None, PolicySlot::McpToolGate, PolicyScope::McpTool, Some("g-1")), "billing"))
                .as_deref(),
            Some("point-gate")
        );
        assert_eq!(slots.len(), 2);
    }

    #[test]
    fn repeated_tool_names_and_gate_ids_each_keep_a_slot() {
        let slots = policy_slots(&surface(serde_json::json!({
            "target": {
                "mcp_tool_policies": [
                    { "tool_name": "search", "policy_definition_id": "first-tool" },
                    { "tool_name": "search", "policy_definition_id": "second-tool" },
                ],
                "mcp_tool_gating": { "gates": [
                    { "id": "g-1", "condition_policy_definition_id": "first-gate",
                      "action": { "effect": "deny", "patterns": ["*"] } },
                    { "id": "g-1", "condition_policy_definition_id": "second-gate",
                      "action": { "effect": "deny", "patterns": ["*"] } },
                ]},
            },
        })));

        let mut named: Vec<&str> = slots
            .values()
            .map(|slot| {
                slot.policy_definition_id
                    .as_str()
            })
            .collect();
        named.sort();
        assert_eq!(named, ["first-gate", "first-tool", "second-gate", "second-tool"]);
        let tool = &slots[&key(None, PolicySlot::McpTool, PolicyScope::McpTool, Some("search#2"))];
        assert_eq!(tool.place_label.as_deref(), Some("search"));
    }

    #[test]
    fn a_gate_without_a_condition_names_no_policy() {
        let slots = policy_slots(&surface(serde_json::json!({
            "target": { "mcp_tool_gating": { "gates": [{
                "id": "g-1", "action": { "effect": "deny", "patterns": ["*"] },
            }]}},
        })));

        assert!(slots.is_empty());
    }
}
