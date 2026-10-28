//! Records of management changes to policies. Each names the actor of the
//! management request it is built in and is written only when a sink selects
//! its event.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use crate::audit::context::current_actor;
use crate::audit::events::{
    Actor, PolicyChangeAction, PolicyChangeSource, PolicyField, PolicyMode, PolicySlot, PolicyTargetKind,
};
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::{
    DelegationAuditAction, PolicyChangeDetails, PolicyTarget, action_category, audit_event, emit,
};
use crate::gateways::types::Gateway;
use crate::observability::PolicyScope;
use crate::policies::global_policy::{GlobalPolicyAssignments, PLANE_GATEWAY};
use crate::policies::policy_definitions::{
    FileSystemPolicyDefinitionStore, PolicyDefinition, PolicyType, content_hash,
};
use crate::policies::slots::{SlotKey, SlotPolicy, policy_slots};

/// The definitions attachment records are named from, set once at start.
static DEFINITIONS: OnceLock<Arc<FileSystemPolicyDefinitionStore>> = OnceLock::new();

/// Names attachment records from `store`. Only the first call takes effect.
pub fn use_definitions(store: Arc<FileSystemPolicyDefinitionStore>) {
    let _ = DEFINITIONS.set(store);
}

/// Each slot `before` and `after` name a different policy in, as the change
/// it is. A replaced policy is detached, then its successor attached.
pub fn surface_slot_changes(
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
) -> Vec<(PolicyChangeAction, SlotKey, SlotPolicy)> {
    let mut old = before
        .map(policy_slots)
        .unwrap_or_default();
    let new = after
        .map(policy_slots)
        .unwrap_or_default();
    let mut changes = Vec::new();
    for (key, policy) in new {
        match old.remove(&key) {
            Some(previous) if previous.policy_definition_id == policy.policy_definition_id => {}
            Some(previous) => {
                changes.push((PolicyChangeAction::PolicyDetached, key.clone(), previous));
                changes.push((PolicyChangeAction::PolicyAttached, key, policy));
            }
            None => changes.push((PolicyChangeAction::PolicyAttached, key, policy)),
        }
    }
    changes.extend(
        old.into_iter()
            .map(|(key, previous)| (PolicyChangeAction::PolicyDetached, key, previous)),
    );
    changes
}

/// Records the policies a surface write attached and detached. Writes nothing
/// outside a management request: startup migrations, replication and request
/// handling are not user changes.
pub async fn surface_written(
    before: Option<&AgentSurface>,
    after: Option<&AgentSurface>,
) {
    if current_actor().is_none() {
        return;
    }
    let Some(surface) = after.or(before) else {
        return;
    };
    let mut changes = Vec::new();
    for (action, key, slot) in surface_slot_changes(before, after) {
        let mut change = change(PolicyChangeSource::Api);
        change.policy_definition_id = Some(slot.policy_definition_id);
        change.target = Some(PolicyTarget {
            kind: PolicyTargetKind::Surface,
            id: Some(surface.surface_id.clone()),
            name: Some(surface.name.clone()),
        });
        change.scope = Some(key.scope.to_string());
        change.slot = Some(key.slot);
        change.surface_variant = Some(slot.surface_variant);
        change.transit_point = key.point;
        match key.slot {
            PolicySlot::McpTool => change.mcp_tool_name = slot.place_label,
            PolicySlot::McpToolGate => change.gate = slot.place_label,
            _ => {}
        }
        changes.push((action, change));
    }
    write_attachments(changes).await;
}

/// The policies a gateway write attached and detached, and the attachments it
/// enabled or disabled. Every policy of a gateway is attached at its target
/// slot, the primary and each deny-overrides member alike. A legacy inline
/// policy, enforced only when no definition is referenced, has no definition
/// id and is named by the content hash of its Rego.
pub fn gateway_policy_changes(
    before: Option<&Gateway>,
    after: Option<&Gateway>,
) -> Vec<(PolicyChangeAction, PolicyChangeDetails)> {
    let Some(gateway) = after.or(before) else {
        return Vec::new();
    };
    let at_gateway = || {
        let mut change = change(PolicyChangeSource::Api);
        change.target = Some(PolicyTarget {
            kind: PolicyTargetKind::Gateway,
            id: Some(gateway.id.clone()),
            name: Some(gateway.name.clone()),
        });
        change.scope = Some(
            PolicyScope::Gateway
                .as_str()
                .to_string(),
        );
        change.slot = Some(PolicySlot::Target);
        change
    };
    let mut changes = gateway_definition_changes(before, after, &at_gateway);
    changes.extend(inline_policy_changes(inline_policy(before), inline_policy(after), &at_gateway));
    changes
}

/// The hash of a gateway's inline Rego and whether it is enabled, when the
/// gateway has one: it references no definition, and its Rego is not blank or
/// the policy is enabled. An enabled blank policy is compiled as it is and
/// denies every request, as `resolve_and_compile_gateway_set` fails closed.
fn inline_policy(gateway: Option<&Gateway>) -> Option<(String, bool)> {
    let config = gateway?
        .opa_policy_config
        .as_ref()?;
    let references = config
        .policy_definition_id
        .iter()
        .chain(&config.policy_definition_ids)
        .any(|id| !id.is_empty());
    let blank = config
        .policy
        .trim()
        .is_empty();
    (!references && (config.enabled || !blank))
        .then(|| (content_hash(&PolicyType::Gateway, &config.policy), config.enabled))
}

fn inline_policy_changes(
    before: Option<(String, bool)>,
    after: Option<(String, bool)>,
    at_gateway: &impl Fn() -> PolicyChangeDetails,
) -> Vec<(PolicyChangeAction, PolicyChangeDetails)> {
    let inline = |hash: String, enabled: bool| {
        let mut change = at_gateway();
        change.policy_name = Some(INLINE_GATEWAY_POLICY.to_string());
        change.policy_type = Some(policy_type_name(&PolicyType::Gateway).to_string());
        change.policy_content_hash = Some(hash);
        change.enabled = Some(enabled);
        change
    };
    match (before, after) {
        (None, None) => Vec::new(),
        (None, Some((hash, enabled))) => vec![(PolicyChangeAction::PolicyAttached, inline(hash, enabled))],
        (Some((hash, enabled)), None) => vec![(PolicyChangeAction::PolicyDetached, inline(hash, enabled))],
        (Some((previous_hash, was_enabled)), Some((hash, enabled))) => {
            let mut changes = Vec::new();
            if previous_hash != hash {
                let mut updated = inline(hash.clone(), enabled);
                updated.previous_policy_content_hash = Some(previous_hash);
                updated.changed = vec![PolicyField::Rego];
                changes.push((PolicyChangeAction::PolicyUpdated, updated));
            }
            if was_enabled != enabled {
                let mut switched = inline(hash, enabled);
                switched.previous_enabled = Some(was_enabled);
                changes.push((PolicyChangeAction::PolicyAttachmentChanged, switched));
            }
            changes
        }
    }
}

/// The name decisions of an inline gateway policy carry.
const INLINE_GATEWAY_POLICY: &str = "Gateway policy";

fn gateway_definition_changes(
    before: Option<&Gateway>,
    after: Option<&Gateway>,
    at_gateway: &impl Fn() -> PolicyChangeDetails,
) -> Vec<(PolicyChangeAction, PolicyChangeDetails)> {
    let attachments = |gateway: Option<&Gateway>| -> BTreeMap<String, bool> {
        let Some(config) = gateway.and_then(|gateway| {
            gateway
                .opa_policy_config
                .as_ref()
        }) else {
            return BTreeMap::new();
        };
        config
            .policy_definition_id
            .iter()
            .chain(&config.policy_definition_ids)
            .filter(|id| !id.is_empty())
            .map(|id| (id.clone(), config.enabled))
            .collect()
    };
    diff(attachments(before), attachments(after))
        .into_iter()
        .map(|(action, policy_id, previous, enabled)| {
            let mut change = at_gateway();
            change.policy_definition_id = Some(policy_id);
            change.enabled = enabled;
            if action == PolicyChangeAction::PolicyAttachmentChanged {
                change.previous_enabled = previous;
            }
            (action, change)
        })
        .collect()
}

/// Records [`gateway_policy_changes`]. Writes nothing outside a management
/// request.
pub async fn gateway_written(
    before: Option<&Gateway>,
    after: Option<&Gateway>,
) {
    if current_actor().is_none() {
        return;
    }
    write_attachments(gateway_policy_changes(before, after)).await;
}

/// The appliance-wide assignments `after` added, removed or switched between
/// enforced and monitor-only, relative to `before`.
pub fn assignment_changes(
    before: &GlobalPolicyAssignments,
    after: &GlobalPolicyAssignments,
    source: PolicyChangeSource,
) -> Vec<(PolicyChangeAction, PolicyChangeDetails)> {
    let modes = |assignments: &GlobalPolicyAssignments| -> BTreeMap<(String, String), PolicyMode> {
        assignments
            .assignments
            .iter()
            .flat_map(|(plane, list)| {
                list.iter()
                    .map(move |assignment| {
                        let mode = if assignment.monitor_only {
                            PolicyMode::MonitorOnly
                        } else {
                            PolicyMode::Enforced
                        };
                        ((plane.clone(), assignment.policy_id.clone()), mode)
                    })
            })
            .collect()
    };
    diff(modes(before), modes(after))
        .into_iter()
        .map(|(action, (plane, policy_id), previous, mode)| {
            let mut change = change(source);
            change.policy_definition_id = Some(policy_id);
            change.target = Some(PolicyTarget {
                kind: PolicyTargetKind::Appliance,
                id: None,
                name: None,
            });
            let scope = match plane.as_str() {
                PLANE_GATEWAY => PolicyScope::Gateway,
                _ => PolicyScope::Surface,
            };
            change.scope = Some(scope.as_str().to_string());
            change.slot = Some(PolicySlot::Plane);
            change.plane = Some(plane);
            change.mode = mode;
            if action == PolicyChangeAction::PolicyAttachmentChanged {
                change.previous_mode = previous;
            }
            (action, change)
        })
        .collect()
}

/// Each key `before` and `after` hold differently, in key order: attached when
/// only `after` holds it, detached when only `before` does, changed when both
/// hold different values. Gives the previous and current value of each.
fn diff<K: Ord, V: PartialEq + Copy>(
    mut before: BTreeMap<K, V>,
    after: BTreeMap<K, V>,
) -> Vec<(PolicyChangeAction, K, Option<V>, Option<V>)> {
    let mut changes = Vec::new();
    for (key, value) in after {
        match before.remove(&key) {
            Some(previous) if previous == value => {}
            Some(previous) => {
                changes.push((PolicyChangeAction::PolicyAttachmentChanged, key, Some(previous), Some(value)))
            }
            None => changes.push((PolicyChangeAction::PolicyAttached, key, None, Some(value))),
        }
    }
    changes.extend(
        before
            .into_iter()
            .map(|(key, previous)| (PolicyChangeAction::PolicyDetached, key, Some(previous), Some(previous))),
    );
    changes.sort_by(|left, right| left.1.cmp(&right.1));
    changes
}

/// Records [`assignment_changes`].
pub async fn assignments_written(
    before: &GlobalPolicyAssignments,
    after: &GlobalPolicyAssignments,
    source: PolicyChangeSource,
) {
    write_attachments(assignment_changes(before, after, source)).await;
}

/// Records each attachment change, naming its policy from the stored
/// definition when there is one.
async fn write_attachments(changes: Vec<(PolicyChangeAction, PolicyChangeDetails)>) {
    for (action, mut change) in changes {
        if let Some(id) = change
            .policy_definition_id
            .as_deref()
            && let Some(definition) = definition(id).await
        {
            name_from(&mut change, &definition);
        }
        record(action, change);
    }
}

async fn definition(id: &str) -> Option<PolicyDefinition> {
    DEFINITIONS
        .get()?
        .get(id)
        .await
}

fn name_from(
    change: &mut PolicyChangeDetails,
    policy: &PolicyDefinition,
) {
    change.policy_definition_id = Some(policy.id.clone());
    change.policy_name = Some(policy.name.clone());
    change.policy_type = Some(policy_type_name(&policy.policy_type).to_string());
    change.policy_version = policy.version;
    change.policy_content_hash = policy.content_hash.clone();
}

/// A change through `source` by the actor of the current management request,
/// or by the gateway itself outside one.
pub fn change(source: PolicyChangeSource) -> PolicyChangeDetails {
    PolicyChangeDetails::new(current_actor().unwrap_or_else(Actor::system), source)
}

/// [`change`] naming `policy` as stored: its id, name, type, version and hash.
pub fn of_definition(
    policy: &PolicyDefinition,
    source: PolicyChangeSource,
) -> PolicyChangeDetails {
    let mut change = change(source);
    name_from(&mut change, policy);
    change
}

/// The update from `before` to `after`, both as stored, or `None` when it
/// changed nothing.
pub fn definition_updated(
    before: &PolicyDefinition,
    after: &PolicyDefinition,
    source: PolicyChangeSource,
) -> Option<PolicyChangeDetails> {
    let changed: Vec<PolicyField> = [
        (PolicyField::Rego, before.content_hash != after.content_hash || before.policy != after.policy),
        (PolicyField::Name, before.name != after.name),
        (PolicyField::Description, before.description != after.description),
        (PolicyField::Enabled, before.enabled != after.enabled),
        (PolicyField::SampleInput, before.sample_input != after.sample_input),
        (PolicyField::Owner, before.tenant_id != after.tenant_id),
    ]
    .into_iter()
    .filter_map(|(field, differs)| differs.then_some(field))
    .collect();
    if changed.is_empty() {
        return None;
    }
    let mut change = of_definition(after, source);
    change.previous_policy_version = before.version;
    change.previous_policy_content_hash = before.content_hash.clone();
    change.changed = changed;
    Some(change)
}

/// Writes `change` as the `action` event. A change to a surface also carries
/// the surface's id and name at the top level, as decisions do.
pub fn record(
    action: PolicyChangeAction,
    change: PolicyChangeDetails,
) {
    let change = Box::new(change);
    let action = match action {
        PolicyChangeAction::PolicyCreated => DelegationAuditAction::PolicyCreated(change),
        PolicyChangeAction::PolicyUpdated => DelegationAuditAction::PolicyUpdated(change),
        PolicyChangeAction::PolicyDeleted => DelegationAuditAction::PolicyDeleted(change),
        PolicyChangeAction::PolicyAttached => DelegationAuditAction::PolicyAttached(change),
        PolicyChangeAction::PolicyDetached => DelegationAuditAction::PolicyDetached(change),
        PolicyChangeAction::PolicyAttachmentChanged => DelegationAuditAction::PolicyAttachmentChanged(change),
    };
    write(action);
}

/// Writes a policy change record, carrying a surface target's id and name at
/// the top level.
pub(crate) fn write(action: DelegationAuditAction) {
    emit(action_category(&action), move || {
        let surface = match &action {
            DelegationAuditAction::PolicyCreated(change)
            | DelegationAuditAction::PolicyUpdated(change)
            | DelegationAuditAction::PolicyDeleted(change)
            | DelegationAuditAction::PolicyAttached(change)
            | DelegationAuditAction::PolicyDetached(change)
            | DelegationAuditAction::PolicyAttachmentChanged(change)
            | DelegationAuditAction::PolicyChangeRefused(change) => change
                .target
                .as_ref()
                .filter(|target| target.kind == PolicyTargetKind::Surface)
                .cloned(),
            _ => None,
        };
        let mut event = audit_event(
            action,
            None,
            None,
            None,
            surface
                .as_ref()
                .and_then(|target| target.id.as_deref()),
        );
        event.channel_name = surface.and_then(|target| target.name);
        event
    });
}

fn policy_type_name(policy_type: &PolicyType) -> &'static str {
    match policy_type {
        PolicyType::Gateway => "gateway",
        PolicyType::AgentSurface => "agent_surface",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::context::in_management_request;
    use crate::audit::events::{ActorKind, PolicyTargetKind};
    use crate::audit::producer::capture;
    use crate::delegation_vault::audit::{PolicyTarget, action_category};
    use crate::policies::policy_definitions::PolicyType;

    fn stored(
        version: u32,
        rego: &str,
    ) -> PolicyDefinition {
        PolicyDefinition {
            id: "deny-pii".to_string(),
            tenant_id: None,
            name: "Deny PII".to_string(),
            description: "Blocks PII".to_string(),
            policy_type: PolicyType::AgentSurface,
            policy: rego.to_string(),
            enabled: true,
            created_at: "2026-10-27T00:00:00Z".to_string(),
            updated_at: None,
            version: Some(version),
            content_hash: Some(format!("sha256:{rego}")),
            sample_input: None,
        }
    }

    #[tokio::test]
    async fn a_change_names_the_request_actor_and_the_definition_as_stored() {
        let change = in_management_request(Actor::user("u-1"), async {
            of_definition(&stored(2, "allow"), PolicyChangeSource::Api)
        })
        .await;

        assert_eq!(change.actor, Actor::user("u-1"));
        assert_eq!(change.source, PolicyChangeSource::Api);
        assert_eq!(
            change
                .policy_definition_id
                .as_deref(),
            Some("deny-pii")
        );
        assert_eq!(change.policy_name.as_deref(), Some("Deny PII"));
        assert_eq!(change.policy_type.as_deref(), Some("agent_surface"));
        assert_eq!(change.policy_version, Some(2));
        assert_eq!(
            change
                .policy_content_hash
                .as_deref(),
            Some("sha256:allow")
        );
    }

    #[test]
    fn a_change_outside_a_management_request_is_the_gateways() {
        assert_eq!(
            change(PolicyChangeSource::DefinitionDeleted)
                .actor
                .kind,
            ActorKind::System
        );
    }

    #[test]
    fn an_update_names_the_parts_it_changed_and_the_version_it_replaced() {
        let before = stored(2, "allow");
        let mut after = stored(3, "deny");
        after.name = "Deny all PII".to_string();

        let update = definition_updated(&before, &after, PolicyChangeSource::Api).expect("a change");

        assert_eq!(update.changed, vec![PolicyField::Rego, PolicyField::Name]);
        assert_eq!(update.policy_version, Some(3));
        assert_eq!(update.previous_policy_version, Some(2));
        assert_eq!(
            update
                .previous_policy_content_hash
                .as_deref(),
            Some("sha256:allow")
        );
    }

    #[test]
    fn each_part_of_a_definition_is_named_when_it_changes() {
        type Edit = fn(&mut PolicyDefinition);
        let before = stored(1, "allow");
        let parts: [(PolicyField, Edit); 5] = [
            (PolicyField::Description, |p| p.description = "other".to_string()),
            (PolicyField::Enabled, |p| p.enabled = false),
            (PolicyField::SampleInput, |p| p.sample_input = Some("{}".to_string())),
            (PolicyField::Owner, |p| p.tenant_id = Some("tenant-a".to_string())),
            (PolicyField::Rego, |p| p.content_hash = Some("sha256:other".to_string())),
        ];
        for (field, edit) in parts {
            let mut after = before.clone();
            edit(&mut after);
            let update = definition_updated(&before, &after, PolicyChangeSource::Api).expect("a change");
            assert_eq!(update.changed, vec![field]);
        }
    }

    #[test]
    fn an_update_that_changes_nothing_records_nothing() {
        let policy = stored(1, "allow");
        assert!(definition_updated(&policy, &policy.clone(), PolicyChangeSource::Api).is_none());
    }

    #[tokio::test]
    async fn a_change_is_written_as_its_event_with_the_request_id_and_the_surface() {
        let ((), records) = capture(in_management_request(Actor::user("u-1"), async {
            let mut attached = change(PolicyChangeSource::Api);
            attached.target = Some(PolicyTarget {
                kind: PolicyTargetKind::Surface,
                id: Some("s-1".to_string()),
                name: Some("Orders".to_string()),
            });
            record(PolicyChangeAction::PolicyAttached, attached);
        }))
        .await;

        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(action_category(&record.event), "policy_attached");
        assert!(record.request_id.is_some());
        assert_eq!(record.surface_id.as_deref(), Some("s-1"));
        assert_eq!(record.channel_name.as_deref(), Some("Orders"));
    }

    fn surface(policies: serde_json::Value) -> AgentSurface {
        let mut value = serde_json::json!({
            "surface_id": "s-1",
            "name": "Orders",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/orders", "protocol": "a2a" },
            "target": { "endpoint": "https://upstream" },
        });
        for (key, slot) in policies
            .as_object()
            .expect("an object")
        {
            match key.as_str() {
                "inbound_policy" => value["access_point"][key] = slot.clone(),
                _ => value["target"][key] = slot.clone(),
            }
        }
        serde_json::from_value(value).unwrap()
    }

    fn policy(id: &str) -> serde_json::Value {
        serde_json::json!({ "policy_definition_id": id })
    }

    fn changes(
        before: Option<&AgentSurface>,
        after: Option<&AgentSurface>,
    ) -> Vec<(PolicyChangeAction, String, String)> {
        surface_slot_changes(before, after)
            .into_iter()
            .map(|(action, key, slot)| (action, format!("{:?}", key.slot), slot.policy_definition_id))
            .collect()
    }

    #[test]
    fn a_new_surface_attaches_each_policy_it_names() {
        let created = surface(serde_json::json!({ "policy": policy("a"), "inbound_policy": policy("b") }));

        let mut found = changes(None, Some(&created));
        found.sort();

        assert_eq!(
            found,
            vec![
                (PolicyChangeAction::PolicyAttached, "Inbound".to_string(), "b".to_string()),
                (PolicyChangeAction::PolicyAttached, "Target".to_string(), "a".to_string()),
            ]
        );
    }

    #[test]
    fn replacing_a_policy_detaches_the_old_one_then_attaches_the_new_one() {
        let before = surface(serde_json::json!({ "policy": policy("a"), "response_policy": policy("r") }));
        let after = surface(serde_json::json!({ "policy": policy("b"), "response_policy": policy("r") }));

        assert_eq!(
            changes(Some(&before), Some(&after)),
            vec![
                (PolicyChangeAction::PolicyDetached, "Target".to_string(), "a".to_string()),
                (PolicyChangeAction::PolicyAttached, "Target".to_string(), "b".to_string()),
            ]
        );
    }

    #[test]
    fn removing_a_policy_or_the_surface_detaches_it() {
        let before = surface(serde_json::json!({ "policy": policy("a") }));
        let after = surface(serde_json::json!({}));
        let detached = vec![(PolicyChangeAction::PolicyDetached, "Target".to_string(), "a".to_string())];

        assert_eq!(changes(Some(&before), Some(&after)), detached);
        assert_eq!(changes(Some(&before), None), detached);
    }

    #[test]
    fn a_write_that_keeps_every_policy_changes_nothing() {
        let before = surface(serde_json::json!({ "policy": policy("a") }));
        let mut after = before.clone();
        after.name = "Orders v2".to_string();

        assert!(changes(Some(&before), Some(&after)).is_empty());
    }

    #[tokio::test]
    async fn a_surface_write_records_where_each_policy_was_attached() {
        let after = surface(serde_json::json!({ "policy": policy("a") }));

        let ((), records) =
            capture(in_management_request(Actor::user("u-1"), surface_written(None, Some(&after)))).await;

        assert_eq!(records.len(), 1);
        let json = serde_json::to_value(&records[0]).unwrap();
        assert_eq!(json["surface_id"], "s-1");
        assert_eq!(json["channel_name"], "Orders");
        assert_eq!(
            json["event"]["policy_attached"],
            serde_json::json!({
                "policy_definition_id": "a",
                "target": { "kind": "surface", "id": "s-1", "name": "Orders" },
                "scope": "surface",
                "slot": "target",
                "surface_variant": "_base_",
                "actor": { "kind": "user", "id": "u-1" },
                "source": "api",
            })
        );
    }

    #[tokio::test]
    async fn a_write_to_a_variant_slot_records_the_variant() {
        let mut after = surface(serde_json::json!({}));
        after.variants.push(
            serde_json::from_value(serde_json::json!({
                "id": "v-1", "alias": "beta", "name": "Beta",
                "overrides": { "target": { "policy": policy("a") } }
            }))
            .unwrap(),
        );

        let ((), records) =
            capture(in_management_request(Actor::user("u-1"), surface_written(None, Some(&after)))).await;

        assert_eq!(records.len(), 1);
        let json = serde_json::to_value(&records[0]).unwrap();
        assert_eq!(json["event"]["policy_attached"]["surface_variant"], "beta");
        assert!(json.get("surface_variant").is_none(), "a management record has no top-level variant: {json}");
    }

    #[tokio::test]
    async fn a_gate_on_a_transit_point_is_recorded_with_its_point() {
        let after: AgentSurface = serde_json::from_value(serde_json::json!({
            "surface_id": "s-1",
            "name": "Orders",
            "access_point": { "listen_address": "0.0.0.0:8443", "route": "/orders", "protocol": "mcp" },
            "target": { "endpoint": "https://upstream" },
            "transit": { "points": [{
                "alias": "billing", "target_endpoint": "https://dest",
                "mcp_tool_gating": { "gates": [{
                    "id": "g-1", "name": "Office hours", "condition_policy_definition_id": "a",
                    "action": { "effect": "deny", "patterns": ["*"] },
                }]},
            }]},
        }))
        .unwrap();

        let ((), records) =
            capture(in_management_request(Actor::user("u-1"), surface_written(None, Some(&after)))).await;

        assert_eq!(records.len(), 1);
        let json = serde_json::to_value(&records[0]).unwrap();
        let attached = &json["event"]["policy_attached"];
        assert_eq!(attached["slot"], "mcp_tool_gate");
        assert_eq!(attached["transit_point"], "billing");
        assert_eq!(attached["gate"], "Office hours");
    }

    #[tokio::test]
    async fn a_surface_write_outside_a_management_request_records_nothing() {
        let after = surface(serde_json::json!({ "policy": policy("a") }));

        let ((), records) = capture(surface_written(None, Some(&after))).await;

        assert!(records.is_empty());
    }

    fn gateway(
        enabled: bool,
        primary: Option<&str>,
        members: &[&str],
    ) -> Gateway {
        let mut gateway = Gateway::new(
            "Peer".to_string(),
            String::new(),
            "did:web:peer.example".to_string(),
            crate::gateways::types::GatewayType::Remote,
        );
        gateway.id = "gw-1".to_string();
        gateway.opa_policy_config = Some(crate::gateways::types::GatewayOpaPolicyConfig {
            enabled,
            policy: String::new(),
            policy_definition_id: primary.map(str::to_string),
            policy_definition_ids: members
                .iter()
                .map(|id| id.to_string())
                .collect(),
        });
        gateway
    }

    fn summary(changes: Vec<(PolicyChangeAction, PolicyChangeDetails)>) -> Vec<(PolicyChangeAction, String)> {
        changes
            .into_iter()
            .map(|(action, change)| {
                (
                    action,
                    change
                        .policy_definition_id
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    #[test]
    fn a_gateway_policy_and_each_deny_overrides_member_is_attached_at_the_gateway() {
        let changes = gateway_policy_changes(None, Some(&gateway(true, Some("p"), &["m"])));

        assert_eq!(
            summary(changes.clone()),
            vec![
                (PolicyChangeAction::PolicyAttached, "m".to_string()),
                (PolicyChangeAction::PolicyAttached, "p".to_string())
            ]
        );
        let (_, attached) = &changes[0];
        assert_eq!(
            attached.target,
            Some(PolicyTarget {
                kind: PolicyTargetKind::Gateway,
                id: Some("gw-1".to_string()),
                name: Some("Peer".to_string()),
            })
        );
        assert_eq!(attached.scope.as_deref(), Some("gateway"));
        assert_eq!(attached.slot, Some(PolicySlot::Target));
        assert_eq!(attached.enabled, Some(true));
        assert_eq!(attached.surface_variant, None, "a gateway has no variants");
    }

    #[test]
    fn disabling_a_gateway_policy_changes_each_of_its_attachments() {
        let changes =
            gateway_policy_changes(Some(&gateway(true, Some("p"), &[])), Some(&gateway(false, Some("p"), &[])));

        assert_eq!(summary(changes.clone()), vec![(PolicyChangeAction::PolicyAttachmentChanged, "p".to_string())]);
        assert_eq!(changes[0].1.enabled, Some(false));
        assert_eq!(changes[0].1.previous_enabled, Some(true));
    }

    #[test]
    fn removing_a_member_or_the_gateway_detaches_its_policies() {
        let before = gateway(true, Some("p"), &["m"]);

        assert_eq!(
            summary(gateway_policy_changes(Some(&before), Some(&gateway(true, Some("p"), &[])))),
            vec![(PolicyChangeAction::PolicyDetached, "m".to_string())]
        );
        assert_eq!(
            summary(gateway_policy_changes(Some(&before), None)),
            vec![
                (PolicyChangeAction::PolicyDetached, "m".to_string()),
                (PolicyChangeAction::PolicyDetached, "p".to_string())
            ]
        );
        assert!(gateway_policy_changes(Some(&before), Some(&before.clone())).is_empty());
    }

    fn inline_gateway(
        enabled: bool,
        rego: &str,
    ) -> Gateway {
        let mut gateway = gateway(enabled, None, &[]);
        if let Some(config) = gateway
            .opa_policy_config
            .as_mut()
        {
            config.policy = rego.to_string();
        }
        gateway
    }

    fn inline_hash(rego: &str) -> Option<String> {
        Some(crate::policies::policy_definitions::content_hash(
            &crate::policies::policy_definitions::PolicyType::Gateway,
            rego,
        ))
    }

    #[test]
    fn an_inline_gateway_policy_is_attached_by_its_content_hash() {
        let changes = gateway_policy_changes(Some(&gateway(false, None, &[])), Some(&inline_gateway(true, "allow")));

        assert_eq!(changes.len(), 1);
        let (action, attached) = &changes[0];
        assert_eq!(*action, PolicyChangeAction::PolicyAttached);
        assert_eq!(attached.policy_definition_id, None);
        assert_eq!(
            attached
                .policy_name
                .as_deref(),
            Some("Gateway policy")
        );
        assert_eq!(
            attached
                .policy_type
                .as_deref(),
            Some("gateway")
        );
        assert_eq!(attached.policy_content_hash, inline_hash("allow"));
        assert_eq!(attached.scope.as_deref(), Some("gateway"));
        assert_eq!(attached.slot, Some(PolicySlot::Target));
        assert_eq!(attached.enabled, Some(true));
    }

    #[test]
    fn changing_an_inline_gateway_policy_is_an_update_of_its_rego() {
        let changes = gateway_policy_changes(Some(&inline_gateway(true, "allow")), Some(&inline_gateway(true, "deny")));

        assert_eq!(changes.len(), 1);
        let (action, updated) = &changes[0];
        assert_eq!(*action, PolicyChangeAction::PolicyUpdated);
        assert_eq!(updated.changed, vec![PolicyField::Rego]);
        assert_eq!(updated.policy_content_hash, inline_hash("deny"));
        assert_eq!(updated.previous_policy_content_hash, inline_hash("allow"));
        assert_eq!(
            updated
                .target
                .as_ref()
                .map(|target| target.kind),
            Some(PolicyTargetKind::Gateway)
        );
    }

    #[test]
    fn replacing_an_inline_gateway_policy_with_a_definition_detaches_the_inline_one() {
        let changes =
            gateway_policy_changes(Some(&inline_gateway(true, "allow")), Some(&gateway(true, Some("p"), &[])));

        assert_eq!(
            changes
                .iter()
                .map(|(action, change)| (
                    *action,
                    change
                        .policy_definition_id
                        .clone(),
                    change
                        .policy_content_hash
                        .clone()
                ))
                .collect::<Vec<_>>(),
            vec![
                (PolicyChangeAction::PolicyAttached, Some("p".to_string()), None),
                (PolicyChangeAction::PolicyDetached, None, inline_hash("allow")),
            ]
        );
    }

    #[test]
    fn disabling_an_inline_gateway_policy_changes_its_attachment() {
        let changes =
            gateway_policy_changes(Some(&inline_gateway(true, "allow")), Some(&inline_gateway(false, "allow")));

        assert_eq!(summary(changes.clone()), vec![(PolicyChangeAction::PolicyAttachmentChanged, String::new())]);
        assert_eq!(changes[0].1.enabled, Some(false));
        assert_eq!(changes[0].1.previous_enabled, Some(true));
    }

    #[test]
    fn a_blank_inline_gateway_policy_is_attached_only_while_enabled() {
        let enabled = gateway_policy_changes(None, Some(&inline_gateway(true, "  ")));
        assert_eq!(summary(enabled.clone()), vec![(PolicyChangeAction::PolicyAttached, String::new())]);
        assert_eq!(
            enabled[0]
                .1
                .policy_content_hash,
            inline_hash("  ")
        );

        assert!(gateway_policy_changes(None, Some(&inline_gateway(false, "  "))).is_empty());
        assert_eq!(
            summary(gateway_policy_changes(Some(&inline_gateway(true, "")), Some(&inline_gateway(false, "")))),
            vec![(PolicyChangeAction::PolicyDetached, String::new())]
        );
    }

    #[test]
    fn inline_rego_beside_a_definition_is_not_an_attachment() {
        let mut referenced = gateway(true, Some("p"), &[]);
        if let Some(config) = referenced
            .opa_policy_config
            .as_mut()
        {
            config.policy = "ignored".to_string();
        }

        assert!(gateway_policy_changes(Some(&gateway(true, Some("p"), &[])), Some(&referenced)).is_empty());
    }

    fn assignments(planes: &[(&str, &str, bool)]) -> GlobalPolicyAssignments {
        let mut assignments = GlobalPolicyAssignments::default();
        for (plane, policy_id, monitor_only) in planes {
            assignments
                .assignments
                .entry(plane.to_string())
                .or_default()
                .push(crate::policies::global_policy::GlobalAssignment {
                    policy_id: policy_id.to_string(),
                    monitor_only: *monitor_only,
                });
        }
        assignments
    }

    #[test]
    fn an_appliance_wide_assignment_is_attached_at_its_plane_in_its_mode() {
        let changes = assignment_changes(
            &assignments(&[]),
            &assignments(&[("gateway", "g", false), ("agent_surface", "s", true)]),
            PolicyChangeSource::Api,
        );

        let by_policy = |id: &str| {
            changes
                .iter()
                .find(|(_, change)| {
                    change
                        .policy_definition_id
                        .as_deref()
                        == Some(id)
                })
                .cloned()
                .expect("a change")
        };
        let (action, gateway_plane) = by_policy("g");
        assert_eq!(action, PolicyChangeAction::PolicyAttached);
        assert_eq!(gateway_plane.scope.as_deref(), Some("gateway"));
        assert_eq!(gateway_plane.plane.as_deref(), Some("gateway"));
        assert_eq!(gateway_plane.slot, Some(PolicySlot::Plane));
        assert_eq!(gateway_plane.mode, Some(crate::audit::events::PolicyMode::Enforced));
        assert_eq!(
            gateway_plane
                .target
                .map(|target| target.kind),
            Some(PolicyTargetKind::Appliance)
        );
        let (_, surface_plane) = by_policy("s");
        assert_eq!(surface_plane.scope.as_deref(), Some("surface"));
        assert_eq!(surface_plane.mode, Some(crate::audit::events::PolicyMode::MonitorOnly));
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn switching_an_assignment_to_monitor_only_or_removing_it_is_recorded() {
        let before = assignments(&[("gateway", "g", false), ("gateway", "h", false)]);
        let after = assignments(&[("gateway", "g", true)]);

        let changes = assignment_changes(&before, &after, PolicyChangeSource::DefinitionDeleted);

        assert_eq!(
            summary(changes.clone()),
            vec![
                (PolicyChangeAction::PolicyAttachmentChanged, "g".to_string()),
                (PolicyChangeAction::PolicyDetached, "h".to_string()),
            ]
        );
        assert_eq!(changes[0].1.previous_mode, Some(crate::audit::events::PolicyMode::Enforced));
        assert_eq!(changes[0].1.mode, Some(crate::audit::events::PolicyMode::MonitorOnly));
        assert_eq!(changes[1].1.source, PolicyChangeSource::DefinitionDeleted);
    }

    #[tokio::test]
    async fn every_action_is_written_as_the_event_of_its_name() {
        for (action, category) in [
            (PolicyChangeAction::PolicyCreated, "policy_created"),
            (PolicyChangeAction::PolicyUpdated, "policy_updated"),
            (PolicyChangeAction::PolicyDeleted, "policy_deleted"),
            (PolicyChangeAction::PolicyAttached, "policy_attached"),
            (PolicyChangeAction::PolicyDetached, "policy_detached"),
            (PolicyChangeAction::PolicyAttachmentChanged, "policy_attachment_changed"),
        ] {
            let ((), records) = capture(async { record(action, change(PolicyChangeSource::Api)) }).await;
            assert_eq!(
                records
                    .iter()
                    .map(|record| action_category(&record.event))
                    .collect::<Vec<_>>(),
                vec![category]
            );
        }
    }
}
