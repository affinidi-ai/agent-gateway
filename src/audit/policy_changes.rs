//! Records of management changes to policies. Each names the actor of the
//! management request it is built in and is written only when a sink selects
//! its event.

use std::sync::{Arc, OnceLock};

use crate::audit::context::current_actor;
use crate::audit::events::{Actor, PolicyChangeAction, PolicyChangeSource, PolicyField, PolicySlot, PolicyTargetKind};
use crate::config::agent_surface::AgentSurface;
use crate::delegation_vault::audit::{
    DelegationAuditAction, PolicyChangeDetails, PolicyTarget, action_category, audit_event, emit,
};
use crate::policies::policy_definitions::{FileSystemPolicyDefinitionStore, PolicyDefinition, PolicyType};
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
    let source = PolicyChangeSource::Api;
    for (action, key, slot) in surface_slot_changes(before, after) {
        let mut change = match definition(&slot.policy_definition_id).await {
            Some(definition) => of_definition(&definition, source),
            None => {
                let mut change = change(source);
                change.policy_definition_id = Some(slot.policy_definition_id);
                change
            }
        };
        change.target = Some(PolicyTarget {
            kind: PolicyTargetKind::Surface,
            id: Some(
                surface
                    .surface_id
                    .clone(),
            ),
            name: Some(surface.name.clone()),
        });
        change.scope = Some(key.scope.to_string());
        change.slot = Some(key.slot);
        change.variant = slot.variant_alias;
        match key.slot {
            PolicySlot::TransitPoint => change.transit_point = slot.place_label,
            PolicySlot::McpTool => change.mcp_tool_name = slot.place_label,
            PolicySlot::McpToolGate => change.gate = slot.place_label,
            _ => {}
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
    change.policy_definition_id = Some(policy.id.clone());
    change.policy_name = Some(policy.name.clone());
    change.policy_type = Some(policy_type_name(&policy.policy_type).to_string());
    change.policy_version = policy.version;
    change.policy_content_hash = policy
        .content_hash
        .clone();
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
    change.previous_policy_content_hash = before
        .content_hash
        .clone();
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

fn write(action: DelegationAuditAction) {
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
        assert_eq!(change.policy_definition_id.as_deref(), Some("deny-pii"));
        assert_eq!(change.policy_name.as_deref(), Some("Deny PII"));
        assert_eq!(change.policy_type.as_deref(), Some("agent_surface"));
        assert_eq!(change.policy_version, Some(2));
        assert_eq!(change.policy_content_hash.as_deref(), Some("sha256:allow"));
    }

    #[test]
    fn a_change_outside_a_management_request_is_the_gateways() {
        assert_eq!(change(PolicyChangeSource::DefinitionDeleted).actor.kind, ActorKind::System);
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
        assert_eq!(update.previous_policy_content_hash.as_deref(), Some("sha256:allow"));
    }

    #[test]
    fn each_part_of_a_definition_is_named_when_it_changes() {
        let before = stored(1, "allow");
        let parts: [(PolicyField, fn(&mut PolicyDefinition)); 5] = [
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

        let ((), records) = capture(in_management_request(Actor::user("u-1"), surface_written(None, Some(&after)))).await;

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
                "actor": { "kind": "user", "id": "u-1" },
                "source": "api",
            })
        );
    }

    #[tokio::test]
    async fn a_surface_write_outside_a_management_request_records_nothing() {
        let after = surface(serde_json::json!({ "policy": policy("a") }));

        let ((), records) = capture(surface_written(None, Some(&after))).await;

        assert!(records.is_empty());
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
