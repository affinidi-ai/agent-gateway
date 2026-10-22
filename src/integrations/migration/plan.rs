//! The mapping from the live records to endpoints, event sets and integrations, without disk.
//!
//! Each live integration keeps its id for all three definitions, so metrics labels, stream
//! record keys and access token resource scopes still name it, and running the migration
//! again finds what it already wrote.

use std::collections::BTreeSet;

use serde_json::{Map, Value as JsonValue, json};

use super::legacy::{LegacyIntegration, LegacyRecords};
use super::received::{AuditForwarding, received_events};
use crate::integrations::definitions::{Endpoint, EndpointType, EventSet, Integration, Status};
use crate::integrations::publishers::reserved_header;
use crate::integrations::runtime_variables::patterns;

/// Audit delivery limits for a migrated audit integration: live kept no journal, and with no
/// limits a record would be retried forever.
pub const AUDIT_DROP_AFTER_SECS: u64 = 7 * 24 * 60 * 60;
pub const AUDIT_MAX_ATTEMPTS: u32 = 20;

/// The API's limit on definition names.
const MAX_NAME_LEN: usize = 200;
const EVENT_SET_SUFFIX: &str = " events (migrated)";

/// One live integration as the definitions that replace it.
#[derive(Debug, Clone, PartialEq)]
pub struct Planned {
    pub id: String,
    pub name: String,
    pub endpoint: Endpoint,
    /// None when live delivered it nothing, so only the endpoint is kept.
    pub event_set: Option<EventSet>,
    pub integration: Option<Integration>,
    /// Why the integration is written disabled whatever its live status: it belonged to a
    /// tenant, and integrations are now appliance-wide.
    pub integration_disabled: Option<String>,
    /// What changed for it, for the report; never a secret value.
    pub notes: Vec<String>,
}

/// A live integration that cannot become an endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct Skipped {
    pub id: String,
    pub name: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MigrationPlan {
    pub planned: Vec<Planned>,
    pub skipped: Vec<Skipped>,
    /// Records that name no live integration, and other findings not about one integration.
    pub notes: Vec<String>,
}

pub fn plan(
    records: &LegacyRecords,
    audit: &AuditForwarding,
) -> MigrationPlan {
    let mut migration = MigrationPlan {
        notes: dangling_references(records),
        ..MigrationPlan::default()
    };
    for integration in &records.integrations {
        match plan_one(integration, records, audit) {
            Ok(planned) => migration
                .planned
                .push(planned),
            Err(reason) => migration
                .skipped
                .push(Skipped {
                    id: integration.id.clone(),
                    name: integration.name.clone(),
                    reason,
                }),
        }
    }
    migration
}

fn plan_one(
    live: &LegacyIntegration,
    records: &LegacyRecords,
    audit: &AuditForwarding,
) -> Result<Planned, String> {
    let endpoint_type: EndpointType = serde_json::from_value(JsonValue::String(live.integration_type.clone()))
        .map_err(|_| format!("Its type {} is not one an endpoint can have", live.integration_type))?;
    let mut notes = Vec::new();
    let name = bounded_name(&live.name, "", &live.id);
    let mut configuration = live.configuration.clone();
    let mut content = match &live.content {
        JsonValue::Object(_) => live.content.clone(),
        JsonValue::Null => json!({}),
        _ => {
            notes.push("Its template was not a JSON object and starts empty".to_string());
            json!({})
        }
    };
    rename_surface_variables(&mut configuration);
    rename_surface_variables(&mut content);
    let endpoint_configuration = match endpoint_type {
        EndpointType::Slack => slack_configuration(configuration, &mut content, &mut notes),
        EndpointType::Webhook => webhook_configuration(configuration, &mut notes),
        EndpointType::Stream => stream_configuration(configuration, &mut notes),
        EndpointType::Email => configuration,
    };
    let mut endpoint = Endpoint::new(name.clone(), live.description.clone(), endpoint_type, endpoint_configuration);
    endpoint.id = live.id.clone();
    stamp(&mut endpoint.created_at, &mut endpoint.updated_at, live);

    if let Some(tenant) = &live.tenant_id {
        notes.push(format!("Belonged to the tenant {tenant}; integrations are now appliance-wide"));
    }
    notes.extend(attachment_notes(live, records));
    let received = received_events(live, records, audit);
    notes.extend(received.notes);
    if received.events.is_empty() {
        notes.push("Live delivered it no events, so only its endpoint is kept".to_string());
        return Ok(Planned {
            id: live.id.clone(),
            name,
            endpoint,
            event_set: None,
            integration: None,
            integration_disabled: None,
            notes,
        });
    }

    let mut event_set = EventSet::new(
        bounded_name(&live.name, EVENT_SET_SUFFIX, &live.id),
        format!("The events {name} received before endpoints and event sets"),
        received.events,
    )
    .map_err(|error| error.to_string())?;
    event_set.id = live.id.clone();
    stamp(&mut event_set.created_at, &mut event_set.updated_at, live);

    let custom = strip_placeholders(&mut content, |variable| variable.starts_with('_'));
    if !custom.is_empty() {
        notes.push(format!("Removed the custom variables {} from its template", joined(&custom)));
    }
    let unfilled: BTreeSet<String> = event_set
        .unknown_template_variables(&content)
        .into_iter()
        .collect();
    strip_placeholders(&mut content, |variable| unfilled.contains(variable));
    if !unfilled.is_empty() {
        notes.push(format!(
            "Removed {} from its template: no event of its event set fills them, so they would be empty",
            joined(&unfilled)
        ));
    }
    notes.extend(default_template_notes(endpoint_type, &content));

    let mut integration =
        Integration::new(name.clone(), live.description.clone(), live.id.clone(), live.id.clone(), content);
    integration.id = live.id.clone();
    // Live delivered a tenant's integration only the events of the gateways and connection
    // points linked to it, all its tenant's or appliance-wide. Its event set now receives them
    // from every tenant, so it is never enabled without an administrator choosing to.
    let integration_disabled = live
        .tenant_id
        .as_ref()
        .map(|tenant| {
            format!(
                "It belonged to the tenant {tenant}. Integrations are now appliance-wide, so enabled it would receive every tenant's events; review it before enabling it"
            )
        });
    integration.status = if live.status == "active" && integration_disabled.is_none() {
        Status::Active
    } else {
        Status::Disabled
    };
    if integration_disabled.is_some() {
        notes.push("Its integration is written disabled: enabled, it would receive every tenant's events".to_string());
    }
    stamp(&mut integration.created_at, &mut integration.updated_at, live);
    if event_set.has_audit_events() {
        if live.audit_events.is_empty() {
            integration.audit_drop_after_secs = Some(AUDIT_DROP_AFTER_SECS);
            integration.audit_max_attempts = Some(AUDIT_MAX_ATTEMPTS);
            notes.push(format!(
                "Audit records are now journaled and retried; it skips records older than {} days or after {AUDIT_MAX_ATTEMPTS} attempts",
                AUDIT_DROP_AFTER_SECS / 86_400
            ));
        } else {
            integration.audit_drop_after_secs = live.audit_drop_after_secs;
            integration.audit_max_attempts = live.audit_max_attempts;
        }
    }
    if let Err(problem) = integration.check_against(&event_set) {
        notes.push(format!("Does not pass the integration checks: {problem}"));
    }
    Ok(Planned {
        id: live.id.clone(),
        name,
        endpoint,
        event_set: Some(event_set),
        integration: Some(integration),
        integration_disabled,
        notes,
    })
}

/// Live's timestamps, when it had them.
fn stamp(
    created_at: &mut String,
    updated_at: &mut String,
    live: &LegacyIntegration,
) {
    if !live.created_at.is_empty() {
        *created_at = live.created_at.clone();
    }
    if !live.updated_at.is_empty() {
        *updated_at = live.updated_at.clone();
    }
}

/// `name` and `suffix` within the API's name limit, shortening `name`; the id when the name is
/// empty.
fn bounded_name(
    name: &str,
    suffix: &str,
    id: &str,
) -> String {
    let name = match name.trim() {
        "" => id,
        trimmed => trimmed,
    };
    let mut kept = String::new();
    for character in name.chars() {
        if kept.len() + character.len_utf8() + suffix.len() > MAX_NAME_LEN {
            break;
        }
        kept.push(character);
    }
    format!("{kept}{suffix}")
}

fn joined(names: &BTreeSet<String>) -> String {
    names
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Live's loader renamed `${CHANNEL_*}` to `${SURFACE_*}`; the migration reads records
/// without it, so it renames them here.
fn rename_surface_variables(value: &mut JsonValue) {
    match value {
        JsonValue::String(text) if text.contains("${CHANNEL_") => *text = text.replace("${CHANNEL_", "${SURFACE_"),
        JsonValue::Array(items) => items
            .iter_mut()
            .for_each(rename_surface_variables),
        JsonValue::Object(fields) => fields
            .values_mut()
            .for_each(rename_surface_variables),
        _ => {}
    }
}

/// Removes the placeholders whose variable `remove` picks from every string in `value`, and
/// returns their names.
fn strip_placeholders(
    value: &mut JsonValue,
    remove: impl Fn(&str) -> bool + Copy,
) -> BTreeSet<String> {
    let mut removed = BTreeSet::new();
    strip_into(value, remove, &mut removed);
    removed
}

fn strip_into(
    value: &mut JsonValue,
    remove: impl Fn(&str) -> bool + Copy,
    removed: &mut BTreeSet<String>,
) {
    match value {
        JsonValue::String(text) => *text = strip_text(text, remove, removed),
        JsonValue::Array(items) => items
            .iter_mut()
            .for_each(|item| strip_into(item, remove, removed)),
        JsonValue::Object(fields) => fields
            .values_mut()
            .for_each(|field| strip_into(field, remove, removed)),
        _ => {}
    }
}

fn strip_text(
    text: &str,
    remove: impl Fn(&str) -> bool,
    removed: &mut BTreeSet<String>,
) -> String {
    patterns()
        .regex
        .replace_all(text, |capture: &regex::Captures| {
            let variable = capture[1].trim();
            if remove(variable) {
                removed.insert(variable.to_string());
                String::new()
            } else {
                capture[0].to_string()
            }
        })
        .into_owned()
}

/// Live read the Slack sender name and icon from the template first and the configuration
/// second; they belong to the endpoint now. `channel` can no longer be sent.
fn slack_configuration(
    configuration: JsonValue,
    content: &mut JsonValue,
    notes: &mut Vec<String>,
) -> JsonValue {
    let mut configuration = into_object(configuration);
    let template = content
        .as_object_mut()
        .expect("the template is an object");
    for field in ["bot_name", "icon_emoji"] {
        if let Some(value) = template
            .remove(field)
            .filter(|value| {
                value
                    .as_str()
                    .is_some_and(|text| !text.is_empty())
            })
        {
            configuration.insert(field.to_string(), value);
        }
    }
    let channel = template
        .remove("channel")
        .into_iter()
        .chain(configuration.remove("channel"))
        .any(|value| {
            value
                .as_str()
                .is_some_and(|text| !text.is_empty())
        });
    if channel {
        notes.push("Its Slack channel is no longer sent; messages go to the channel of the webhook URL".to_string());
    }
    JsonValue::Object(configuration)
}

/// Header names the gateway sets itself, values live skipped when sending, and placeholders
/// the current publisher no longer fills are removed; the report names the headers but
/// never their values.
fn webhook_configuration(
    configuration: JsonValue,
    notes: &mut Vec<String>,
) -> JsonValue {
    let mut configuration = into_object(configuration);
    let Some(JsonValue::Object(headers)) = configuration.remove("headers") else {
        return JsonValue::Object(configuration);
    };
    let mut kept = Map::new();
    for (name, value) in headers {
        if reserved_header(&name) {
            notes.push(format!("Removed the header {name}, which the gateway sets on every delivery"));
            continue;
        }
        let JsonValue::String(text) = value else {
            notes.push(format!("Removed the header {name}: its value was not text, so live never sent it"));
            continue;
        };
        let mut placeholders = BTreeSet::new();
        let text = strip_text(&text, |_| true, &mut placeholders);
        if !placeholders.is_empty() {
            notes.push(format!(
                "Removed {} from the header {name}: header values are no longer filled",
                joined(&placeholders)
            ));
        }
        if text.trim().is_empty() {
            notes.push(format!("Removed the header {name}, empty without its placeholders"));
            continue;
        }
        kept.insert(name, JsonValue::String(text));
    }
    if !kept.is_empty() {
        configuration.insert("headers".to_string(), JsonValue::Object(kept));
    }
    JsonValue::Object(configuration)
}

/// Kinesis uses the AWS credential chain; the access keys live's form saved were never read.
fn stream_configuration(
    configuration: JsonValue,
    notes: &mut Vec<String>,
) -> JsonValue {
    let mut configuration = into_object(configuration);
    let dropped: BTreeSet<String> = ["access_key", "secret_key"]
        .into_iter()
        .filter(|field| {
            configuration
                .remove(*field)
                .is_some()
        })
        .map(str::to_string)
        .collect();
    if !dropped.is_empty() {
        notes.push(format!("Dropped {}, which nothing reads: Kinesis uses the AWS credential chain", joined(&dropped)));
    }
    JsonValue::Object(configuration)
}

fn into_object(configuration: JsonValue) -> Map<String, JsonValue> {
    match configuration {
        JsonValue::Object(fields) => fields,
        _ => Map::new(),
    }
}

/// Where the template leaves out what live filled from the event's subject and message.
fn default_template_notes(
    endpoint_type: EndpointType,
    content: &JsonValue,
) -> Vec<String> {
    let missing = |field: &str| {
        content
            .get(field)
            .and_then(JsonValue::as_str)
            .is_none_or(str::is_empty)
    };
    match endpoint_type {
        EndpointType::Webhook | EndpointType::Stream
            if content
                .as_object()
                .is_some_and(Map::is_empty) =>
        {
            vec!["Its empty template now sends the event envelope instead of live's subject and message".to_string()]
        }
        EndpointType::Email if missing("subject") || missing("body") => {
            vec!["Its subject or body is empty, so the event's name or summary fills it".to_string()]
        }
        EndpointType::Slack if missing("text") => {
            vec!["Its text is empty, so the event's name and summary fill it".to_string()]
        }
        _ => Vec::new(),
    }
}

/// What the report says about the attachments of `live`: identities it was attached to, which
/// live never delivered to, and the values of custom variables, which are not migrated.
fn attachment_notes(
    live: &LegacyIntegration,
    records: &LegacyRecords,
) -> Vec<String> {
    let mut notes = Vec::new();
    if records
        .identity_attachments
        .iter()
        .any(|attachment| attachment.integration_id == live.id)
    {
        notes.push("Was attached to identities, which live never delivered to; not migrated".to_string());
    }
    let variables: BTreeSet<String> = records
        .gateway_attachments
        .iter()
        .flat_map(|(_, attachments)| attachments)
        .chain(&records.user_attachments)
        .filter(|attachment| attachment.integration_id == live.id)
        .flat_map(|attachment| {
            attachment
                .variables
                .keys()
                .cloned()
        })
        .collect();
    if !variables.is_empty() {
        notes.push(format!("The attachment values for {} are not migrated", joined(&variables)));
    }
    notes
}

/// Attachments and connection points naming an integration live no longer had.
fn dangling_references(records: &LegacyRecords) -> Vec<String> {
    let known: BTreeSet<&str> = records
        .integrations
        .iter()
        .map(|integration| integration.id.as_str())
        .collect();
    let missing = |id: &str| !known.contains(id);
    let mut notes = Vec::new();
    for (gateway_id, attachments) in &records.gateway_attachments {
        for attachment in attachments
            .iter()
            .filter(|attachment| missing(&attachment.integration_id))
        {
            notes.push(format!(
                "The gateway {gateway_id} was attached to the missing integration {}; not migrated",
                attachment.integration_id
            ));
        }
    }
    for (kind, attachments) in [("users", &records.user_attachments), ("identities", &records.identity_attachments)] {
        for attachment in attachments
            .iter()
            .filter(|attachment| missing(&attachment.integration_id))
        {
            notes.push(format!(
                "The {kind} were attached to the missing integration {}; not migrated",
                attachment.integration_id
            ));
        }
    }
    for point in &records.connection_points {
        for id in point
            .integration_ids()
            .into_iter()
            .filter(|id| missing(id))
        {
            notes.push(format!("The connection point {} names the missing integration {id}; not migrated", point.id));
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::migration::legacy::{
        LegacyAttachment, LegacyConnectionPoint, LegacyConnectionPointIntegration,
    };
    use std::collections::HashMap;

    const ID: &str = "6f1c2a7e-3b9d-4c55-9a51-0d7e8f2b4c11";

    fn live(
        integration_type: &str,
        category: &str,
        configuration: JsonValue,
        content: JsonValue,
    ) -> LegacyIntegration {
        LegacyIntegration {
            id: ID.to_string(),
            tenant_id: None,
            name: "Ops".to_string(),
            description: "Tell ops".to_string(),
            integration_type: integration_type.to_string(),
            category: Some(category.to_string()),
            configuration,
            content,
            status: "active".to_string(),
            created_at: "2026-09-01T10:00:00+00:00".to_string(),
            updated_at: "2026-09-02T10:00:00+00:00".to_string(),
            audit_events: Vec::new(),
            audit_drop_after_secs: None,
            audit_max_attempts: None,
        }
    }

    fn attached_to_gateway(
        integration: LegacyIntegration,
        variables: &[(&str, &str)],
    ) -> LegacyRecords {
        LegacyRecords {
            gateway_attachments: vec![(
                "gw-1".to_string(),
                vec![LegacyAttachment {
                    integration_id: integration.id.clone(),
                    variables: variables
                        .iter()
                        .map(|(name, value)| (name.to_string(), value.to_string()))
                        .collect::<HashMap<_, _>>(),
                    event_types: vec!["gateway.created".to_string()],
                }],
            )],
            integrations: vec![integration],
            ..LegacyRecords::default()
        }
    }

    fn no_audit() -> AuditForwarding {
        AuditForwarding::from_settings(false, &[])
    }

    fn only(plan: &MigrationPlan) -> &Planned {
        assert_eq!(plan.planned.len(), 1, "{plan:?}");
        &plan.planned[0]
    }

    fn noted(
        planned: &Planned,
        text: &str,
    ) -> bool {
        planned
            .notes
            .iter()
            .any(|note| note.contains(text))
    }

    fn slack(content: JsonValue) -> LegacyIntegration {
        live("slack", "gateway", json!({"webhook_url": "https://hooks.slack.com/services/T/B/x"}), content)
    }

    #[test]
    fn a_live_integration_becomes_an_endpoint_an_event_set_and_an_integration_with_its_id() {
        let records = attached_to_gateway(slack(json!({"text": "New gateway ${GATEWAY_NAME}"})), &[]);

        let planned = only(&plan(&records, &no_audit())).clone();

        assert_eq!(planned.endpoint.id, ID);
        assert_eq!(planned.endpoint.name, "Ops");
        assert_eq!(planned.endpoint.description, "Tell ops");
        assert_eq!(planned.endpoint.endpoint_type, EndpointType::Slack);
        assert_eq!(planned.endpoint.configuration, json!({"webhook_url": "https://hooks.slack.com/services/T/B/x"}));
        assert_eq!(planned.endpoint.status, Status::Active);
        assert_eq!(planned.endpoint.created_at, "2026-09-01T10:00:00+00:00");
        let event_set = planned
            .event_set
            .expect("event set");
        assert_eq!(event_set.id, ID);
        assert_eq!(event_set.name, "Ops events (migrated)");
        assert_eq!(event_set.events, std::collections::HashSet::from(["gateway.created".to_string()]));
        let integration = planned
            .integration
            .expect("integration");
        assert_eq!(
            (
                integration.id.as_str(),
                integration
                    .endpoint_id
                    .as_str()
            ),
            (ID, ID)
        );
        assert_eq!(integration.event_set_id, ID);
        assert_eq!(integration.content, json!({"text": "New gateway ${GATEWAY_NAME}"}));
        assert_eq!(integration.status, Status::Active);
        assert_eq!(integration.audit_max_attempts, None);
        assert_eq!(integration.check_against(&event_set), Ok(()));
    }

    #[test]
    fn a_status_other_than_active_is_disabled() {
        for status in ["disabled", "paused"] {
            let mut integration = slack(json!({"text": "hi"}));
            integration.status = status.to_string();

            let planned = only(&plan(&attached_to_gateway(integration, &[]), &no_audit())).clone();

            assert_eq!(
                planned
                    .integration
                    .expect("integration")
                    .status,
                Status::Disabled
            );
            assert_eq!(planned.endpoint.status, Status::Active, "the endpoint itself was never disabled");
        }
    }

    #[test]
    fn surface_variables_are_renamed_in_the_template_and_the_configuration() {
        let integration = live(
            "webhook",
            "gateway",
            json!({"url": "https://93.184.215.14/${CHANNEL_ID}"}),
            json!({"surface": "${CHANNEL_NAME}", "nested": ["${CHANNEL_ID}"]}),
        );

        let planned = only(&plan(&attached_to_gateway(integration, &[]), &no_audit())).clone();

        assert_eq!(planned.endpoint.configuration["url"], "https://93.184.215.14/${SURFACE_ID}");
        assert_eq!(
            planned
                .integration
                .expect("integration")
                .content,
            json!({"surface": "", "nested": [""]}),
            "renamed, then removed: no gateway event fills SURFACE_ variables"
        );
    }

    #[test]
    fn custom_variables_are_removed_from_the_template_and_their_attachment_values_dropped() {
        let integration = slack(json!({"text": "${GATEWAY_NAME} for ${_TEAM:Team} ${_ENV}"}));

        let planned = only(&plan(&attached_to_gateway(integration, &[("_TEAM", "edge")]), &no_audit())).clone();

        assert_eq!(
            planned
                .integration
                .clone()
                .expect("integration")
                .content,
            json!({"text": "${GATEWAY_NAME} for  "})
        );
        assert!(noted(&planned, "_ENV, _TEAM"), "{:?}", planned.notes);
        assert!(noted(&planned, "values for _TEAM"), "{:?}", planned.notes);
        assert!(!noted(&planned, "edge"), "attachment values are never reported: {:?}", planned.notes);
    }

    #[test]
    fn variables_no_event_of_the_set_fills_are_removed_and_reported() {
        let integration = slack(json!({"text": "${GATEWAY_NAME} ${USERNAME} ${AMOUNT}"}));

        let planned = only(&plan(&attached_to_gateway(integration, &[]), &no_audit())).clone();

        let integration = planned
            .integration
            .clone()
            .expect("integration");
        assert_eq!(integration.content, json!({"text": "${GATEWAY_NAME}  "}));
        assert!(noted(&planned, "AMOUNT, USERNAME"), "{:?}", planned.notes);
        assert_eq!(
            integration.check_against(
                planned
                    .event_set
                    .as_ref()
                    .expect("set")
            ),
            Ok(())
        );
    }

    #[test]
    fn slack_sender_settings_move_from_the_template_to_the_endpoint_and_the_channel_is_dropped() {
        let integration = live(
            "slack",
            "gateway",
            json!({"webhook_url": "https://hooks.slack.com/services/T/B/x", "bot_name": "Old", "channel": "#old"}),
            json!({"text": "hi", "bot_name": "Gateway", "icon_emoji": ":robot:", "channel": "#ops"}),
        );

        let planned = only(&plan(&attached_to_gateway(integration, &[]), &no_audit())).clone();

        assert_eq!(
            planned.endpoint.configuration,
            json!({"webhook_url": "https://hooks.slack.com/services/T/B/x", "bot_name": "Gateway", "icon_emoji": ":robot:"})
        );
        assert_eq!(
            planned
                .integration
                .clone()
                .expect("integration")
                .content,
            json!({"text": "hi"})
        );
        assert!(noted(&planned, "channel"), "{:?}", planned.notes);
    }

    #[test]
    fn kinesis_access_keys_are_dropped_without_reporting_them() {
        let integration = live(
            "stream",
            "x402",
            json!({"platform": "kinesis", "topic": "events", "region": "eu-west-1", "access_key": "AKIA", "secret_key": "s3cr3t"}),
            json!({}),
        );

        let planned = only(&plan(
            &LegacyRecords {
                integrations: vec![integration],
                ..LegacyRecords::default()
            },
            &no_audit(),
        ))
        .clone();

        assert_eq!(
            planned.endpoint.configuration,
            json!({"platform": "kinesis", "topic": "events", "region": "eu-west-1"})
        );
        assert!(noted(&planned, "access_key, secret_key"), "{:?}", planned.notes);
        assert!(
            !planned
                .notes
                .iter()
                .any(|note| note.contains("s3cr3t") || note.contains("AKIA"))
        );
    }

    #[test]
    fn webhook_headers_lose_reserved_names_unsent_values_and_placeholders() {
        let integration = live(
            "webhook",
            "gateway",
            json!({"url": "https://93.184.215.14/hook", "headers": {
                "Authorization": "Bearer token",
                "content-type": "text/plain",
                "X-Count": 3,
                "X-Gateway": "gw ${GATEWAY_NAME}",
                "X-Only-A-Placeholder": "${GATEWAY_ID}"
            }}),
            json!({"gateway": "${GATEWAY_NAME}"}),
        );

        let planned = only(&plan(&attached_to_gateway(integration, &[]), &no_audit())).clone();

        assert_eq!(
            planned.endpoint.configuration["headers"],
            json!({"Authorization": "Bearer token", "X-Gateway": "gw "})
        );
        for header in ["content-type", "X-Count", "X-Gateway", "X-Only-A-Placeholder"] {
            assert!(noted(&planned, header), "{header}: {:?}", planned.notes);
        }
        assert!(!noted(&planned, "Bearer"), "header values are never reported: {:?}", planned.notes);
    }

    #[test]
    fn an_empty_webhook_template_now_sends_the_event_envelope() {
        for content in [json!({}), JsonValue::Null] {
            let integration = live("webhook", "gateway", json!({"url": "https://93.184.215.14/hook"}), content);

            let planned = only(&plan(&attached_to_gateway(integration, &[]), &no_audit())).clone();

            assert_eq!(
                planned
                    .integration
                    .clone()
                    .expect("integration")
                    .content,
                json!({})
            );
            assert!(noted(&planned, "event envelope"), "{:?}", planned.notes);
        }
    }

    #[test]
    fn an_audit_integration_gets_the_migration_limits_unless_it_had_its_own() {
        let records = LegacyRecords {
            integrations: vec![live("webhook", "audit", json!({"url": "https://93.184.215.14/hook"}), json!({}))],
            ..LegacyRecords::default()
        };

        let planned = only(&plan(&records, &AuditForwarding::from_settings(false, &[]))).clone();
        let integration = planned
            .integration
            .clone()
            .expect("integration");
        assert_eq!(integration.audit_drop_after_secs, Some(AUDIT_DROP_AFTER_SECS));
        assert_eq!(integration.audit_max_attempts, Some(AUDIT_MAX_ATTEMPTS));
        assert!(noted(&planned, "20 attempts"), "{:?}", planned.notes);

        let mut own = records.clone();
        own.integrations[0].audit_events = vec!["policy_decision".to_string()];
        own.integrations[0].audit_max_attempts = Some(5);
        let kept = only(&plan(&own, &no_audit()))
            .integration
            .clone()
            .expect("integration");
        assert_eq!((kept.audit_max_attempts, kept.audit_drop_after_secs), (Some(5), None));
    }

    #[test]
    fn a_tenants_integration_is_written_disabled_and_its_audit_one_keeps_only_the_endpoint() {
        let mut gateway = slack(json!({"text": "hi"}));
        gateway.tenant_id = Some("team-a".to_string());
        let planned = only(&plan(&attached_to_gateway(gateway, &[]), &no_audit())).clone();
        let integration = planned
            .integration
            .clone()
            .expect("integration");
        assert_eq!(integration.status, Status::Disabled, "enabled, it would receive every tenant's events");
        let reason = planned
            .integration_disabled
            .clone()
            .expect("reason");
        assert!(reason.contains("team-a") && reason.contains("every tenant"), "{reason}");
        assert!(noted(&planned, "written disabled"), "{:?}", planned.notes);
        assert_eq!(planned.endpoint.status, Status::Active, "no integration delivers to it while disabled");

        let operators = only(&plan(&attached_to_gateway(slack(json!({"text": "hi"})), &[]), &no_audit())).clone();
        assert_eq!(
            operators
                .integration
                .expect("integration")
                .status,
            Status::Active
        );
        assert_eq!(operators.integration_disabled, None);

        let mut audit = live("webhook", "audit", json!({"url": "https://93.184.215.14/hook"}), json!({}));
        audit.tenant_id = Some("team-a".to_string());
        let records = LegacyRecords {
            integrations: vec![audit],
            ..LegacyRecords::default()
        };
        let endpoint_only = only(&plan(&records, &no_audit())).clone();
        assert!(
            endpoint_only
                .event_set
                .is_none()
                && endpoint_only
                    .integration
                    .is_none()
        );
        assert!(noted(&endpoint_only, "only its endpoint"), "{:?}", endpoint_only.notes);
        assert_eq!(endpoint_only.integration_disabled, None);
    }

    #[test]
    fn an_integration_live_delivered_nothing_keeps_only_its_endpoint() {
        let records = LegacyRecords {
            integrations: vec![slack(json!({"text": "hi"}))],
            ..LegacyRecords::default()
        };

        let planned = only(&plan(&records, &no_audit())).clone();

        assert_eq!(planned.endpoint.id, ID);
        assert_eq!((planned.event_set, planned.integration), (None, None));
    }

    #[test]
    fn an_unknown_type_is_skipped_with_the_reason() {
        let records = LegacyRecords {
            integrations: vec![live("teams", "gateway", json!({}), json!({}))],
            ..LegacyRecords::default()
        };

        let plan = plan(&records, &no_audit());

        assert!(plan.planned.is_empty());
        assert_eq!(plan.skipped.len(), 1);
        assert!(
            plan.skipped[0]
                .reason
                .contains("teams"),
            "{:?}",
            plan.skipped
        );
    }

    #[test]
    fn a_long_name_is_shortened_to_what_the_api_allows() {
        let mut integration = slack(json!({"text": "hi"}));
        integration.name = "é".repeat(150);

        let planned = only(&plan(&attached_to_gateway(integration, &[]), &no_audit())).clone();

        assert!(planned.endpoint.name.len() <= MAX_NAME_LEN);
        let event_set = planned
            .event_set
            .expect("set");
        assert!(event_set.name.len() <= MAX_NAME_LEN, "{}", event_set.name.len());
        assert!(
            event_set
                .name
                .ends_with(EVENT_SET_SUFFIX)
        );
    }

    #[test]
    fn records_naming_no_live_integration_are_reported_once_each() {
        let missing = "0b6c9d6e-0000-4000-8000-000000000000";
        let attachment = LegacyAttachment {
            integration_id: missing.to_string(),
            variables: HashMap::new(),
            event_types: Vec::new(),
        };
        let records = LegacyRecords {
            gateway_attachments: vec![("gw-1".to_string(), vec![attachment.clone()])],
            user_attachments: vec![attachment.clone()],
            identity_attachments: vec![attachment],
            connection_points: vec![LegacyConnectionPoint {
                id: "cp-1".to_string(),
                gateway_id: "gw-1".to_string(),
                integrations: vec![LegacyConnectionPointIntegration {
                    integration_id: missing.to_string(),
                    variables: json!({}),
                }],
                integration_id: None,
            }],
            ..LegacyRecords::default()
        };

        let plan = plan(&records, &no_audit());

        assert_eq!(plan.notes.len(), 4, "{:?}", plan.notes);
        assert!(
            plan.notes
                .iter()
                .all(|note| note.contains(missing))
        );
    }

    #[test]
    fn identity_attachments_are_reported_as_never_delivered() {
        let integration = slack(json!({"text": "hi"}));
        let records = LegacyRecords {
            identity_attachments: vec![LegacyAttachment {
                integration_id: ID.to_string(),
                variables: HashMap::new(),
                event_types: Vec::new(),
            }],
            integrations: vec![integration],
            ..LegacyRecords::default()
        };

        let planned = only(&plan(&records, &no_audit())).clone();

        assert!(noted(&planned, "identities"), "{:?}", planned.notes);
    }
}
