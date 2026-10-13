//! Builds the audit sinks from where each one is configured.

use std::time::Duration;

use tracing::warn;

use crate::audit::registry::{EventMask, Sink, SinkId, sinks};
use crate::integrations::audit_integration_triggers::receives_audit_records;
use crate::storage::settings_store::{DashboardSettings, global_settings};
use crate::storage::{Integration, get_integration_storage};

/// Each active, appliance-wide Governance Audit integration as a sink.
pub fn integration_sinks(integrations: &[Integration]) -> Vec<Sink> {
    integrations
        .iter()
        .filter(|integration| receives_audit_records(integration))
        .map(|integration| {
            Sink::new(
                SinkId::Integration(integration.id.clone()),
                EventMask::from_categories(
                    integration
                        .audit_events
                        .iter()
                        .map(String::as_str),
                ),
            )
            .dropping_older_than(
                integration
                    .audit_drop_after_secs
                    .map(Duration::from_secs),
            )
        })
        .collect()
}

pub fn build_sinks(
    settings: &DashboardSettings,
    integrations: &[Integration],
) -> Vec<Sink> {
    std::iter::once(audit_log_sink(settings))
        .chain(integration_sinks(integrations))
        .collect()
}

/// Rebuilds the sinks from the current settings and integrations. When the
/// integrations cannot be listed the current sinks are kept.
pub async fn rebuild_sinks() {
    let settings = global_settings().unwrap_or_default();
    let integrations = match get_integration_storage() {
        Some(storage) => match storage.list().await {
            Ok(integrations) => integrations,
            Err(e) => {
                warn!(error = %e, "Failed to list integrations; keeping the current audit sinks");
                return;
            }
        },
        None => Vec::new(),
    };
    sinks().replace(build_sinks(&settings, &integrations));
}

/// The VP Audit Log as a sink: the selected events while auditing is on,
/// nothing while it is off.
pub fn audit_log_sink(settings: &DashboardSettings) -> Sink {
    let events = if settings.audit_enabled {
        EventMask::from_categories(
            settings
                .audit_events
                .iter()
                .map(String::as_str),
        )
    } else {
        EventMask::default()
    };
    Sink::new(SinkId::AuditLog, events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::catalog::event_bit;
    use crate::audit::registry::SinkRegistry;

    #[test]
    fn default_settings_give_an_audit_log_sink_that_selects_nothing() {
        let sink = audit_log_sink(&DashboardSettings::default());
        assert_eq!(sink.id, SinkId::AuditLog);
        assert_eq!(sink.events, EventMask::default());
    }

    #[test]
    fn audit_log_sink_selects_the_stored_events_when_enabled() {
        let settings = DashboardSettings {
            audit_enabled: true,
            audit_events: vec!["policy_decision".to_string(), "no_such_event".to_string()],
            ..DashboardSettings::default()
        };
        let events = audit_log_sink(&settings).events;
        assert!(events.contains(event_bit("policy_decision").unwrap()));
        assert_eq!(events.categories(), vec!["policy_decision"]);
    }

    fn audit_integration(
        status: &str,
        tenant_id: Option<&str>,
        events: &[&str],
    ) -> Integration {
        let mut integration = Integration::new(
            "siem".to_string(),
            String::new(),
            "stream".to_string(),
            serde_json::json!({}),
            serde_json::json!({}),
            status.to_string(),
            Some("audit".to_string()),
        );
        integration.tenant_id = tenant_id.map(str::to_string);
        integration.audit_events = events
            .iter()
            .map(|event| event.to_string())
            .collect();
        integration
    }

    #[test]
    fn active_appliance_wide_audit_integrations_are_sinks() {
        let integration = audit_integration("active", None, &["auth_failed"]);
        let sinks = integration_sinks(std::slice::from_ref(&integration));
        assert_eq!(sinks.len(), 1);
        assert_eq!(sinks[0].id, SinkId::Integration(integration.id.clone()));
        assert_eq!(sinks[0].events.categories(), vec!["auth_failed"]);
    }

    #[test]
    fn an_integrations_drop_policy_carries_into_its_sink() {
        let mut integration = audit_integration("active", None, &["auth_failed"]);
        integration.audit_drop_after_secs = Some(3600);
        let without = audit_integration("active", None, &["auth_failed"]);
        let sinks = integration_sinks(&[integration, without]);
        assert_eq!(sinks[0].drop_older_than, Some(std::time::Duration::from_secs(3600)));
        assert_eq!(sinks[1].drop_older_than, None);
    }

    #[test]
    fn disabled_tenant_owned_and_other_integrations_are_not_sinks() {
        let mut general = audit_integration("active", None, &["auth_failed"]);
        general.category = Some("general".to_string());
        let integrations = [
            audit_integration("disabled", None, &["auth_failed"]),
            audit_integration("active", Some("tenant-a"), &["auth_failed"]),
            general,
        ];
        assert!(integration_sinks(&integrations).is_empty());
    }

    #[test]
    fn build_lists_the_audit_log_then_each_integration() {
        let settings = DashboardSettings {
            audit_enabled: true,
            audit_events: vec!["policy_decision".to_string()],
            ..DashboardSettings::default()
        };
        let integration = audit_integration("active", None, &["policy_decision", "trust_check"]);
        let registry = SinkRegistry::new(build_sinks(&settings, std::slice::from_ref(&integration)));

        let policy = event_bit("policy_decision").unwrap();
        let trust = event_bit("trust_check").unwrap();
        assert_eq!(registry.recipients(policy), &[SinkId::AuditLog, SinkId::Integration(integration.id.clone())]);
        assert_eq!(registry.recipients(trust), &[SinkId::Integration(integration.id.clone())]);
    }

    #[test]
    fn integrations_receive_events_the_audit_log_does_not_keep() {
        let settings = DashboardSettings::default();
        let integration = audit_integration("active", None, &["auth_failed"]);
        let registry = SinkRegistry::new(build_sinks(&settings, std::slice::from_ref(&integration)));
        assert!(registry.wants(event_bit("auth_failed").unwrap()));
    }

    #[test]
    fn inactive_audit_log_sink_selects_nothing_and_keeps_the_selection() {
        let settings = DashboardSettings {
            audit_enabled: false,
            audit_events: vec!["policy_decision".to_string()],
            ..DashboardSettings::default()
        };
        assert_eq!(audit_log_sink(&settings).events, EventMask::default());
        assert_eq!(settings.audit_events, vec!["policy_decision".to_string()]);
    }
}
