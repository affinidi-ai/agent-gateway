//! Checks the stored definitions the way saving them does, so definitions that stopped passing
//! after a restore or an upgrade are reported at startup instead of at their first delivery.

use anyhow::Result;
use tracing::{info, warn};

use super::{DefinitionStores, Endpoint, EventSet, Integration};
use crate::integrations::events::find_event;
use crate::secrets::SecretsStore;

/// A stored definition that does not pass its checks.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: &'static str,
    pub id: String,
    pub name: String,
    pub problem: String,
}

/// How many definitions were checked, and what is wrong with them.
#[derive(Debug, Default, PartialEq)]
pub struct CheckReport {
    pub endpoints: usize,
    pub event_sets: usize,
    pub integrations: usize,
    pub findings: Vec<Finding>,
}

/// Checks every endpoint (its configuration, its secret references resolved), event set (every
/// event in the catalog) and integration (its endpoint and event set exist and its template
/// fits the set). Nothing is changed.
pub async fn check_definitions(
    endpoints: &[Endpoint],
    event_sets: &[EventSet],
    integrations: &[Integration],
    secrets: Option<&dyn SecretsStore>,
) -> CheckReport {
    let mut findings = Vec::new();
    for endpoint in endpoints {
        if let Err(problem) = endpoint
            .validate_resolved(secrets)
            .await
        {
            findings.push(finding("endpoint", &endpoint.id, &endpoint.name, problem));
        }
    }
    for event_set in event_sets {
        let unknown: Vec<&str> = event_set
            .events
            .iter()
            .map(String::as_str)
            .filter(|event| find_event(event).is_none())
            .collect();
        if !unknown.is_empty() {
            let problem = format!("Unknown events: {}", unknown.join(", "));
            findings.push(finding("event set", &event_set.id, &event_set.name, problem));
        }
    }
    for integration in integrations {
        for problem in integration_problems(integration, endpoints, event_sets) {
            findings.push(finding("integration", &integration.id, &integration.name, problem));
        }
    }
    CheckReport {
        endpoints: endpoints.len(),
        event_sets: event_sets.len(),
        integrations: integrations.len(),
        findings,
    }
}

fn integration_problems(
    integration: &Integration,
    endpoints: &[Endpoint],
    event_sets: &[EventSet],
) -> Vec<String> {
    let mut problems = Vec::new();
    if !endpoints
        .iter()
        .any(|endpoint| endpoint.id == integration.endpoint_id)
    {
        problems.push(format!("Its endpoint {} does not exist", integration.endpoint_id));
    }
    match event_sets
        .iter()
        .find(|event_set| event_set.id == integration.event_set_id)
    {
        None => problems.push(format!("Its event set {} does not exist", integration.event_set_id)),
        Some(event_set) => problems.extend(
            integration
                .check_against(event_set)
                .err(),
        ),
    }
    problems
}

fn finding(
    kind: &'static str,
    id: &str,
    name: &str,
    problem: String,
) -> Finding {
    Finding {
        kind,
        id: id.to_string(),
        name: name.to_string(),
        problem,
    }
}

/// Checks the stored definitions and logs a warning for each finding, then a summary. Delivery
/// already fails closed, so nothing is changed or disabled.
pub async fn report_stored_definitions(
    stores: &DefinitionStores,
    secrets: Option<&dyn SecretsStore>,
) -> Result<CheckReport> {
    let endpoints = stores
        .endpoints
        .list()
        .await?;
    let event_sets = stores
        .event_sets
        .list()
        .await?;
    let integrations = stores
        .integrations
        .list()
        .await?;
    let report = check_definitions(&endpoints, &event_sets, &integrations, secrets).await;
    for finding in &report.findings {
        warn!(
            event = "integrations.definition.invalid",
            kind = finding.kind,
            id = %finding.id,
            name = %finding.name,
            problem = %finding.problem,
            "A stored integration definition does not pass its checks; its deliveries will fail"
        );
    }
    let summary = format!(
        "Checked {} integration endpoints, {} event sets and {} integrations: {} problems",
        report.endpoints,
        report.event_sets,
        report.integrations,
        report.findings.len()
    );
    if report.findings.is_empty() {
        info!(event = "integrations.definitions.checked", "{summary}");
    } else {
        warn!(event = "integrations.definitions.checked", "{summary}");
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::definitions::EndpointType;
    use serde_json::json;

    fn webhook(url: &str) -> Endpoint {
        Endpoint::new("Ops webhook".to_string(), String::new(), EndpointType::Webhook, json!({"url": url}))
    }

    fn gateway_events() -> EventSet {
        EventSet::new("Gateways".to_string(), String::new(), vec!["gateway.created".to_string()]).expect("set")
    }

    fn integration(
        name: &str,
        endpoint: &Endpoint,
        event_set_id: &str,
        content: serde_json::Value,
    ) -> Integration {
        Integration::new(name.to_string(), String::new(), endpoint.id.clone(), event_set_id.to_string(), content)
    }

    #[tokio::test]
    async fn clean_definitions_have_no_findings() {
        let endpoint = webhook("https://93.184.215.14/hook");
        let events = gateway_events();
        let alerts = integration("Alerts", &endpoint, &events.id, json!({}));

        let report = check_definitions(&[endpoint], &[events], &[alerts], None).await;

        assert_eq!(
            report,
            CheckReport {
                endpoints: 1,
                event_sets: 1,
                integrations: 1,
                findings: Vec::new(),
            }
        );
    }

    #[tokio::test]
    async fn reports_each_definition_that_no_longer_passes_its_checks() {
        let internal = webhook("http://169.254.169.254/latest");
        let mut unresolved = webhook("https://93.184.215.14/hook");
        unresolved.name = "Signed webhook".to_string();
        unresolved.configuration["signing_secret"] = json!("$SECRET:hook-signing");
        let mut stale = gateway_events();
        stale
            .events
            .push("identity.created".to_string());
        let events = gateway_events();
        let orphan = integration("Orphan", &internal, "missing-set", json!({}));
        let unfilled = integration("Unfilled", &internal, &events.id, json!({"text": "${USERNAME}"}));

        let report = check_definitions(
            &[internal.clone(), unresolved.clone()],
            &[stale.clone(), events],
            &[orphan.clone(), unfilled.clone()],
            None,
        )
        .await;

        let found: Vec<(&str, &str, &str)> = report
            .findings
            .iter()
            .map(|finding| (finding.kind, finding.id.as_str(), finding.name.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                ("endpoint", internal.id.as_str(), "Ops webhook"),
                ("endpoint", unresolved.id.as_str(), "Signed webhook"),
                ("event set", stale.id.as_str(), "Gateways"),
                ("integration", orphan.id.as_str(), "Orphan"),
                ("integration", unfilled.id.as_str(), "Unfilled"),
            ]
        );
        let problems: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.problem.as_str())
            .collect();
        assert!(problems[0].contains("169.254.169.254"), "{}", problems[0]);
        assert!(problems[1].contains("hook-signing"), "{}", problems[1]);
        assert_eq!(problems[2], "Unknown events: identity.created");
        assert_eq!(problems[3], "Its event set missing-set does not exist");
        assert_eq!(problems[4], "No event of the event set fills these template variables: USERNAME");
        assert_eq!((report.endpoints, report.event_sets, report.integrations), (2, 2, 2));
    }

    #[tokio::test]
    async fn a_finding_never_shows_a_secret_or_a_slack_webhook_url() {
        let slack = |webhook_url: &str| {
            Endpoint::new("Ops Slack".to_string(), String::new(), EndpointType::Slack, json!({"webhook_url": webhook_url}))
        };
        let referenced = slack("$SECRET:slack-hook");
        let plain = slack("hooks.slack.com/services/T0/B0/s3cr3t-plain");
        let store = crate::integrations::definitions::test_secrets::Secrets(vec![(
            "slack-hook",
            None,
            "not a url s3cr3t-stored",
        )]);

        let report = check_definitions(&[referenced, plain], &[], &[], Some(&store)).await;

        let problems: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.problem.as_str())
            .collect();
        assert_eq!(problems.len(), 2);
        assert_eq!(problems[0], "The value of webhook_url from secret slack-hook fails the endpoint checks");
        assert!(!problems[1].contains("s3cr3t-plain"), "{}", problems[1]);
    }

    #[tokio::test]
    async fn an_integration_whose_endpoint_is_gone_is_reported() {
        let gone = webhook("https://93.184.215.14/hook");
        let events = gateway_events();
        let alerts = integration("Alerts", &gone, &events.id, json!({}));

        let report = check_definitions(&[], &[events], &[alerts], None).await;

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].problem, format!("Its endpoint {} does not exist", gone.id));
    }

    #[tokio::test]
    async fn reporting_the_stored_definitions_changes_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let stores = DefinitionStores::open(
            &dir.path().join("endpoints"),
            &dir.path().join("event_sets"),
            &dir.path()
                .join("integrations"),
        )
        .await
        .expect("stores");
        let internal = webhook("http://169.254.169.254/latest");
        let orphan = integration("Orphan", &internal, "missing-set", json!({}));
        stores
            .endpoints
            .save(&internal)
            .await
            .expect("save endpoint");
        stores
            .integrations
            .save(&orphan)
            .await
            .expect("save integration");

        let report = report_stored_definitions(&stores, None)
            .await
            .expect("report");

        assert_eq!(report.findings.len(), 2);
        assert_eq!(
            stores
                .endpoints
                .list()
                .await
                .expect("list"),
            [internal]
        );
        assert_eq!(
            stores
                .integrations
                .list()
                .await
                .expect("list"),
            [orphan]
        );
    }
}
