//! Forwards every governance audit record the VP Audit Log persists to the
//! active, appliance-global integrations in the `audit` category.
//!
//! The audit writer hands each appended record to [`forward`]. A dispatcher
//! task fans the record out to one bounded queue per subscribed integration, so
//! a slow or unreachable sink never stalls the audit writer or the other sinks.
//! A full queue drops the record for that sink (the VP Audit Log still holds
//! it) and counts it as `agent_gateway_audit_forward_total{result="dropped", integration_id}`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{debug, warn};

use crate::delegation_vault::audit::{
    AuditCallerContext, DelegationAuditAction, DelegationAuditEvent, action_category,
};
use crate::storage::Integration;

/// Integration category whose integrations receive governance audit records.
pub const AUDIT_CATEGORY: &str = "audit";

/// Integration types an audit integration may use. Every VP Audit Log write is
/// a delivery, more than Email or Slack can carry.
pub const AUDIT_INTEGRATION_TYPES: [&str; 2] = ["stream", "webhook"];

const DROP_WARN_INTERVAL: Duration = Duration::from_secs(10);

/// Every audit record category, as `(category, name, description)`. Its event
/// type is `audit.<category>`.
const AUDIT_EVENT_CATEGORIES: &[(&str, &str, &str)] = &[
    (
        "policy_decision",
        "Policy Decision",
        "A gateway, surface, MCP-tool or response OPA policy allowed or denied a request",
    ),
    ("trust_check", "Trust Check", "A TRQP trust-check outcome for the caller or target leg"),
    ("trace_terminated", "Trace Terminated", "A surface terminated the end-to-end trace at its egress"),
    (
        "vp_injected",
        "VP Injected",
        "A signed identity Verifiable Presentation was injected into a proxied request or response",
    ),
    ("token_injected", "Token Injected", "A delegated credential from the vault was injected on the caller's behalf"),
    ("token_refreshed", "Token Refreshed", "An expired delegated credential was refreshed and injected"),
    ("refresh_failed", "Refresh Failed", "A delegated credential could not be refreshed, so consent is required again"),
    ("consent_granted", "Consent Granted", "A user completed the OAuth consent flow and a delegation token was stored"),
    ("consent_required", "Consent Required", "The caller was asked to grant consent before the request could proceed"),
    ("token_revoked", "Token Revoked", "A delegation token was revoked through the management API"),
    ("user_tokens_revoked", "User Tokens Revoked", "Every delegation token for a user was revoked"),
    ("token_not_found", "Token Not Found", "A delegation token lookup found no match"),
    ("elicitation_sent", "Elicitation Sent", "An MCP elicitation request was sent to the client"),
    ("elicitation_accepted", "Elicitation Accepted", "The client accepted an MCP elicitation"),
    ("elicitation_declined", "Elicitation Declined", "The client declined an MCP elicitation"),
    ("elicitation_cancelled", "Elicitation Cancelled", "The client cancelled an MCP elicitation"),
    ("elicitation_timed_out", "Elicitation Timed Out", "The client did not answer an MCP elicitation in time"),
    (
        "pre_authorize_blocked",
        "Pre-Authorize Blocked",
        "Pre-authorization blocked a session because a required credential was missing",
    ),
    ("payment", "Payment Event", "An x402 or MPP payment lifecycle event (challenge, verification, settlement)"),
];

/// The `audit` integration category offered in the integration configuration.
pub fn audit_integration_category() -> crate::config::IntegrationCategory {
    crate::config::IntegrationCategory {
        enum_value: AUDIT_CATEGORY.to_string(),
        name: "Governance Audit".to_string(),
        description: "Forwards every record written to the VP Audit Log: policy decisions, trust checks, VP injections, credential delegation and payment events. Requires the audit.view permission.".to_string(),
        metadata: serde_json::json!({
            "event_types": AUDIT_EVENT_CATEGORIES
                .iter()
                .map(|(category, name, description)| serde_json::json!({
                    "event_type": format!("{}.{}", AUDIT_CATEGORY, category),
                    "name": name,
                    "description": description,
                }))
                .collect::<Vec<_>>(),
        }),
    }
}

/// Whether the integration belongs to the governance audit category.
pub fn is_audit_integration(integration: &Integration) -> bool {
    integration
        .category
        .as_deref()
        == Some(AUDIT_CATEGORY)
}

/// Audit records carry appliance-wide evidence, so only active Stream or
/// Webhook integrations without a tenant owner receive them.
fn receives_audit_records(integration: &Integration) -> bool {
    is_audit_integration(integration)
        && AUDIT_INTEGRATION_TYPES.contains(
            &integration
                .integration_type
                .as_str(),
        )
        && integration.status == "active"
        && integration
            .tenant_id
            .is_none()
}

/// `audit.<category>`, e.g. `audit.policy_decision`.
pub fn audit_event_type(event: &DelegationAuditEvent) -> String {
    format!("{}.{}", AUDIT_CATEGORY, action_category(&event.event))
}

/// Runtime variables describing one audit record.
pub fn audit_variables(event: &DelegationAuditEvent) -> HashMap<String, String> {
    let text = |value: &Option<String>| {
        value
            .clone()
            .unwrap_or_default()
    };
    let policy = match &event.event {
        DelegationAuditAction::PolicyDecision {
            decision,
            deny_reason,
            policy_id,
            policy_name,
            policy_version,
            policy_content_hash,
            ..
        } => PolicyVariables {
            decision: decision.clone(),
            deny_reason: text(deny_reason),
            name: policy_name
                .clone()
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| policy_id.clone()),
            version: policy_version
                .map(|version| version.to_string())
                .unwrap_or_default(),
            content_hash: text(policy_content_hash),
        },
        _ => PolicyVariables::default(),
    };
    let caller = event.caller.as_ref();
    let caller_text = |field: fn(&AuditCallerContext) -> &Option<String>| {
        caller
            .and_then(|caller| field(caller).clone())
            .unwrap_or_default()
    };

    HashMap::from([
        ("EVENT_TYPE".to_string(), audit_event_type(event)),
        ("TIMESTAMP".to_string(), event.timestamp.clone()),
        ("AUDIT_RECORD".to_string(), serde_json::to_string(event).unwrap_or_default()),
        ("AUDIT_CATEGORY".to_string(), action_category(&event.event).to_string()),
        ("AUDIT_TRACE_ID".to_string(), text(&event.trace_id)),
        ("AUDIT_SURFACE_ID".to_string(), text(&event.surface_id)),
        ("AUDIT_SURFACE_NAME".to_string(), text(&event.channel_name)),
        ("AUDIT_PROTOCOL".to_string(), text(&event.protocol)),
        ("AUDIT_AGENT_DID".to_string(), text(&event.agent_identity_did)),
        ("AUDIT_VIA_FABRIC".to_string(), event.via_fabric.to_string()),
        (
            "AUDIT_PRINCIPAL".to_string(),
            caller
                .map(principal)
                .unwrap_or_default(),
        ),
        ("AUDIT_PRINCIPAL_EMAIL".to_string(), caller_text(|caller| &caller.email)),
        ("AUDIT_PRINCIPAL_NAME".to_string(), caller_text(|caller| &caller.name)),
        (
            "AUDIT_AUTH_METHOD".to_string(),
            caller
                .map(|caller| caller.auth_method.clone())
                .unwrap_or_default(),
        ),
        ("AUDIT_DECISION".to_string(), policy.decision),
        ("AUDIT_DENY_REASON".to_string(), policy.deny_reason),
        ("AUDIT_POLICY_NAME".to_string(), policy.name),
        ("AUDIT_POLICY_VERSION".to_string(), policy.version),
        ("AUDIT_POLICY_CONTENT_HASH".to_string(), policy.content_hash),
        ("AUDIT_VP_JWT".to_string(), text(&event.vp_jwt)),
        ("AUDIT_VP_FINGERPRINT".to_string(), text(&event.vp_fingerprint)),
    ])
}

#[derive(Default)]
struct PolicyVariables {
    decision: String,
    deny_reason: String,
    name: String,
    version: String,
    content_hash: String,
}

/// The authenticated caller as a person reads it: email, else display name,
/// else the authenticated subject (JWT `sub`, API key name, DID, mTLS principal).
fn principal(caller: &AuditCallerContext) -> String {
    [&caller.email, &caller.name, &caller.sub]
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_default()
}

/// One audit record, rendered once and shared by every subscribed integration.
#[derive(Debug)]
pub(crate) struct AuditDelivery {
    subject: String,
    message: String,
    variables: HashMap<String, String>,
}

impl AuditDelivery {
    fn from_event(event: &DelegationAuditEvent) -> Self {
        let event_type = audit_event_type(event);
        Self {
            subject: format!("Governance Audit: {}", event_type),
            message: format!("Governance audit record '{}' written", event_type),
            variables: audit_variables(event),
        }
    }
}

type LoadSubscribers = Arc<dyn Fn() -> BoxFuture<'static, Option<HashSet<String>>> + Send + Sync>;
type Deliver = Arc<dyn Fn(String, Arc<AuditDelivery>) -> BoxFuture<'static, ()> + Send + Sync>;

struct DispatcherConfig {
    intake_capacity: usize,
    queue_capacity: usize,
    refresh_interval: Duration,
    stale: Arc<AtomicBool>,
    load_subscribers: LoadSubscribers,
    deliver: Deliver,
}

fn production_stale_flag() -> &'static Arc<AtomicBool> {
    static STALE: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    STALE.get_or_init(|| Arc::new(AtomicBool::new(true)))
}

fn production_intake() -> &'static mpsc::Sender<DelegationAuditEvent> {
    static INTAKE: OnceLock<mpsc::Sender<DelegationAuditEvent>> = OnceLock::new();
    INTAKE.get_or_init(|| {
        spawn_dispatcher(DispatcherConfig {
            intake_capacity: 4096,
            queue_capacity: 1024,
            refresh_interval: Duration::from_secs(30),
            stale: production_stale_flag().clone(),
            load_subscribers: Arc::new(|| Box::pin(load_subscribers_from_storage())),
            deliver: Arc::new(|integration_id, delivery| Box::pin(deliver_to_integration(integration_id, delivery))),
        })
    })
}

/// Queue a persisted audit record for every audit integration. Never blocks.
pub fn forward(event: DelegationAuditEvent) {
    static INTAKE_FULL: WarnThrottle = WarnThrottle::new();
    static INTAKE_CLOSED: WarnThrottle = WarnThrottle::new();

    match production_intake().try_send(event) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            crate::metrics::backends::prometheus::track_audit_forward("dropped", None);
            if let Some(dropped) = INTAKE_FULL.record() {
                warn!(
                    dropped,
                    "Audit forwarding intake queue is full; audit records were not forwarded to integrations"
                );
            }
        }
        Err(TrySendError::Closed(_)) => {
            crate::metrics::backends::prometheus::track_audit_forward("dropped", None);
            if let Some(dropped) = INTAKE_CLOSED.record() {
                warn!(
                    dropped,
                    "Audit forwarding dispatcher has stopped; audit records were not forwarded to integrations"
                );
            }
        }
    }
}

/// Make the dispatcher reload its subscriber list before the next record.
pub fn invalidate_subscribers() {
    production_stale_flag().store(true, Ordering::Release);
}

/// Rate-limits a repeating WARN to one per [`DROP_WARN_INTERVAL`]. `record`
/// counts an occurrence and, when a WARN may be logged, returns how many
/// occurrences it stands for.
struct WarnThrottle {
    pending: AtomicU64,
    last: std::sync::Mutex<Option<Instant>>,
}

impl WarnThrottle {
    const fn new() -> Self {
        Self {
            pending: AtomicU64::new(0),
            last: std::sync::Mutex::new(None),
        }
    }

    fn record(&self) -> Option<u64> {
        self.pending
            .fetch_add(1, Ordering::Relaxed);
        let Ok(mut last) = self.last.try_lock() else {
            return None;
        };
        if last.is_some_and(|at| at.elapsed() < DROP_WARN_INTERVAL) {
            return None;
        }
        *last = Some(Instant::now());
        Some(
            self.pending
                .swap(0, Ordering::Relaxed),
        )
    }
}

async fn load_subscribers_from_storage() -> Option<HashSet<String>> {
    let storage = crate::storage::get_integration_storage()?;
    match storage.list().await {
        Ok(integrations) => Some(
            integrations
                .into_iter()
                .filter(receives_audit_records)
                .map(|integration| integration.id)
                .collect(),
        ),
        Err(e) => {
            warn!(error = %e, "Failed to list integrations for audit forwarding");
            None
        }
    }
}

async fn deliver_to_integration(
    integration_id: String,
    delivery: Arc<AuditDelivery>,
) {
    use crate::integrations::integration_service::{load_integration, publish_to_integration};
    use crate::metrics::backends::prometheus::track_audit_forward;
    static DELIVERY_FAILED: WarnThrottle = WarnThrottle::new();

    let result = match load_integration(&integration_id).await {
        Ok(integration) if receives_audit_records(&integration) => {
            publish_to_integration(&integration, &delivery.subject, &delivery.message, &delivery.variables)
                .await
                .map_err(|e| e.to_string())
        }
        Ok(_) => {
            track_audit_forward("dropped", Some(&integration_id));
            return;
        }
        Err(e) => Err(e.to_string()),
    };
    match result {
        Ok(()) => track_audit_forward("delivered", Some(&integration_id)),
        Err(error) => {
            track_audit_forward("failed", Some(&integration_id));
            if let Some(failures) = DELIVERY_FAILED.record() {
                warn!(
                    integration_id = %integration_id,
                    event_type = delivery.variables.get("EVENT_TYPE").map(String::as_str).unwrap_or_default(),
                    error = %error,
                    failures,
                    "Failed to forward audit records to integrations"
                );
            }
        }
    }
}

fn spawn_dispatcher(config: DispatcherConfig) -> mpsc::Sender<DelegationAuditEvent> {
    let (tx, rx) = mpsc::channel(config.intake_capacity);
    tokio::spawn(run_dispatcher(rx, config));
    tx
}

async fn run_dispatcher(
    mut intake: mpsc::Receiver<DelegationAuditEvent>,
    config: DispatcherConfig,
) {
    let mut subscribers: HashSet<String> = HashSet::new();
    let mut loaded_at: Option<Instant> = None;
    let mut workers: HashMap<String, Worker> = HashMap::new();
    let mut dropped: u64 = 0;
    let mut last_drop_warn: Option<Instant> = None;

    while let Some(event) = intake.recv().await {
        let expired = loaded_at.is_none_or(|at| at.elapsed() >= config.refresh_interval);
        if config
            .stale
            .swap(false, Ordering::AcqRel)
            || expired
        {
            if let Some(current) = (config.load_subscribers)().await {
                subscribers = current;
                workers.retain(|id, worker| {
                    let subscribed = subscribers.contains(id);
                    if !subscribed {
                        worker
                            .retired
                            .store(true, Ordering::Release);
                    }
                    subscribed
                });
            }
            loaded_at = Some(Instant::now());
        }
        if subscribers.is_empty() {
            continue;
        }

        let delivery = Arc::new(AuditDelivery::from_event(&event));
        for integration_id in &subscribers {
            let new_worker = || spawn_worker(integration_id.clone(), config.queue_capacity, config.deliver.clone());
            let worker = workers
                .entry(integration_id.clone())
                .or_insert_with(&new_worker);
            match worker
                .queue
                .try_send(delivery.clone())
            {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    crate::metrics::backends::prometheus::track_audit_forward("dropped", Some(integration_id));
                    dropped += 1;
                }
                Err(TrySendError::Closed(pending)) => {
                    *worker = new_worker();
                    let _ = worker.queue.try_send(pending);
                }
            }
        }

        if dropped > 0 && last_drop_warn.is_none_or(|at| at.elapsed() >= DROP_WARN_INTERVAL) {
            warn!(dropped, "Audit integration queues are full; audit records were not forwarded");
            dropped = 0;
            last_drop_warn = Some(Instant::now());
        }
    }
    debug!("Audit forwarding dispatcher stopped");
}

/// One destination's queue. A worker retired because its integration stopped
/// receiving audit records discards what is still queued, counted as
/// `dropped`, instead of delivering it or logging a failure per record.
struct Worker {
    queue: mpsc::Sender<Arc<AuditDelivery>>,
    retired: Arc<AtomicBool>,
}

fn spawn_worker(
    integration_id: String,
    capacity: usize,
    deliver: Deliver,
) -> Worker {
    let (queue, mut rx) = mpsc::channel::<Arc<AuditDelivery>>(capacity);
    let retired = Arc::new(AtomicBool::new(false));
    let worker_retired = retired.clone();
    tokio::spawn(async move {
        while let Some(delivery) = rx.recv().await {
            if worker_retired.load(Ordering::Acquire) {
                crate::metrics::backends::prometheus::track_audit_forward("dropped", Some(&integration_id));
                continue;
            }
            deliver(integration_id.clone(), delivery).await;
        }
    });
    Worker { queue, retired }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_vault::audit::{PaymentEventDetails, PaymentRail, PaymentStage, audit_event};
    use std::sync::Mutex;
    use tokio::sync::{Semaphore, mpsc::UnboundedReceiver};

    fn integration(
        category: Option<&str>,
        status: &str,
        tenant_id: Option<&str>,
    ) -> Integration {
        let mut integration = Integration::new(
            "Audit stream".to_string(),
            String::new(),
            "stream".to_string(),
            serde_json::json!({"platform": "kafka", "topic": "audit"}),
            serde_json::json!({}),
            status.to_string(),
            category.map(str::to_string),
        );
        integration.tenant_id = tenant_id.map(str::to_string);
        integration
    }

    fn policy_decision(decision: &str) -> DelegationAuditEvent {
        let mut event = audit_event(
            DelegationAuditAction::PolicyDecision {
                scope: "surface".to_string(),
                flow: "access_point".to_string(),
                policy_id: "surface.policy".to_string(),
                policy_name: Some("Deny unknown callers".to_string()),
                policy_definition_id: None,
                decision: decision.to_string(),
                deny_reason: (decision == "deny").then(|| "caller not recognised".to_string()),
                surface_id: Some("surface-1".to_string()),
                caller_did: Some("did:web:caller".to_string()),
                http_method: Some("POST".to_string()),
                http_path: Some("/a2a".to_string()),
                policy_version: Some(3),
                policy_content_hash: Some("sha256:abc".to_string()),
            },
            None,
            None,
            None,
            Some("surface-1"),
        );
        event.channel_name = Some("Billing agent".to_string());
        event.protocol = Some("a2a".to_string());
        event.agent_identity_did = Some("did:web:agent".to_string());
        event.trace_id = Some("trace-1".to_string());
        event.vp_jwt = Some("eyJhbGciOiJFZERTQSJ9.eyJ2cCI6e319.sig".to_string());
        event.vp_fingerprint = Some("sha256:vp".to_string());
        event.caller = Some(jwt_caller(Some("ada@example.com"), Some("Ada Lovelace")));
        event
    }

    fn jwt_caller(
        email: Option<&str>,
        name: Option<&str>,
    ) -> AuditCallerContext {
        crate::delegation_vault::audit::build_caller_context(&crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "user-123".to_string(),
            claims: serde_json::json!({"iss": "https://idp.example.com", "email": email, "name": name}),
        })
    }

    fn vp_injected(trace_id: &str) -> DelegationAuditEvent {
        let mut event = audit_event(DelegationAuditAction::VpInjected, None, None, None, Some("surface-2"));
        event.trace_id = Some(trace_id.to_string());
        event.via_fabric = true;
        event.vp_jwt = Some("vp-jwt".to_string());
        event
    }

    #[test]
    fn audit_variables_describe_a_policy_decision() {
        let event = policy_decision("deny");
        let variables = audit_variables(&event);

        assert_eq!(variables["EVENT_TYPE"], "audit.policy_decision");
        assert_eq!(variables["TIMESTAMP"], event.timestamp);
        assert_eq!(variables["AUDIT_CATEGORY"], "policy_decision");
        assert_eq!(variables["AUDIT_TRACE_ID"], "trace-1");
        assert_eq!(variables["AUDIT_SURFACE_ID"], "surface-1");
        assert_eq!(variables["AUDIT_SURFACE_NAME"], "Billing agent");
        assert_eq!(variables["AUDIT_PROTOCOL"], "a2a");
        assert_eq!(variables["AUDIT_AGENT_DID"], "did:web:agent");
        assert_eq!(variables["AUDIT_VIA_FABRIC"], "false");
        assert_eq!(variables["AUDIT_DECISION"], "deny");
        assert_eq!(variables["AUDIT_DENY_REASON"], "caller not recognised");
        assert_eq!(variables["AUDIT_POLICY_NAME"], "Deny unknown callers");
        assert_eq!(variables["AUDIT_POLICY_VERSION"], "3");
        assert_eq!(variables["AUDIT_POLICY_CONTENT_HASH"], "sha256:abc");
        assert_eq!(variables["AUDIT_PRINCIPAL"], "ada@example.com");
        assert_eq!(variables["AUDIT_PRINCIPAL_EMAIL"], "ada@example.com");
        assert_eq!(variables["AUDIT_PRINCIPAL_NAME"], "Ada Lovelace");
        assert_eq!(variables["AUDIT_AUTH_METHOD"], "jwt_bearer");
        assert_eq!(variables["AUDIT_VP_JWT"], "eyJhbGciOiJFZERTQSJ9.eyJ2cCI6e319.sig");
        assert_eq!(variables["AUDIT_VP_FINGERPRINT"], "sha256:vp");

        let record: serde_json::Value = serde_json::from_str(&variables["AUDIT_RECORD"]).unwrap();
        assert_eq!(record, serde_json::to_value(&event).unwrap(), "the record is the VP Audit Log row");
        assert_eq!(record["event"]["policy_decision"]["decision"], "deny");
    }

    #[test]
    fn audit_variables_leave_policy_fields_empty_for_other_categories() {
        let variables = audit_variables(&vp_injected("trace-9"));

        assert_eq!(variables["EVENT_TYPE"], "audit.vp_injected");
        assert_eq!(variables["AUDIT_CATEGORY"], "vp_injected");
        assert_eq!(variables["AUDIT_VIA_FABRIC"], "true");
        assert_eq!(variables["AUDIT_VP_JWT"], "vp-jwt");
        assert_eq!(variables["AUDIT_DECISION"], "");
        assert_eq!(variables["AUDIT_DENY_REASON"], "");
        assert_eq!(variables["AUDIT_POLICY_NAME"], "");
        assert_eq!(variables["AUDIT_POLICY_VERSION"], "");
        assert_eq!(variables["AUDIT_POLICY_CONTENT_HASH"], "");
        assert_eq!(variables["AUDIT_PRINCIPAL"], "", "no caller context means no principal");
        assert_eq!(variables["AUDIT_PRINCIPAL_EMAIL"], "");
        assert_eq!(variables["AUDIT_PRINCIPAL_NAME"], "");
        assert_eq!(variables["AUDIT_AUTH_METHOD"], "");
        assert_eq!(variables["AUDIT_SURFACE_NAME"], "");
        assert_eq!(variables["AUDIT_VP_FINGERPRINT"], "");
    }

    #[test]
    fn allow_decision_has_no_deny_reason() {
        let variables = audit_variables(&policy_decision("allow"));
        assert_eq!(variables["AUDIT_DECISION"], "allow");
        assert_eq!(variables["AUDIT_DENY_REASON"], "");
    }

    #[test]
    fn principal_falls_back_from_email_to_name_to_subject() {
        let with = |caller: AuditCallerContext| {
            let mut event = policy_decision("allow");
            event.caller = Some(caller);
            audit_variables(&event)["AUDIT_PRINCIPAL"].clone()
        };

        assert_eq!(with(jwt_caller(Some("ada@example.com"), Some("Ada"))), "ada@example.com");
        assert_eq!(with(jwt_caller(None, Some("Ada Lovelace"))), "Ada Lovelace");
        assert_eq!(with(jwt_caller(None, None)), "user-123");
        assert_eq!(with(jwt_caller(Some(""), None)), "user-123", "an empty claim is skipped");

        let api_key =
            crate::delegation_vault::audit::build_caller_context(&crate::source_auth::AuthenticatedIdentity::ApiKey {
                key_name: "billing-bot".to_string(),
            });
        let mut event = policy_decision("allow");
        event.caller = Some(api_key);
        let variables = audit_variables(&event);
        assert_eq!(variables["AUDIT_PRINCIPAL"], "billing-bot");
        assert_eq!(variables["AUDIT_AUTH_METHOD"], "api_key");
        assert_eq!(variables["AUDIT_PRINCIPAL_EMAIL"], "");
    }

    #[test]
    fn a_decision_without_caller_context_has_an_empty_principal() {
        let mut event = policy_decision("deny");
        event.caller = None;
        let variables = audit_variables(&event);

        assert_eq!(variables["AUDIT_PRINCIPAL"], "");
        assert_eq!(variables["AUDIT_AUTH_METHOD"], "");
        assert_eq!(variables["AUDIT_POLICY_NAME"], "Deny unknown callers", "policy fields do not need a caller");
    }

    #[test]
    fn policy_name_falls_back_to_the_policy_package() {
        let mut event = policy_decision("allow");
        if let DelegationAuditAction::PolicyDecision {
            policy_name,
            policy_version,
            policy_content_hash,
            ..
        } = &mut event.event
        {
            *policy_name = None;
            *policy_version = None;
            *policy_content_hash = None;
        }
        let variables = audit_variables(&event);

        assert_eq!(variables["AUDIT_POLICY_NAME"], "surface.policy");
        assert_eq!(variables["AUDIT_POLICY_VERSION"], "", "an unversioned policy has no version");
        assert_eq!(variables["AUDIT_POLICY_CONTENT_HASH"], "");
    }

    #[test]
    fn every_audit_variable_is_offered_to_audit_templates() {
        let produced: HashSet<String> = audit_variables(&policy_decision("deny"))
            .into_keys()
            .collect();
        let offered: HashSet<String> =
            crate::integrations::runtime_variables::get_variable_names_for_category(AUDIT_CATEGORY)
                .into_iter()
                .collect();

        let unregistered: Vec<_> = produced
            .difference(&offered)
            .collect();
        assert!(unregistered.is_empty(), "variables templates cannot use: {unregistered:?}");
        let audit_only: HashSet<String> = offered
            .into_iter()
            .filter(|name| name.starts_with("AUDIT_"))
            .collect();
        let never_set: Vec<_> = audit_only
            .difference(&produced)
            .collect();
        assert!(never_set.is_empty(), "offered variables that are never set: {never_set:?}");
    }

    #[test]
    fn only_active_appliance_wide_audit_integrations_receive_records() {
        assert!(receives_audit_records(&integration(Some("audit"), "active", None)));

        assert!(!receives_audit_records(&integration(Some("audit"), "disabled", None)));
        assert!(!receives_audit_records(&integration(Some("audit"), "active", Some("tenant-a"))));
        assert!(!receives_audit_records(&integration(Some("gateway"), "active", None)));
        assert!(!receives_audit_records(&integration(None, "active", None)));

        for (integration_type, receives) in [("webhook", true), ("email", false), ("slack", false)] {
            let mut typed = integration(Some("audit"), "active", None);
            typed.integration_type = integration_type.to_string();
            assert_eq!(receives_audit_records(&typed), receives, "{integration_type}");
        }
    }

    #[test]
    fn is_audit_integration_matches_the_category_only() {
        assert!(is_audit_integration(&integration(Some("audit"), "disabled", Some("tenant-a"))));
        assert!(!is_audit_integration(&integration(Some("x402"), "active", None)));
        assert!(!is_audit_integration(&integration(None, "active", None)));
    }

    /// Adding a `DelegationAuditAction` variant fails this match until the
    /// variant is added to [`every_action`] as well.
    fn listed(action: &DelegationAuditAction) {
        match action {
            DelegationAuditAction::ConsentGranted
            | DelegationAuditAction::TokenInjected
            | DelegationAuditAction::TokenRefreshed
            | DelegationAuditAction::RefreshFailed
            | DelegationAuditAction::ConsentRequired
            | DelegationAuditAction::TokenRevoked
            | DelegationAuditAction::UserTokensRevoked
            | DelegationAuditAction::TokenNotFound
            | DelegationAuditAction::VpInjected
            | DelegationAuditAction::ElicitationSent
            | DelegationAuditAction::ElicitationAccepted
            | DelegationAuditAction::ElicitationDeclined
            | DelegationAuditAction::ElicitationCancelled
            | DelegationAuditAction::ElicitationTimedOut
            | DelegationAuditAction::PreAuthorizeBlocked
            | DelegationAuditAction::PolicyDecision { .. }
            | DelegationAuditAction::TrustCheck { .. }
            | DelegationAuditAction::TraceTerminated { .. }
            | DelegationAuditAction::PaymentEvent(_) => {}
        }
    }

    fn every_action() -> Vec<DelegationAuditAction> {
        vec![
            DelegationAuditAction::ConsentGranted,
            DelegationAuditAction::TokenInjected,
            DelegationAuditAction::TokenRefreshed,
            DelegationAuditAction::RefreshFailed,
            DelegationAuditAction::ConsentRequired,
            DelegationAuditAction::TokenRevoked,
            DelegationAuditAction::UserTokensRevoked,
            DelegationAuditAction::TokenNotFound,
            DelegationAuditAction::VpInjected,
            DelegationAuditAction::ElicitationSent,
            DelegationAuditAction::ElicitationAccepted,
            DelegationAuditAction::ElicitationDeclined,
            DelegationAuditAction::ElicitationCancelled,
            DelegationAuditAction::ElicitationTimedOut,
            DelegationAuditAction::PreAuthorizeBlocked,
            policy_decision("allow").event,
            DelegationAuditAction::TrustCheck {
                leg: "caller".to_string(),
                authority_id: None,
                entity_id: None,
                ok: true,
                error_code: None,
            },
            DelegationAuditAction::TraceTerminated {
                own_trace_id: "own".to_string(),
                downstream_trace_id: "downstream".to_string(),
                flow: "access_point".to_string(),
            },
            DelegationAuditAction::PaymentEvent(Box::new(PaymentEventDetails {
                rail: PaymentRail::X402,
                stage: PaymentStage::Settled,
                transaction_id: "tx-1".to_string(),
                amount: None,
                currency: None,
                method: None,
                payer: None,
                error: None,
                delegated: false,
                payment_gateway_id: None,
                payment_surface_id: None,
                remote_status: None,
            })),
        ]
    }

    fn category_event_types(category: &crate::config::IntegrationCategory) -> Vec<String> {
        category.metadata["event_types"]
            .as_array()
            .expect("the audit category lists its event types")
            .iter()
            .map(|event| {
                event["event_type"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn audit_category_lists_every_audit_record_category() {
        let actions = every_action();
        actions
            .iter()
            .for_each(listed);
        let produced: HashSet<String> = actions
            .iter()
            .map(|action| format!("audit.{}", action_category(action)))
            .collect();

        let category = audit_integration_category();
        let listed_types = category_event_types(&category);
        let listed_set: HashSet<String> = listed_types
            .iter()
            .cloned()
            .collect();

        assert_eq!(category.enum_value, "audit");
        assert_eq!(listed_types.len(), listed_set.len(), "event types are unique");
        assert_eq!(listed_set, produced, "every audit record category has exactly one event type");
    }

    #[test]
    fn example_gateway_config_carries_the_built_in_audit_category() {
        let example: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/config/examples/gateway.example.json"
        )))
        .unwrap();
        let shipped = example["integration"]["categories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|category| category["enum_value"] == AUDIT_CATEGORY)
            .expect("gateway.example.json offers the audit category");

        assert_eq!(*shipped, serde_json::to_value(audit_integration_category()).unwrap());
    }

    #[test]
    fn default_integration_config_offers_the_audit_category() {
        let config = crate::config::IntegrationConfig::default_config();
        assert!(
            config
                .categories
                .iter()
                .any(|category| category.enum_value == AUDIT_CATEGORY)
        );
    }

    struct Harness {
        intake: mpsc::Sender<DelegationAuditEvent>,
        subscribers: Arc<Mutex<Option<HashSet<String>>>>,
        stale: Arc<AtomicBool>,
        delivered: UnboundedReceiver<(String, String)>,
    }

    impl Harness {
        fn new(
            queue_capacity: usize,
            subscribers: &[&str],
            gate: Option<(&str, Arc<Semaphore>, mpsc::UnboundedSender<()>)>,
        ) -> Self {
            let subscribers = Arc::new(Mutex::new(Some(
                subscribers
                    .iter()
                    .map(|id| id.to_string())
                    .collect(),
            )));
            let stale = Arc::new(AtomicBool::new(false));
            let (delivered_tx, delivered) = mpsc::unbounded_channel();
            let gate = gate.map(|(id, permits, started)| (id.to_string(), permits, started));
            let source = subscribers.clone();
            let intake = spawn_dispatcher(DispatcherConfig {
                intake_capacity: 64,
                queue_capacity,
                refresh_interval: Duration::from_secs(3600),
                stale: stale.clone(),
                load_subscribers: Arc::new(move || {
                    let current = source.lock().unwrap().clone();
                    Box::pin(async move { current })
                }),
                deliver: Arc::new(move |integration_id, delivery| {
                    let delivered_tx = delivered_tx.clone();
                    let gate = gate.clone();
                    Box::pin(async move {
                        if let Some((gated_id, permits, started)) = gate
                            && gated_id == integration_id
                        {
                            let _ = started.send(());
                            permits
                                .acquire()
                                .await
                                .unwrap()
                                .forget();
                        }
                        let trace_id = delivery.variables["AUDIT_TRACE_ID"].clone();
                        let _ = delivered_tx.send((integration_id, trace_id));
                    })
                }),
            });
            Self {
                intake,
                subscribers,
                stale,
                delivered,
            }
        }

        async fn send(
            &self,
            trace_id: &str,
        ) {
            self.intake
                .send(vp_injected(trace_id))
                .await
                .unwrap();
        }

        fn set_subscribers(
            &self,
            subscribers: Option<&[&str]>,
        ) {
            *self
                .subscribers
                .lock()
                .unwrap() = subscribers.map(|ids| {
                ids.iter()
                    .map(|id| id.to_string())
                    .collect()
            });
            self.stale
                .store(true, Ordering::Release);
        }

        async fn next(&mut self) -> (String, String) {
            tokio::time::timeout(Duration::from_secs(5), self.delivered.recv())
                .await
                .expect("a delivery arrives")
                .expect("the dispatcher is running")
        }

        async fn collect(
            &mut self,
            count: usize,
        ) -> HashMap<String, Vec<String>> {
            let mut by_integration: HashMap<String, Vec<String>> = HashMap::new();
            for _ in 0..count {
                let (integration_id, trace_id) = self.next().await;
                by_integration
                    .entry(integration_id)
                    .or_default()
                    .push(trace_id);
            }
            by_integration
        }

        async fn assert_quiet(&mut self) {
            assert!(
                tokio::time::timeout(Duration::from_millis(200), self.delivered.recv())
                    .await
                    .is_err(),
                "no further deliveries are expected"
            );
        }
    }

    fn traces(ids: &[&str]) -> Vec<String> {
        ids.iter()
            .map(|id| id.to_string())
            .collect()
    }

    #[tokio::test]
    async fn dispatcher_forwards_every_record_to_every_subscriber_in_order() {
        let mut harness = Harness::new(16, &["kafka", "webhook"], None);
        for trace_id in ["t1", "t2", "t3"] {
            harness.send(trace_id).await;
        }

        let delivered = harness.collect(6).await;
        assert_eq!(delivered["kafka"], traces(&["t1", "t2", "t3"]));
        assert_eq!(delivered["webhook"], traces(&["t1", "t2", "t3"]));
        harness.assert_quiet().await;
    }

    #[tokio::test]
    async fn dispatcher_forwards_nothing_without_subscribers() {
        let mut harness = Harness::new(16, &[], None);
        harness
            .send("unsubscribed")
            .await;
        harness.assert_quiet().await;

        harness.set_subscribers(Some(&["kafka"]));
        harness
            .send("subscribed")
            .await;
        assert_eq!(harness.next().await, ("kafka".to_string(), "subscribed".to_string()));
        harness.assert_quiet().await;
    }

    #[tokio::test]
    async fn dispatcher_follows_subscriber_changes() {
        let mut harness = Harness::new(16, &["kafka", "webhook"], None);
        harness.send("t1").await;
        let first = harness.collect(2).await;
        assert_eq!(first["kafka"], traces(&["t1"]));
        assert_eq!(first["webhook"], traces(&["t1"]));

        harness.set_subscribers(Some(&["kafka", "slack"]));
        harness.send("t2").await;
        let second = harness.collect(2).await;
        assert_eq!(second["kafka"], traces(&["t2"]));
        assert_eq!(second["slack"], traces(&["t2"]));
        assert!(!second.contains_key("webhook"), "a removed subscriber stops receiving records");
        harness.assert_quiet().await;
    }

    #[tokio::test]
    async fn dispatcher_keeps_subscribers_when_reload_fails() {
        let mut harness = Harness::new(16, &["kafka"], None);
        harness.send("t1").await;
        assert_eq!(harness.next().await.1, "t1");

        harness.set_subscribers(None);
        harness.send("t2").await;
        assert_eq!(harness.next().await, ("kafka".to_string(), "t2".to_string()));
    }

    #[tokio::test]
    async fn slow_subscriber_drops_overflow_without_delaying_others() {
        let permits = Arc::new(Semaphore::new(0));
        let (started_tx, mut started) = mpsc::unbounded_channel();
        let mut harness = Harness::new(2, &["fast", "slow"], Some(("slow", permits.clone(), started_tx)));

        harness.send("t1").await;
        tokio::time::timeout(Duration::from_secs(5), started.recv())
            .await
            .expect("the slow sink starts delivering t1")
            .unwrap();
        assert_eq!(harness.next().await, ("fast".to_string(), "t1".to_string()));
        for trace_id in ["t2", "t3", "t4", "t5", "t6"] {
            harness.send(trace_id).await;
            assert_eq!(
                harness.next().await,
                ("fast".to_string(), trace_id.to_string()),
                "a blocked sink never delays the others"
            );
        }

        permits.add_permits(16);
        let slow = harness.collect(3).await;
        assert_eq!(slow["slow"], traces(&["t1", "t2", "t3"]), "the in-flight record plus a full queue survive");
        harness.assert_quiet().await;
    }

    #[tokio::test]
    async fn a_retired_subscriber_discards_its_queue_instead_of_delivering_it() {
        let permits = Arc::new(Semaphore::new(0));
        let (started_tx, mut started) = mpsc::unbounded_channel();
        let mut harness = Harness::new(4, &["retired", "witness"], Some(("retired", permits.clone(), started_tx)));

        harness.send("t1").await;
        tokio::time::timeout(Duration::from_secs(5), started.recv())
            .await
            .expect("the sink starts delivering t1")
            .unwrap();
        harness.send("t2").await;
        harness.send("t3").await;
        let witnessed = harness.collect(3).await;
        assert_eq!(witnessed["witness"], traces(&["t1", "t2", "t3"]), "t2 and t3 are queued for both sinks");

        harness.set_subscribers(Some(&["witness"]));
        harness.send("t4").await;
        assert_eq!(harness.next().await, ("witness".to_string(), "t4".to_string()));

        permits.add_permits(16);
        assert_eq!(harness.next().await, ("retired".to_string(), "t1".to_string()), "the in-flight record completes");
        harness.assert_quiet().await;
    }

    #[test]
    fn warn_throttle_logs_once_per_interval_and_counts_what_it_held_back() {
        let throttle = WarnThrottle::new();
        assert_eq!(throttle.record(), Some(1), "the first occurrence is logged");
        assert_eq!(throttle.record(), None);
        assert_eq!(throttle.record(), None);

        *throttle.last.lock().unwrap() = Instant::now().checked_sub(DROP_WARN_INTERVAL);
        assert_eq!(throttle.record(), Some(3), "the next WARN reports the held-back occurrences");
    }
}
