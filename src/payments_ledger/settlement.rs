//! Payments agent-pay holds until the Target has delivered: the `capture` or
//! `void` this gateway sends for them over the fabric, and the reconciler that
//! finishes what a send left open.
//!
//! The decision is written to the ledger row before it is sent, so a crash
//! leaves an intent the reconciler replays. The reconciler runs on the Active
//! node only.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};

use super::{DelegatedPaymentStore, LedgerOutcome, PaymentLedgerRow, SettleAction};
use crate::gateways::payment_case::CaseStatusError;

/// How often the reconciler looks at open rows.
const RECONCILE_EVERY: Duration = Duration::from_secs(30);
/// How many rows the reconciler works on at once.
const RECONCILE_CONCURRENCY: usize = 4;
/// How long one settle request waits when the row does not say.
const DEFAULT_WAIT: Duration = Duration::from_secs(15);
/// How long an unconfirmed row without a capture deadline is reconciled.
const UNCONFIRMED_GIVE_UP: chrono::Duration = chrono::Duration::hours(24);
/// An unconfirmed row is left alone for agent-pay's replay window, in which the
/// caller retries the same request.
const REPLAY_WINDOW: chrono::Duration = chrono::Duration::seconds(120);
const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const MAX_REASON_CHARS: usize = 256;

/// Where a held payment stands, as agent-pay answers a settle or status request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Authorized,
    Paid,
    Captured,
    Voided,
    Failed,
    Unconfirmed,
    Expired,
    Unknown,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Paid => "paid",
            Self::Captured => "captured",
            Self::Voided => "voided",
            Self::Failed => "failed",
            Self::Unconfirmed => "unconfirmed",
            Self::Expired => "expired",
            Self::Unknown => "unknown",
        }
    }
}

/// agent-pay's answer to a `payment-settle` or `payment-settlement-status` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementAnswer {
    pub status: SettlementStatus,
    pub authorization_id: Option<String>,
    /// The `Payment-Receipt` or `PAYMENT-RESPONSE` value of a capture.
    pub receipt: Option<String>,
    pub reason: Option<String>,
}

/// Reads an answer. One for another authorization than `authorization_id` is refused.
pub fn parse_answer(
    body: &Value,
    authorization_id: Option<&str>,
) -> Result<SettlementAnswer, CaseStatusError> {
    let text = |name: &str| {
        body.get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    };
    let answered = text("authorization_id");
    if let (Some(asked), Some(answered)) = (authorization_id, answered)
        && asked != answered
    {
        return Err(CaseStatusError::Rejected("the answer is for another authorization".to_string()));
    }
    let status = body
        .get("status")
        .and_then(|status| serde_json::from_value(status.clone()).ok())
        .ok_or_else(|| CaseStatusError::Rejected("the answer has no known status".to_string()))?;
    Ok(SettlementAnswer {
        status,
        authorization_id: answered.map(|value| crate::a2a::clip_for_log(value).to_string()),
        receipt: text("receipt")
            .filter(|receipt| receipt.len() <= MAX_RECEIPT_BYTES)
            .map(str::to_string),
        reason: text("reason").map(|reason| {
            reason
                .chars()
                .take(MAX_REASON_CHARS)
                .collect()
        }),
    })
}

/// What a status request asks about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettlementQuery {
    Authorization(String),
    IdempotencyKey(String),
}

impl SettlementQuery {
    fn body(&self) -> Value {
        match self {
            Self::Authorization(id) => json!({ "authorization_id": id }),
            Self::IdempotencyKey(key) => json!({ "idempotency_key": key }),
        }
    }

    fn authorization_id(&self) -> Option<&str> {
        match self {
            Self::Authorization(id) => Some(id),
            Self::IdempotencyKey(_) => None,
        }
    }
}

/// Sends settle and status requests to agent-pay.
#[async_trait::async_trait]
pub trait SettlementClient: Send + Sync {
    async fn settle(
        &self,
        payment_gateway_id: &str,
        authorization_id: &str,
        action: SettleAction,
        reason: Option<&str>,
        wait: Duration,
    ) -> Result<SettlementAnswer, CaseStatusError>;

    async fn status(
        &self,
        payment_gateway_id: &str,
        query: &SettlementQuery,
        wait: Duration,
    ) -> Result<SettlementAnswer, CaseStatusError>;
}

/// Sends them over the fabric to the connected Remote gateway.
pub struct FabricSettlement {
    gateways: Arc<crate::gateways::FileSystemGatewayStore>,
}

impl FabricSettlement {
    pub fn new(gateways: Arc<crate::gateways::FileSystemGatewayStore>) -> Self {
        Self { gateways }
    }

    async fn ask(
        &self,
        payment_gateway_id: &str,
        request: crate::messages::message_types::MessageType,
        expected: crate::messages::message_types::MessageType,
        body: Value,
        wait: Duration,
    ) -> Result<Value, CaseStatusError> {
        use crate::gateways::GatewayStore;

        let gateway = self
            .gateways
            .get(payment_gateway_id)
            .await
            .map_err(|e| CaseStatusError::Unavailable(e.to_string()))?
            .filter(|gateway| gateway.gateway_type == crate::gateways::types::GatewayType::Remote)
            .ok_or_else(|| {
                CaseStatusError::Unavailable("the payment gateway is not a connected Remote gateway".to_string())
            })?;
        let listener_manager = crate::gateways::connection_points::message_processor::get_listener_manager();
        crate::gateways::handlers::query_payment_settlement(
            listener_manager.as_deref(),
            &gateway,
            request,
            expected,
            body,
            wait,
        )
        .await
    }
}

#[async_trait::async_trait]
impl SettlementClient for FabricSettlement {
    async fn settle(
        &self,
        payment_gateway_id: &str,
        authorization_id: &str,
        action: SettleAction,
        reason: Option<&str>,
        wait: Duration,
    ) -> Result<SettlementAnswer, CaseStatusError> {
        use crate::messages::message_types::MessageType;

        let mut body = json!({ "authorization_id": authorization_id, "action": action.as_str() });
        if let Some(reason) = reason {
            body["reason"] = json!(reason);
        }
        let answer = self
            .ask(payment_gateway_id, MessageType::PaymentSettle, MessageType::PaymentSettleResponse, body, wait)
            .await?;
        parse_answer(&answer, Some(authorization_id))
    }

    async fn status(
        &self,
        payment_gateway_id: &str,
        query: &SettlementQuery,
        wait: Duration,
    ) -> Result<SettlementAnswer, CaseStatusError> {
        use crate::messages::message_types::MessageType;

        let answer = self
            .ask(
                payment_gateway_id,
                MessageType::PaymentSettlementStatus,
                MessageType::PaymentSettlementStatusResponse,
                query.body(),
                wait,
            )
            .await?;
        parse_answer(&answer, query.authorization_id())
    }
}

static CLIENT: OnceLock<Arc<dyn SettlementClient>> = OnceLock::new();

/// Sets the client the gate and the reconciler send settle requests with.
pub fn init_client(client: Arc<dyn SettlementClient>) {
    if CLIENT.set(client).is_err() {
        warn!("[payments-ledger] The settlement client was already initialised");
    }
}

#[cfg(test)]
static TEST_CLIENTS: std::sync::LazyLock<std::sync::Mutex<HashMap<String, Arc<dyn SettlementClient>>>> =
    std::sync::LazyLock::new(Default::default);

/// Routes this process's settle requests for `payment_gateway_id` to `client`.
#[cfg(test)]
pub(crate) fn install_test_client(
    payment_gateway_id: &str,
    client: Arc<dyn SettlementClient>,
) {
    TEST_CLIENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(payment_gateway_id.to_string(), client);
}

fn client_for(payment_gateway_id: &str) -> Option<Arc<dyn SettlementClient>> {
    #[cfg(test)]
    if let Some(client) = TEST_CLIENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(payment_gateway_id)
    {
        return Some(client.clone());
    }
    let _ = payment_gateway_id;
    CLIENT.get().cloned()
}

/// What a capture or void came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settled {
    pub outcome: LedgerOutcome,
    /// The capture receipt, to replace the authorization's on the response.
    pub receipt: Option<String>,
}

/// The ledger outcome an answer to `action` leads to; `None` leaves the row
/// `authorized` for the reconciler to send again.
fn outcome_after(
    action: SettleAction,
    answer: &Result<SettlementAnswer, CaseStatusError>,
) -> Option<LedgerOutcome> {
    let Ok(answer) = answer else {
        return Some(LedgerOutcome::Unconfirmed);
    };
    match answer.status {
        SettlementStatus::Captured | SettlementStatus::Paid => Some(LedgerOutcome::Paid),
        SettlementStatus::Voided | SettlementStatus::Expired => Some(LedgerOutcome::Voided),
        SettlementStatus::Failed => match action {
            SettleAction::Capture => Some(LedgerOutcome::CaptureFailed),
            SettleAction::Void => None,
        },
        SettlementStatus::Authorized => None,
        SettlementStatus::Unconfirmed | SettlementStatus::Unknown => Some(LedgerOutcome::Unconfirmed),
    }
}

/// The ledger outcome a status answer for a row whose intent is `intent`
/// leads to; `None` when the payment is still open or its state is not known.
fn outcome_of_status(
    intent: Option<SettleAction>,
    status: SettlementStatus,
) -> Option<LedgerOutcome> {
    match status {
        SettlementStatus::Captured | SettlementStatus::Paid => Some(LedgerOutcome::Paid),
        SettlementStatus::Voided | SettlementStatus::Expired => Some(LedgerOutcome::Voided),
        SettlementStatus::Failed => Some(match intent {
            Some(SettleAction::Capture) => LedgerOutcome::CaptureFailed,
            Some(SettleAction::Void) => LedgerOutcome::Voided,
            None => LedgerOutcome::Rejected,
        }),
        SettlementStatus::Authorized | SettlementStatus::Unconfirmed | SettlementStatus::Unknown => None,
    }
}

fn status_label(answer: &Result<SettlementAnswer, CaseStatusError>) -> &'static str {
    match answer {
        Ok(answer) => answer.status.as_str(),
        Err(CaseStatusError::Unavailable(_)) => "unavailable",
        Err(CaseStatusError::Rejected(_)) => "rejected",
    }
}

/// Rows of authorizations this process still holds for a request in flight,
/// which the reconciler leaves to that request until its capture deadline.
static IN_FLIGHT: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(Default::default);

fn in_flight_rows() -> std::sync::MutexGuard<'static, std::collections::HashSet<String>> {
    IN_FLIGHT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Marks a row in flight until dropped.
#[derive(Debug)]
pub struct InFlight(String);

impl InFlight {
    pub fn track(row_id: &str) -> Self {
        in_flight_rows().insert(row_id.to_string());
        Self(row_id.to_string())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        in_flight_rows().remove(&self.0);
    }
}

fn is_in_flight(row_id: &str) -> bool {
    in_flight_rows().contains(row_id)
}

/// The facts of a held payment a capture or void needs.
#[derive(Clone, Debug)]
pub struct HeldPayment {
    pub row_id: String,
    pub payment_gateway_id: String,
    pub authorization_id: String,
    pub wait: Duration,
}

/// Writes `action` to the row as its intent, sends it and records what came of
/// it. Without a ledger the action is still sent.
pub async fn settle(
    held: &HeldPayment,
    action: SettleAction,
    reason: Option<&str>,
) -> Settled {
    settle_with(super::global().as_deref(), held, action, reason).await
}

async fn settle_with(
    store: Option<&DelegatedPaymentStore>,
    held: &HeldPayment,
    action: SettleAction,
    reason: Option<&str>,
) -> Settled {
    if let Some(store) = store {
        let mut recorded = action;
        let written = store
            .update(&held.row_id, |row| {
                if row.settle_intent != Some(SettleAction::Capture) {
                    row.settle_intent = Some(action);
                }
                recorded = row
                    .settle_intent
                    .unwrap_or(action);
                row.settle_attempts = row
                    .settle_attempts
                    .saturating_add(1);
            })
            .await;
        if let Err(e) = written {
            warn!(
                error = %e,
                row_id = %held.row_id,
                "[payments-ledger] Failed to record a settle intent; the reconciler sends it"
            );
            return Settled {
                outcome: LedgerOutcome::Authorized,
                receipt: None,
            };
        }
        if recorded != action {
            warn!(
                row_id = %held.row_id,
                "[payments-ledger] A void was refused for a payment already decided to be captured"
            );
            return Settled {
                outcome: LedgerOutcome::Authorized,
                receipt: None,
            };
        }
    }
    let answer = match client_for(&held.payment_gateway_id) {
        Some(client) => {
            client
                .settle(&held.payment_gateway_id, &held.authorization_id, action, reason, held.wait)
                .await
        }
        None => Err(CaseStatusError::Unavailable("no settlement client".to_string())),
    };
    crate::metrics::backends::prometheus::track_payment_settlement(action.as_str(), status_label(&answer));
    let outcome = outcome_after(action, &answer);
    let receipt = answer
        .as_ref()
        .ok()
        .filter(|_| outcome == Some(LedgerOutcome::Paid))
        .and_then(|answer| answer.receipt.clone());
    if let Err(e) = &answer {
        warn!(
            row_id = %held.row_id,
            action = action.as_str(),
            error = %e,
            "[payments-ledger] A held payment could not be settled; the reconciler finishes it"
        );
    }
    let settle_reason = outcome.and_then(|outcome| {
        settled_reason(
            outcome,
            answer
                .as_ref()
                .ok()
                .and_then(|answer| answer.reason.as_deref())
                .or(reason),
        )
    });
    let outcome = match (store, outcome) {
        (Some(store), Some(outcome)) => apply(store, &held.row_id, outcome, receipt.as_deref(), None, settle_reason)
            .await
            .map_or(outcome, |row| row.outcome),
        (_, Some(outcome)) => outcome,
        (_, None) => LedgerOutcome::Authorized,
    };
    Settled { outcome, receipt }
}

/// The reason a row moved to `outcome` keeps: agent-pay's, else the one the
/// gateway sent with its action, for a voided payment or a failed capture only.
fn settled_reason(
    outcome: LedgerOutcome,
    given: Option<&str>,
) -> Option<String> {
    match outcome {
        LedgerOutcome::Voided => Some(super::ledger_reason(given.unwrap_or("voided"))),
        LedgerOutcome::CaptureFailed => Some(super::ledger_reason(given.unwrap_or("capture_failed"))),
        _ => None,
    }
}

/// Moves the row to `outcome` with `reason` and reports it.
async fn apply(
    store: &DelegatedPaymentStore,
    row_id: &str,
    outcome: LedgerOutcome,
    receipt: Option<&str>,
    authorization_id: Option<String>,
    reason: Option<String>,
) -> Option<PaymentLedgerRow> {
    let reference = receipt.and_then(|receipt| crate::proxy::handler::agent_pay_gate::receipt_facts(receipt).reference);
    let updated = store
        .update(row_id, |row| {
            row.outcome = outcome;
            if reference.is_some() {
                row.receipt_reference = reference;
            }
            if authorization_id.is_some() {
                row.authorization_id = authorization_id;
            }
            if reason.is_some() {
                row.reason = reason;
            }
        })
        .await;
    match updated {
        Ok(row) => {
            report(&row, None);
            Some(row)
        }
        Err(e) => {
            warn!(error = %e, row_id, "[payments-ledger] Failed to record a settled payment");
            None
        }
    }
}

/// Raises the audit event, the integration event and the log line for a row's
/// new outcome, or for the reconciler giving up on it when `gave_up` names why.
fn report(
    row: &PaymentLedgerRow,
    gave_up: Option<&str>,
) {
    use crate::delegation_vault::audit::{DelegatedPaymentFacts, PaymentEventDetails, PaymentStage};
    use crate::integrations::payment_gate_integration_triggers::{
        PaymentGateEvent, PaymentGateEventFacts, raise_payment_gate_event,
    };

    let (stage, event) = match (gave_up, row.outcome) {
        (Some(_), _) => (PaymentStage::SettlementFailed, PaymentGateEvent::ReconcileFailed),
        (None, LedgerOutcome::Paid) => (PaymentStage::Settled, PaymentGateEvent::Paid),
        (None, LedgerOutcome::Voided) => (PaymentStage::Voided, PaymentGateEvent::Voided),
        (None, LedgerOutcome::CaptureFailed) => (PaymentStage::SettlementFailed, PaymentGateEvent::CaptureFailed),
        (None, LedgerOutcome::Rejected) => (PaymentStage::Failed, PaymentGateEvent::Rejected),
        (None, _) => (PaymentStage::Unconfirmed, PaymentGateEvent::Unconfirmed),
    };
    match (gave_up, row.outcome) {
        (Some(reason), _) => warn!(
            row_id = %row.id,
            surface_id = %row.surface_id,
            reason,
            "[payments-ledger] Gave up reconciling a held payment"
        ),
        (None, LedgerOutcome::CaptureFailed) => warn!(
            row_id = %row.id,
            surface_id = %row.surface_id,
            "[payments-ledger] Capturing a delivered payment failed"
        ),
        (None, outcome) => info!(
            row_id = %row.id,
            surface_id = %row.surface_id,
            outcome = outcome.as_str(),
            "[payments-ledger] Held payment settled"
        ),
    }
    let rail = match row.rail {
        Some(super::LedgerRail::Mpp) => crate::delegation_vault::audit::PaymentRail::Mpp,
        _ => crate::delegation_vault::audit::PaymentRail::X402,
    };
    crate::delegation_vault::audit::record_payment_event(
        PaymentEventDetails {
            rail,
            stage,
            transaction_id: row.id.clone(),
            amount: row.amount.clone(),
            currency: row.currency.clone(),
            method: None,
            payer: None,
            error: gave_up
                .map(|reason| format!("reconcile_failed: {reason}"))
                .or_else(|| (row.outcome == LedgerOutcome::CaptureFailed).then(|| "capture_failed".to_string())),
            delegated: true,
            payment_gateway_id: Some(row.payment_gateway_id.clone()),
            payment_surface_id: Some(row.payment_surface_id.clone()),
            remote_status: row.remote_status,
            delegation: Some(Box::new(DelegatedPaymentFacts {
                resource: row.resource.clone(),
                variant: row.variant.clone(),
                case_id: row.case_id.clone(),
                vc_fingerprint: row.vc_fingerprint.clone(),
                idempotency_key: row.idempotency_key.clone(),
                receipt_reference: row.receipt_reference.clone(),
                authorization_id: row.authorization_id.clone(),
                ..DelegatedPaymentFacts::default()
            })),
        },
        Some(&row.surface_id),
        None,
        row.trace_id.as_deref(),
        false,
        None,
    );
    raise_payment_gate_event(
        event,
        PaymentGateEventFacts {
            surface_id: row.surface_id.clone(),
            variant: row.variant.clone(),
            payment_gateway_id: row.payment_gateway_id.clone(),
            payment_surface_id: row.payment_surface_id.clone(),
            resource: row.resource.clone(),
            rail: row.rail.map(|rail| {
                match rail {
                    super::LedgerRail::X402 => "x402",
                    super::LedgerRail::Mpp => "mpp",
                }
                .to_string()
            }),
            amount: row.amount.clone(),
            currency: row.currency.clone(),
            case_id: row.case_id.clone(),
            remote_status: row.remote_status,
            trace_id: row
                .trace_id
                .clone()
                .unwrap_or_default(),
            authorization_id: row.authorization_id.clone(),
            receipt_reference: row.receipt_reference.clone(),
            quoted_amount: row.quoted_amount.clone(),
            quoted_currency: row.quoted_currency.clone(),
            price_mismatch: row.price_mismatch,
            reason: row.reason.clone(),
        },
    );
}

fn wait_of(row: &PaymentLedgerRow) -> Duration {
    row.settle_timeout_ms
        .map_or(DEFAULT_WAIT, Duration::from_millis)
}

/// Whether the reconciler has anything to do with a row.
fn open(row: &PaymentLedgerRow) -> bool {
    super::store::awaits_settlement(row) && (row.authorization_id.is_some() || row.idempotency_key.is_some())
}

/// Checks every open row of the window once; returns how many it acted on.
pub async fn reconcile_once(
    store: &DelegatedPaymentStore,
    now: DateTime<Utc>,
) -> usize {
    let open_rows = store.rows_where(open);
    if open_rows.is_empty() {
        return 0;
    }
    let mut settled_keys: HashMap<String, String> = HashMap::new();
    for (row, _) in
        store.rows_where(|row| row.idempotency_key.is_some() && !matches!(row.outcome, LedgerOutcome::Unconfirmed))
    {
        if let Some(key) = row.idempotency_key {
            settled_keys.insert(key, row.id);
        }
    }
    let settled_keys = &settled_keys;
    futures::stream::iter(open_rows)
        .map(|(row, _)| async move { reconcile_row(store, row, settled_keys, now).await })
        .buffer_unordered(RECONCILE_CONCURRENCY)
        .filter(|acted| std::future::ready(*acted))
        .count()
        .await
}

async fn reconcile_row(
    store: &DelegatedPaymentStore,
    row: PaymentLedgerRow,
    settled_keys: &HashMap<String, String>,
    now: DateTime<Utc>,
) -> bool {
    let wait = wait_of(&row);
    if row.settle_intent.is_none()
        && is_in_flight(&row.id)
        && row
            .capture_deadline
            .is_none_or(|deadline| now <= deadline)
    {
        return false;
    }
    let last_touched = row
        .updated_at
        .unwrap_or(row.created_at);
    let busy_for = chrono::Duration::from_std(wait * 2).unwrap_or(chrono::Duration::seconds(30));
    if now - last_touched < busy_for {
        return false;
    }
    if row.authorization_id.is_none() {
        if now - row.created_at < REPLAY_WINDOW {
            return false;
        }
        if let Some(later) = row
            .idempotency_key
            .as_ref()
            .and_then(|key| settled_keys.get(key))
            .filter(|later| **later != row.id)
        {
            let later = later.clone();
            return store
                .update(&row.id, |row| row.superseded_by = Some(later))
                .await
                .is_ok();
        }
    }
    let deadline = row
        .capture_deadline
        .unwrap_or(row.created_at + UNCONFIRMED_GIVE_UP);
    let Some(client) = client_for(&row.payment_gateway_id) else {
        return false;
    };
    let held = row
        .authorization_id
        .clone()
        .map(|authorization_id| HeldPayment {
            row_id: row.id.clone(),
            payment_gateway_id: row.payment_gateway_id.clone(),
            authorization_id,
            wait,
        });
    if now <= deadline
        && row.outcome == LedgerOutcome::Authorized
        && let Some(held) = &held
    {
        let (action, reason) = match row.settle_intent {
            Some(action) => (action, None),
            None => (SettleAction::Void, Some("not_delivered")),
        };
        settle_with(Some(store), held, action, reason).await;
        return true;
    }
    let query = match &row.authorization_id {
        Some(id) => SettlementQuery::Authorization(id.clone()),
        None => match &row.idempotency_key {
            Some(key) => SettlementQuery::IdempotencyKey(key.clone()),
            None => return false,
        },
    };
    let answer = client
        .status(&row.payment_gateway_id, &query, wait)
        .await;
    crate::metrics::backends::prometheus::track_payment_settlement("status", status_label(&answer));
    if let Ok(answer) = &answer {
        if let Some(outcome) = outcome_of_status(row.settle_intent, answer.status) {
            apply(
                store,
                &row.id,
                outcome,
                answer.receipt.as_deref(),
                None,
                settled_reason(outcome, answer.reason.as_deref()),
            )
            .await;
            return true;
        }
        if answer.status == SettlementStatus::Authorized && now <= deadline {
            let authorization_id = held
                .as_ref()
                .map(|held| held.authorization_id.clone())
                .or_else(|| {
                    answer
                        .authorization_id
                        .clone()
                });
            if let Some(authorization_id) = authorization_id {
                let action = row
                    .settle_intent
                    .unwrap_or(SettleAction::Void);
                if row.authorization_id.is_none() {
                    let _ = store
                        .update(&row.id, |row| row.authorization_id = Some(authorization_id.clone()))
                        .await;
                }
                let held = HeldPayment {
                    row_id: row.id.clone(),
                    payment_gateway_id: row.payment_gateway_id.clone(),
                    authorization_id,
                    wait,
                };
                settle_with(Some(store), &held, action, None).await;
                return true;
            }
        }
    }
    if now > deadline {
        let reason = match &answer {
            Ok(answer) => format!("agent-pay still reports {}", answer.status.as_str()),
            Err(e) => e.to_string(),
        };
        crate::metrics::backends::prometheus::track_payment_settlement("reconcile", "failed");
        let kept = super::ledger_reason(&format!("reconcile_failed: {reason}"));
        if let Ok(row) = store
            .update(&row.id, |row| {
                row.reconcile_failed = true;
                row.reason = Some(kept);
            })
            .await
        {
            report(&row, Some(&reason));
        }
        return true;
    }
    false
}

/// Reconciles open rows every [`RECONCILE_EVERY`] while this node is Active.
pub fn spawn_reconciler(store: Arc<DelegatedPaymentStore>) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(RECONCILE_EVERY);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            every.tick().await;
            if crate::server::mode::is_standby() {
                continue;
            }
            let acted = reconcile_once(&store, Utc::now()).await;
            if acted > 0 {
                info!("[payments-ledger] Reconciled {acted} held or unconfirmed payment(s)");
            }
        }
    });
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::payments_ledger::tests::store;
    use std::sync::Mutex;

    /// A client that answers from a script and records what it was asked.
    #[derive(Default)]
    pub(crate) struct Scripted {
        pub settle: Mutex<Vec<Result<SettlementAnswer, CaseStatusError>>>,
        pub status: Mutex<Vec<Result<SettlementAnswer, CaseStatusError>>>,
        pub settled: Mutex<Vec<(String, SettleAction, Option<String>)>>,
        pub queried: Mutex<Vec<SettlementQuery>>,
    }

    pub(crate) fn answer(status: SettlementStatus) -> Result<SettlementAnswer, CaseStatusError> {
        Ok(SettlementAnswer {
            status,
            authorization_id: None,
            receipt: None,
            reason: None,
        })
    }

    impl Scripted {
        pub(crate) fn settling(answers: Vec<Result<SettlementAnswer, CaseStatusError>>) -> Arc<Self> {
            Arc::new(Self {
                settle: Mutex::new(answers),
                ..Self::default()
            })
        }
    }

    #[async_trait::async_trait]
    impl SettlementClient for Scripted {
        async fn settle(
            &self,
            _: &str,
            authorization_id: &str,
            action: SettleAction,
            reason: Option<&str>,
            _: Duration,
        ) -> Result<SettlementAnswer, CaseStatusError> {
            self.settled
                .lock()
                .unwrap()
                .push((authorization_id.to_string(), action, reason.map(str::to_string)));
            let mut answers = self.settle.lock().unwrap();
            if answers.is_empty() {
                return Err(CaseStatusError::Unavailable("no answer scripted".to_string()));
            }
            answers.remove(0)
        }

        async fn status(
            &self,
            _: &str,
            query: &SettlementQuery,
            _: Duration,
        ) -> Result<SettlementAnswer, CaseStatusError> {
            self.queried
                .lock()
                .unwrap()
                .push(query.clone());
            let mut answers = self.status.lock().unwrap();
            if answers.is_empty() {
                return Err(CaseStatusError::Unavailable("no answer scripted".to_string()));
            }
            answers.remove(0)
        }
    }

    fn gateway() -> String {
        format!("gw-settle-{}", uuid::Uuid::new_v4())
    }

    fn held_row(
        gateway_id: &str,
        outcome: LedgerOutcome,
        age: chrono::Duration,
    ) -> PaymentLedgerRow {
        let mut row = crate::payments_ledger::tests::row("s-1", outcome, age);
        row.payment_gateway_id = gateway_id.to_string();
        row.authorization_id = Some("auth-1".to_string());
        row.capture_deadline = Some(Utc::now() + chrono::Duration::minutes(15));
        row.settle_timeout_ms = Some(1000);
        row
    }

    #[test]
    fn an_answer_is_read_and_one_for_another_authorization_is_refused() {
        let read = parse_answer(
            &json!({"authorization_id": "auth-1", "status": "captured", "receipt": "cmVjZWlwdA", "reason": "ok"}),
            Some("auth-1"),
        )
        .unwrap();
        assert_eq!(read.status, SettlementStatus::Captured);
        assert_eq!(read.receipt.as_deref(), Some("cmVjZWlwdA"));
        assert_eq!(read.reason.as_deref(), Some("ok"));
        assert_eq!(
            read.authorization_id
                .as_deref(),
            Some("auth-1")
        );

        assert!(matches!(
            parse_answer(&json!({"authorization_id": "auth-2", "status": "captured"}), Some("auth-1")),
            Err(CaseStatusError::Rejected(_))
        ));
        assert!(matches!(parse_answer(&json!({"status": "refunded"}), None), Err(CaseStatusError::Rejected(_))));
        assert_eq!(
            parse_answer(&json!({"status": "authorized", "authorization_id": "auth-9"}), None)
                .unwrap()
                .authorization_id
                .as_deref(),
            Some("auth-9"),
            "a status query by idempotency key learns the authorization"
        );
    }

    #[test]
    fn every_answer_to_an_action_maps_to_a_ledger_outcome() {
        use SettlementStatus::*;
        for (action, status, outcome) in [
            (SettleAction::Capture, Captured, Some(LedgerOutcome::Paid)),
            (SettleAction::Capture, Failed, Some(LedgerOutcome::CaptureFailed)),
            (SettleAction::Capture, Unconfirmed, Some(LedgerOutcome::Unconfirmed)),
            (SettleAction::Capture, Voided, Some(LedgerOutcome::Voided)),
            (SettleAction::Void, Voided, Some(LedgerOutcome::Voided)),
            (SettleAction::Void, Expired, Some(LedgerOutcome::Voided)),
            (SettleAction::Void, Failed, None),
            (SettleAction::Void, Authorized, None),
            (SettleAction::Void, Unknown, Some(LedgerOutcome::Unconfirmed)),
        ] {
            assert_eq!(outcome_after(action, &answer(status)), outcome, "{action:?} {status:?}");
        }
        assert_eq!(
            outcome_after(SettleAction::Capture, &Err(CaseStatusError::Unavailable("timeout".to_string()))),
            Some(LedgerOutcome::Unconfirmed)
        );
    }

    #[tokio::test]
    async fn a_capture_writes_its_intent_first_and_records_the_capture_receipt() {
        let (store, dir) = store().await;
        let gateway_id = gateway();
        let client = Scripted::settling(vec![Ok(SettlementAnswer {
            status: SettlementStatus::Captured,
            authorization_id: Some("auth-1".to_string()),
            receipt: Some("eyJyZWZlcmVuY2UiOiJwaV8xIn0".to_string()),
            reason: None,
        })]);
        install_test_client(&gateway_id, client.clone());
        let row = held_row(&gateway_id, LedgerOutcome::Authorized, chrono::Duration::zero());
        store
            .record_durable(row.clone(), None)
            .await
            .unwrap();
        let held = HeldPayment {
            row_id: row.id.clone(),
            payment_gateway_id: gateway_id,
            authorization_id: "auth-1".to_string(),
            wait: Duration::from_secs(1),
        };

        let settled = settle_with(Some(&store), &held, SettleAction::Capture, None).await;

        assert_eq!(settled.outcome, LedgerOutcome::Paid);
        assert_eq!(settled.receipt.as_deref(), Some("eyJyZWZlcmVuY2UiOiJwaV8xIn0"));
        let (recorded, _) = store
            .get(&row.id)
            .await
            .unwrap();
        assert_eq!(recorded.outcome, LedgerOutcome::Paid);
        assert_eq!(recorded.settle_intent, Some(SettleAction::Capture));
        assert_eq!(recorded.settle_attempts, 1);
        assert_eq!(
            recorded
                .receipt_reference
                .as_deref(),
            Some("pi_1")
        );
        assert_eq!(
            client
                .settled
                .lock()
                .unwrap()
                .clone(),
            vec![("auth-1".to_string(), SettleAction::Capture, None)]
        );
        let reopened = DelegatedPaymentStore::new(dir.clone())
            .await
            .unwrap();
        assert_eq!(
            reopened
                .get(&row.id)
                .await
                .map(|(row, _)| row.outcome),
            Some(LedgerOutcome::Paid),
            "the last version of the row is what a restart loads"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_failed_capture_is_capture_failed_and_an_unanswered_one_unconfirmed() {
        let (store, dir) = store().await;
        let gateway_id = gateway();
        install_test_client(
            &gateway_id,
            Scripted::settling(vec![
                answer(SettlementStatus::Failed),
                Err(CaseStatusError::Unavailable("no answer".to_string())),
            ]),
        );
        for (expected, reason) in
            [(LedgerOutcome::CaptureFailed, Some("capture_failed")), (LedgerOutcome::Unconfirmed, None)]
        {
            let row = held_row(&gateway_id, LedgerOutcome::Authorized, chrono::Duration::zero());
            store
                .record_durable(row.clone(), None)
                .await
                .unwrap();
            let held = HeldPayment {
                row_id: row.id.clone(),
                payment_gateway_id: gateway_id.clone(),
                authorization_id: "auth-1".to_string(),
                wait: Duration::from_secs(1),
            };
            let settled = settle_with(Some(&store), &held, SettleAction::Capture, None).await;
            assert_eq!(
                settled,
                Settled {
                    outcome: expected,
                    receipt: None
                }
            );
            let stored = store
                .get(&row.id)
                .await
                .unwrap()
                .0;
            assert_eq!(stored.outcome, expected);
            assert_eq!(stored.reason.as_deref(), reason, "{expected:?}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_action_agent_pay_could_not_record_keeps_its_intent_and_is_resent() {
        for action in [SettleAction::Capture, SettleAction::Void] {
            let (store, dir) = store().await;
            let gateway_id = gateway();
            let unrecorded = || {
                Ok(SettlementAnswer {
                    status: SettlementStatus::Authorized,
                    authorization_id: Some("auth-1".to_string()),
                    receipt: None,
                    reason: Some("store_unavailable".to_string()),
                })
            };
            let client = Scripted::settling(vec![unrecorded(), unrecorded()]);
            install_test_client(&gateway_id, client.clone());
            let row = held_row(&gateway_id, LedgerOutcome::Authorized, chrono::Duration::zero());
            store
                .record_durable(row.clone(), None)
                .await
                .unwrap();
            let held = HeldPayment {
                row_id: row.id.clone(),
                payment_gateway_id: gateway_id.clone(),
                authorization_id: "auth-1".to_string(),
                wait: Duration::from_secs(1),
            };

            let settled = settle_with(Some(&store), &held, action, None).await;
            assert_eq!(settled.outcome, LedgerOutcome::Authorized, "{action:?}");
            let recorded = store
                .get(&row.id)
                .await
                .unwrap()
                .0;
            assert_eq!((recorded.outcome, recorded.settle_intent), (LedgerOutcome::Authorized, Some(action)));

            let later = Utc::now() + chrono::Duration::seconds(10);
            assert_eq!(reconcile_once(&store, later).await, 1);
            assert_eq!(
                client
                    .settled
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(_, sent, _)| *sent)
                    .collect::<Vec<_>>(),
                vec![action, action],
                "the reconciler resends the same action"
            );
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[tokio::test]
    async fn a_void_never_overrides_a_capture_intent_and_an_unwritten_intent_is_not_sent() {
        let (store, dir) = store().await;
        let gateway_id = gateway();
        let client = Scripted::settling(vec![answer(SettlementStatus::Voided)]);
        install_test_client(&gateway_id, client.clone());
        let mut row = held_row(&gateway_id, LedgerOutcome::Authorized, chrono::Duration::zero());
        row.settle_intent = Some(SettleAction::Capture);
        store
            .record_durable(row.clone(), None)
            .await
            .unwrap();
        let held = |row_id: &str| HeldPayment {
            row_id: row_id.to_string(),
            payment_gateway_id: gateway_id.clone(),
            authorization_id: "auth-1".to_string(),
            wait: Duration::from_secs(1),
        };

        let settled = settle_with(Some(&store), &held(&row.id), SettleAction::Void, None).await;
        assert_eq!(settled.outcome, LedgerOutcome::Authorized);
        assert_eq!(
            store
                .get(&row.id)
                .await
                .unwrap()
                .0
                .settle_intent,
            Some(SettleAction::Capture)
        );

        let unwritten = settle_with(Some(&store), &held("no-such-row"), SettleAction::Capture, None).await;
        assert_eq!(unwritten.outcome, LedgerOutcome::Authorized);
        assert!(
            client
                .settled
                .lock()
                .unwrap()
                .is_empty(),
            "nothing is sent without a written intent"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_reconciler_leaves_an_undecided_row_in_flight_until_its_capture_deadline() {
        let (store, dir) = store().await;
        let gateway_id = gateway();
        let client = Scripted::settling(vec![answer(SettlementStatus::Voided)]);
        install_test_client(&gateway_id, client.clone());
        let row = held_row(&gateway_id, LedgerOutcome::Authorized, chrono::Duration::minutes(5));
        store
            .record_durable(row.clone(), None)
            .await
            .unwrap();
        let in_flight = InFlight::track(&row.id);

        assert_eq!(reconcile_once(&store, Utc::now()).await, 0, "a long request in flight is not voided");
        assert!(
            client
                .settled
                .lock()
                .unwrap()
                .is_empty()
        );

        drop(in_flight);
        assert_eq!(reconcile_once(&store, Utc::now()).await, 1);
        assert_eq!(
            client
                .settled
                .lock()
                .unwrap()
                .iter()
                .map(|(_, action, _)| *action)
                .collect::<Vec<_>>(),
            vec![SettleAction::Void]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_reconciler_replays_an_intent_and_voids_an_undecided_stale_authorization() {
        let (store, dir) = store().await;
        let gateway_id = gateway();
        let client = Scripted::settling(vec![answer(SettlementStatus::Captured), answer(SettlementStatus::Voided)]);
        install_test_client(&gateway_id, client.clone());
        let mut with_intent = held_row(&gateway_id, LedgerOutcome::Authorized, chrono::Duration::seconds(10));
        with_intent.settle_intent = Some(SettleAction::Capture);
        let undecided = held_row(&gateway_id, LedgerOutcome::Authorized, chrono::Duration::seconds(5));
        let fresh = held_row(&gateway_id, LedgerOutcome::Authorized, chrono::Duration::zero());
        for row in [&with_intent, &undecided, &fresh] {
            store
                .record_durable(row.clone(), None)
                .await
                .unwrap();
        }

        let acted = reconcile_once(&store, Utc::now()).await;

        assert_eq!(acted, 2, "the fresh row is still in flight");
        assert_eq!(
            store
                .get(&with_intent.id)
                .await
                .unwrap()
                .0
                .outcome,
            LedgerOutcome::Paid
        );
        let voided = store
            .get(&undecided.id)
            .await
            .unwrap()
            .0;
        assert_eq!(voided.outcome, LedgerOutcome::Voided);
        assert_eq!(voided.reason.as_deref(), Some("not_delivered"));
        assert_eq!(voided.settle_intent, Some(SettleAction::Void));
        assert_eq!(
            store
                .get(&fresh.id)
                .await
                .unwrap()
                .0
                .outcome,
            LedgerOutcome::Authorized
        );
        let mut sent = client
            .settled
            .lock()
            .unwrap()
            .clone();
        sent.sort_by_key(|(_, action, _)| action.as_str());
        assert_eq!(
            sent,
            vec![
                ("auth-1".to_string(), SettleAction::Capture, None),
                ("auth-1".to_string(), SettleAction::Void, Some("not_delivered".to_string())),
            ]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_reconciler_settles_an_unconfirmed_row_from_its_status() {
        let (store, dir) = store().await;
        let gateway_id = gateway();
        let client = Arc::new(Scripted {
            status: Mutex::new(vec![answer(SettlementStatus::Captured)]),
            ..Scripted::default()
        });
        install_test_client(&gateway_id, client.clone());
        let mut row = held_row(&gateway_id, LedgerOutcome::Unconfirmed, chrono::Duration::seconds(10));
        row.settle_intent = Some(SettleAction::Capture);
        store
            .record_durable(row.clone(), None)
            .await
            .unwrap();

        assert_eq!(reconcile_once(&store, Utc::now()).await, 1);

        assert_eq!(
            store
                .get(&row.id)
                .await
                .unwrap()
                .0
                .outcome,
            LedgerOutcome::Paid
        );
        assert_eq!(
            client
                .queried
                .lock()
                .unwrap()
                .clone(),
            vec![SettlementQuery::Authorization("auth-1".to_string())]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_reconciler_gives_up_after_the_deadline_and_marks_the_row() {
        let (store, dir) = store().await;
        let gateway_id = gateway();
        install_test_client(
            &gateway_id,
            Arc::new(Scripted {
                status: Mutex::new(vec![answer(SettlementStatus::Unknown)]),
                ..Scripted::default()
            }),
        );
        let mut row = held_row(&gateway_id, LedgerOutcome::Unconfirmed, chrono::Duration::minutes(30));
        row.capture_deadline = Some(Utc::now() - chrono::Duration::minutes(1));
        store
            .record_durable(row.clone(), None)
            .await
            .unwrap();

        assert_eq!(reconcile_once(&store, Utc::now()).await, 1);
        let given_up = store
            .get(&row.id)
            .await
            .unwrap()
            .0;
        assert!(given_up.reconcile_failed);
        assert_eq!(given_up.outcome, LedgerOutcome::Unconfirmed);
        assert_eq!(reconcile_once(&store, Utc::now()).await, 0, "a row given up on is left alone");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_unconfirmed_row_a_retry_settled_is_superseded_and_not_queried() {
        let (store, dir) = store().await;
        let gateway_id = gateway();
        let client = Arc::new(Scripted::default());
        install_test_client(&gateway_id, client.clone());
        let mut first =
            crate::payments_ledger::tests::row("s-1", LedgerOutcome::Unconfirmed, chrono::Duration::minutes(5));
        first.payment_gateway_id = gateway_id.clone();
        first.idempotency_key = Some("key-1".to_string());
        let mut retry = crate::payments_ledger::tests::row("s-1", LedgerOutcome::Paid, chrono::Duration::minutes(4));
        retry.payment_gateway_id = gateway_id;
        retry.idempotency_key = Some("key-1".to_string());
        for row in [&first, &retry] {
            store
                .record_durable(row.clone(), None)
                .await
                .unwrap();
        }

        assert_eq!(reconcile_once(&store, Utc::now()).await, 1);
        assert_eq!(
            store
                .get(&first.id)
                .await
                .unwrap()
                .0
                .superseded_by,
            Some(retry.id.clone())
        );
        assert!(
            client
                .queried
                .lock()
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
