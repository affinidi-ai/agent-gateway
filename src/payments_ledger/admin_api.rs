use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::case_status::CaseStatus;
use super::{
    CaseStatusLookup, DEFAULT_LIST_LIMIT, DelegatedPaymentStore, LedgerFilter, LedgerOutcome, MAX_LIST_LIMIT,
    PaymentLedgerRow,
};
use crate::auth_manager::pat::PatResourceScope;
use crate::delegation_vault::audit::{DelegationAuditAction, DelegationAuditEvent, PaymentStage};
use crate::identity::handlers::surfaces::surface_visible;
use crate::tenancy::PatTenantContext;

#[derive(Clone)]
pub struct PaymentsLedgerApiState {
    pub store: Option<Arc<DelegatedPaymentStore>>,
    /// Asks the payment gateway where a held payment stands. Without it a held
    /// payment's detail carries no `case_status`.
    pub case_status: Option<Arc<CaseStatusLookup>>,
}

#[derive(Deserialize)]
struct ListPaymentsQuery {
    surface_id: Option<String>,
    outcome: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct ListPaymentsResponse {
    payments: Vec<PaymentDetail>,
    total: usize,
}

/// A row, with where its held payment stands when that could be had.
#[derive(Serialize)]
struct PaymentDetail {
    #[serde(flatten)]
    row: PaymentLedgerRow,
    #[serde(skip_serializing_if = "Option::is_none")]
    case_status: Option<CaseStatus>,
}

fn error(
    status: StatusCode,
    message: &str,
) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.is_empty())
}

fn parse_outcome(value: Option<String>) -> Result<Option<LedgerOutcome>, serde_json::Error> {
    non_empty(value)
        .map(|v| serde_json::from_value(serde_json::Value::String(v)))
        .transpose()
}

/// Whether the caller may read a payment row: a tenant caller only the rows of
/// its own tenant's surfaces, since a row carries what the payer paid for and
/// the transaction behind it, which the surfaces of an operator or another
/// tenant keep from it. An operator caller sees every row. A resource scope
/// narrows either.
fn caller_can_see(
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> impl Fn(Option<&str>, &str) -> bool {
    let context = context
        .as_ref()
        .map(|Extension(context)| context.clone());
    let scope = scope
        .as_ref()
        .map(|Extension(scope)| scope.clone());
    move |tenant_id, surface_id| {
        context
            .as_ref()
            .is_none_or(|context| tenant_id == Some(context.tenant_id.as_str()))
            && surface_visible(tenant_id, surface_id, context.as_ref(), scope.as_ref())
    }
}

async fn list_payments(
    State(state): State<PaymentsLedgerApiState>,
    Query(query): Query<ListPaymentsQuery>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Response {
    let outcome = match parse_outcome(query.outcome) {
        Ok(outcome) => outcome,
        Err(_) => {
            return error(
                StatusCode::BAD_REQUEST,
                "outcome must be paid, challenge, held, rejected, unconfirmed, unavailable, authorized, voided or \
                 capture_failed",
            );
        }
    };
    let filter = LedgerFilter {
        surface_id: non_empty(query.surface_id),
        outcome,
        limit: query
            .limit
            .unwrap_or(DEFAULT_LIST_LIMIT)
            .min(MAX_LIST_LIMIT),
    };
    let (rows, total) = match state.store {
        Some(store) => store.list(&filter, caller_can_see(&context, &scope)),
        None => (Vec::new(), 0),
    };
    let mut payments = Vec::with_capacity(rows.len());
    for row in rows {
        let case_status = match (&state.case_status, row.outcome, row.case_id.as_deref()) {
            (Some(lookup), LedgerOutcome::Held, Some(case_id)) => {
                lookup
                    .cached(&row.payment_gateway_id, case_id)
                    .await
            }
            _ => None,
        };
        payments.push(PaymentDetail { row, case_status });
    }
    Json(ListPaymentsResponse { payments, total }).into_response()
}

async fn get_payment(
    State(state): State<PaymentsLedgerApiState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Response {
    let found = match state.store {
        Some(store) => store.get(&id).await,
        None => None,
    };
    match found {
        Some((row, tenant_id)) if caller_can_see(&context, &scope)(tenant_id.as_deref(), &row.surface_id) => {
            let case_status = match (&state.case_status, row.outcome, row.case_id.as_deref()) {
                (Some(lookup), LedgerOutcome::Held, Some(case_id)) => {
                    lookup
                        .check(&row.payment_gateway_id, case_id)
                        .await
                }
                _ => None,
            };
            Json(PaymentDetail { row, case_status }).into_response()
        }
        _ => error(StatusCode::NOT_FOUND, "Payment not found"),
    }
}

pub const DEFAULT_AUDIT_PAGE_SIZE: usize = 50;
pub const MAX_AUDIT_PAGE_SIZE: usize = 500;
const DEFAULT_SUMMARY_HOURS: i64 = 24;
const MAX_SUMMARY_HOURS: i64 = 24 * 400;

#[derive(Deserialize)]
struct PaymentAuditQuery {
    surface_id: Option<String>,
    stage: Option<String>,
    trace_id: Option<String>,
    since: Option<String>,
    until: Option<String>,
    page: Option<usize>,
    page_size: Option<usize>,
}

#[derive(Serialize)]
struct PaymentAuditPage {
    events: Vec<DelegationAuditEvent>,
    total: usize,
    page: usize,
    page_size: usize,
    total_pages: usize,
}

/// What a caller asked of the payment audit trail, checked.
struct AuditFilter {
    surface_id: Option<String>,
    stage: Option<PaymentStage>,
    trace_id: Option<String>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
}

fn parse_time(
    value: Option<String>,
    name: &str,
) -> Result<Option<DateTime<Utc>>, String> {
    non_empty(value)
        .map(|v| {
            DateTime::parse_from_rfc3339(&v)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| format!("{name} must be an RFC 3339 time"))
        })
        .transpose()
}

impl AuditFilter {
    fn parse(query: &PaymentAuditQuery) -> Result<Self, String> {
        let stage = non_empty(query.stage.clone())
            .map(|v| serde_json::from_value(serde_json::Value::String(v)))
            .transpose()
            .map_err(|_| {
                "stage must be challenge_issued, verify_attempt, verified, failed, held, unconfirmed, authorized, \
                 voided, settled or settlement_failed"
                    .to_string()
            })?;
        Ok(Self {
            surface_id: non_empty(query.surface_id.clone()),
            stage,
            trace_id: non_empty(query.trace_id.clone()),
            since: parse_time(query.since.clone(), "since")?,
            until: parse_time(query.until.clone(), "until")?,
        })
    }

    fn matches(
        &self,
        event: &DelegationAuditEvent,
    ) -> bool {
        let DelegationAuditAction::PaymentEvent(details) = &event.event else {
            return false;
        };
        let at = || {
            DateTime::parse_from_rfc3339(&event.timestamp)
                .ok()
                .map(|t| t.with_timezone(&Utc))
        };
        self.surface_id
            .as_deref()
            .is_none_or(|surface_id| event.surface_id.as_deref() == Some(surface_id))
            && self
                .stage
                .is_none_or(|stage| details.stage == stage)
            && self
                .trace_id
                .as_deref()
                .is_none_or(|trace_id| event.trace_id.as_deref() == Some(trace_id))
            && self
                .since
                .is_none_or(|since| at().is_some_and(|at| at >= since))
            && self
                .until
                .is_none_or(|until| at().is_some_and(|at| at <= until))
    }
}

/// One page of `events` (newest first) that `filter` and `visible` admit. A
/// payment record leaves here with its credential fingerprint, never the
/// credential itself.
fn audit_page(
    events: Vec<DelegationAuditEvent>,
    filter: &AuditFilter,
    visible: impl Fn(&DelegationAuditEvent) -> bool,
    page: usize,
    page_size: usize,
) -> PaymentAuditPage {
    let mut kept: Vec<DelegationAuditEvent> = events
        .into_iter()
        .filter(|event| filter.matches(event) && visible(event))
        .collect();
    let total = kept.len();
    let total_pages = total
        .div_ceil(page_size)
        .max(1);
    let page = page.clamp(1, total_pages);
    let events = kept
        .drain(((page - 1) * page_size).min(total)..)
        .take(page_size)
        .map(|mut event| {
            event.vp_jwt = None;
            event
        })
        .collect();
    PaymentAuditPage {
        events,
        total,
        page,
        page_size,
        total_pages,
    }
}

/// Recent `payment` records from the VP Audit Log. A tenant caller sees only the
/// records of surfaces whose ledger rows it may see; a record whose surface has
/// no row in the ledger window is shown to operator callers only.
async fn list_payment_audit(
    State(state): State<PaymentsLedgerApiState>,
    Query(query): Query<PaymentAuditQuery>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Response {
    let filter = match AuditFilter::parse(&query) {
        Ok(filter) => filter,
        Err(message) => return error(StatusCode::BAD_REQUEST, &message),
    };
    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_AUDIT_PAGE_SIZE)
        .clamp(1, MAX_AUDIT_PAGE_SIZE);
    let tenants = state
        .store
        .as_ref()
        .map(|store| store.surface_tenants())
        .unwrap_or_default();
    let restricted = context.is_some() || scope.is_some();
    let can_see = caller_can_see(&context, &scope);
    let visible = |event: &DelegationAuditEvent| match event.surface_id.as_deref() {
        Some(surface_id) => match tenants.get(surface_id) {
            Some(tenant_id) => can_see(tenant_id.as_deref(), surface_id),
            None => context.is_none() && can_see(None, surface_id),
        },
        None => !restricted,
    };
    let events = crate::delegation_vault::audit::read_payment_events().await;
    Json(audit_page(events, &filter, visible, query.page.unwrap_or(1), page_size)).into_response()
}

#[derive(Deserialize)]
struct SummaryQuery {
    surface_id: Option<String>,
    hours: Option<i64>,
}

#[derive(Serialize)]
struct PaymentSummary {
    since: DateTime<Utc>,
    total: usize,
    counts: std::collections::BTreeMap<LedgerOutcome, usize>,
}

/// Rows in the ledger window from the last `hours` (default 24), by outcome.
async fn payment_summary(
    State(state): State<PaymentsLedgerApiState>,
    Query(query): Query<SummaryQuery>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Response {
    let hours = query
        .hours
        .unwrap_or(DEFAULT_SUMMARY_HOURS)
        .clamp(1, MAX_SUMMARY_HOURS);
    let since = Utc::now() - chrono::Duration::hours(hours);
    let surface_id = non_empty(query.surface_id);
    let can_see = caller_can_see(&context, &scope);
    let counts = match state.store {
        Some(store) => store.count_by_outcome(|row, tenant_id| {
            row.created_at >= since
                && surface_id
                    .as_deref()
                    .is_none_or(|surface_id| row.surface_id == surface_id)
                && can_see(tenant_id, &row.surface_id)
        }),
        None => Default::default(),
    };
    Json(PaymentSummary {
        since,
        total: counts.values().sum(),
        counts,
    })
    .into_response()
}

#[derive(Serialize)]
struct BreakerView {
    payment_gateway_id: String,
    #[serde(flatten)]
    breaker: crate::proxy::handler::agent_pay_gate::BreakerSnapshot,
}

/// Where a payment gateway's circuit breaker stands. A tenant caller or a
/// resource-scoped token may read it only for a gateway one of its visible
/// ledger rows names.
async fn get_breaker(
    State(state): State<PaymentsLedgerApiState>,
    Path(payment_gateway_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Response {
    if context.is_some() || scope.is_some() {
        let can_see = caller_can_see(&context, &scope);
        let named = state
            .store
            .as_ref()
            .is_some_and(|store| {
                store.any_row(|row, tenant_id| {
                    row.payment_gateway_id == payment_gateway_id && can_see(tenant_id, &row.surface_id)
                })
            });
        if !named {
            return error(StatusCode::NOT_FOUND, "Payment gateway not found");
        }
    }
    let breaker =
        crate::proxy::handler::agent_pay_gate::breaker_snapshot(&payment_gateway_id, std::time::Instant::now());
    Json(BreakerView { payment_gateway_id, breaker }).into_response()
}

/// `GET /payments`, `/payments/{id}`, `/payments/audit`, `/payments/summary`
/// and `/payments/breakers/{payment_gateway_id}`; mounted under `/api/admin`
/// behind `payments.view`.
pub fn create_payments_ledger_router(state: PaymentsLedgerApiState) -> Router {
    Router::new()
        .route("/payments", get(list_payments))
        .route("/payments/audit", get(list_payment_audit))
        .route("/payments/summary", get(payment_summary))
        .route("/payments/breakers/{payment_gateway_id}", get(get_breaker))
        .route("/payments/{id}", get(get_payment))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments_ledger::LedgerRail;
    use crate::payments_ledger::tests::{row, store};
    use axum::body::Body;
    use axum::http::Request;
    use chrono::Duration;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn tenant(id: &str) -> PatTenantContext {
        PatTenantContext {
            token_id: "agat_test".to_string(),
            tenant_id: id.to_string(),
        }
    }

    async fn call(
        router: Router,
        uri: &str,
        context: Option<PatTenantContext>,
        scope: Option<PatResourceScope>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        if let Some(context) = context {
            request
                .extensions_mut()
                .insert(context);
        }
        if let Some(scope) = scope {
            request
                .extensions_mut()
                .insert(scope);
        }
        let response = router
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn router_with(rows: Vec<(PaymentLedgerRow, Option<&str>)>) -> (Router, std::path::PathBuf) {
        let (store, dir) = store().await;
        for (row, tenant_id) in rows {
            store
                .record(row, tenant_id.map(str::to_string))
                .unwrap();
        }
        let router = create_payments_ledger_router(PaymentsLedgerApiState {
            store: Some(Arc::new(store)),
            case_status: None,
        });
        (router, dir)
    }

    fn keys(value: &serde_json::Value) -> Vec<&str> {
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    #[tokio::test]
    async fn the_list_returns_payments_and_total_with_exact_row_keys() {
        let mut paid = row("s-1", LedgerOutcome::Paid, Duration::minutes(1));
        paid.rail = Some(LedgerRail::X402);
        paid.amount = Some("1.00".to_string());
        let challenge = row("s-1", LedgerOutcome::Challenge, Duration::zero());
        let (router, dir) = router_with(vec![(paid.clone(), Some("tenant-a")), (challenge.clone(), None)]).await;

        let (status, body) = call(router.clone(), "/payments", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(keys(&body), vec!["payments", "total"]);
        assert_eq!(body["total"], 2);
        assert_eq!(body["payments"][0]["id"], challenge.id);
        assert_eq!(
            keys(&body["payments"][0]),
            vec!["created_at", "id", "latency_ms", "outcome", "payment_gateway_id", "payment_surface_id", "surface_id"]
        );
        assert_eq!(body["payments"][0]["outcome"], "challenge");
        assert_eq!(body["payments"][1]["rail"], "x402");
        assert_eq!(body["payments"][1]["amount"], "1.00");
        assert!(
            body["payments"][1]
                .get("tenant_id")
                .is_none()
        );

        let (status, body) = call(router.clone(), &format!("/payments/{}", paid.id), None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_value::<PaymentLedgerRow>(body.clone()).unwrap(), paid);
        assert!(
            body.get("tenant_id")
                .is_none()
        );

        let (status, body) = call(router, "/payments?outcome=paid&surface_id=s-1&limit=5", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        assert_eq!(body["payments"][0]["id"], paid.id);
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn the_unconfirmed_outcome_can_be_listed_and_filtered() {
        let unconfirmed = row("s-1", LedgerOutcome::Unconfirmed, Duration::minutes(1));
        let paid = row("s-1", LedgerOutcome::Paid, Duration::zero());
        let (router, dir) = router_with(vec![(unconfirmed.clone(), None), (paid, None)]).await;
        let (status, body) = call(router, "/payments?outcome=unconfirmed", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        assert_eq!(body["payments"][0]["id"], unconfirmed.id);
        assert_eq!(body["payments"][0]["outcome"], "unconfirmed");
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn an_unknown_outcome_is_a_bad_request() {
        let (router, dir) = router_with(vec![]).await;
        let (status, body) = call(router.clone(), "/payments?outcome=settled", None, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("outcome")
        );

        let (status, body) = call(router, "/payments?outcome=", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 0);
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn the_limit_caps_payments_but_not_total() {
        let rows = (0..3)
            .map(|i| (row("s-1", LedgerOutcome::Paid, Duration::minutes(i)), None))
            .collect();
        let (router, dir) = router_with(rows).await;
        let (status, body) = call(router, "/payments?limit=2", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["payments"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(body["total"], 3);
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_tenant_caller_sees_only_the_rows_of_its_own_tenant() {
        let own = row("s-a", LedgerOutcome::Paid, Duration::minutes(2));
        let operator = row("s-op", LedgerOutcome::Held, Duration::minutes(1));
        let foreign = row("s-b", LedgerOutcome::Paid, Duration::zero());
        let (router, dir) = router_with(vec![
            (own.clone(), Some("tenant-a")),
            (operator.clone(), None),
            (foreign.clone(), Some("tenant-b")),
        ])
        .await;

        let (status, body) = call(router.clone(), "/payments", Some(tenant("tenant-a")), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        let listed: Vec<&str> = body["payments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(listed, vec![own.id.as_str()]);

        let (status, _) = call(router.clone(), &format!("/payments/{}", own.id), Some(tenant("tenant-a")), None).await;
        assert_eq!(status, StatusCode::OK);
        for hidden in [&foreign, &operator] {
            let (status, body) =
                call(router.clone(), &format!("/payments/{}", hidden.id), Some(tenant("tenant-a")), None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{}", hidden.surface_id);
            assert_eq!(body["error"], "Payment not found");
        }

        let (status, body) = call(router, "/payments", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 3, "an operator caller sees every row");
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_resource_scoped_token_sees_only_rows_of_surfaces_in_scope() {
        let in_scope = row("s-1", LedgerOutcome::Paid, Duration::zero());
        let out_of_scope = row("s-2", LedgerOutcome::Paid, Duration::zero());
        let (router, dir) = router_with(vec![(in_scope.clone(), None), (out_of_scope.clone(), None)]).await;
        let scope = || Some(PatResourceScope(Arc::new(regex::Regex::new("^s-1$").unwrap())));

        let (status, body) = call(router.clone(), "/payments", None, scope()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 1);
        assert_eq!(body["payments"][0]["id"], in_scope.id);
        let (status, _) = call(router, &format!("/payments/{}", out_of_scope.id), None, scope()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    fn payment_event(
        surface_id: Option<&str>,
        stage: PaymentStage,
        trace_id: &str,
        timestamp: &str,
    ) -> DelegationAuditEvent {
        use crate::delegation_vault::audit::{PaymentEventDetails, PaymentRail, audit_event};
        let mut event = audit_event(
            DelegationAuditAction::PaymentEvent(Box::new(PaymentEventDetails {
                rail: PaymentRail::Mpp,
                stage,
                transaction_id: format!("row-{trace_id}"),
                amount: None,
                currency: None,
                method: None,
                payer: None,
                error: None,
                delegated: true,
                payment_gateway_id: Some("gw-pay".to_string()),
                payment_surface_id: Some("ps-1".to_string()),
                remote_status: None,
                delegation: None,
            })),
            None,
            None,
            None,
            surface_id,
        );
        event.trace_id = Some(trace_id.to_string());
        event.timestamp = timestamp.to_string();
        event.vp_jwt = Some("eyJ.grant.sig".to_string());
        event.vp_fingerprint = Some(format!("sha256:{trace_id}"));
        event
    }

    fn audit_query(pairs: &[(&str, &str)]) -> PaymentAuditQuery {
        let value: serde_json::Map<String, serde_json::Value> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        serde_json::from_value(serde_json::Value::Object(value)).unwrap()
    }

    fn traces(page: &PaymentAuditPage) -> Vec<&str> {
        page.events
            .iter()
            .map(|event| {
                event
                    .trace_id
                    .as_deref()
                    .unwrap()
            })
            .collect()
    }

    fn sample_events() -> Vec<DelegationAuditEvent> {
        vec![
            payment_event(Some("s-1"), PaymentStage::Failed, "t-3", "2026-10-26T12:00:00Z"),
            payment_event(Some("s-2"), PaymentStage::Verified, "t-2", "2026-10-26T11:00:00Z"),
            payment_event(Some("s-1"), PaymentStage::Verified, "t-1", "2026-10-26T10:00:00Z"),
            payment_event(None, PaymentStage::Failed, "t-0", "2026-10-26T09:00:00Z"),
        ]
    }

    #[test]
    fn the_audit_trail_filters_by_surface_stage_trace_and_time_and_pages_newest_first() {
        let all = |_: &DelegationAuditEvent| true;
        let page = |pairs: &[(&str, &str)], page: usize, size: usize| {
            audit_page(sample_events(), &AuditFilter::parse(&audit_query(pairs)).unwrap(), all, page, size)
        };

        let everything = page(&[], 1, 50);
        assert_eq!(traces(&everything), vec!["t-3", "t-2", "t-1", "t-0"]);
        assert_eq!((everything.total, everything.total_pages), (4, 1));
        assert!(
            everything
                .events
                .iter()
                .all(|event| event.vp_jwt.is_none()),
            "the credential never leaves"
        );
        assert_eq!(
            everything.events[0]
                .vp_fingerprint
                .as_deref(),
            Some("sha256:t-3")
        );

        assert_eq!(traces(&page(&[("surface_id", "s-1")], 1, 50)), vec!["t-3", "t-1"]);
        assert_eq!(traces(&page(&[("stage", "verified")], 1, 50)), vec!["t-2", "t-1"]);
        assert_eq!(traces(&page(&[("trace_id", "t-2")], 1, 50)), vec!["t-2"]);
        assert_eq!(
            traces(&page(&[("since", "2026-10-26T10:00:00Z"), ("until", "2026-10-26T11:30:00+00:00")], 1, 50)),
            vec!["t-2", "t-1"]
        );
        assert!(
            page(&[("trace_id", "nope")], 1, 50)
                .events
                .is_empty()
        );

        let second = page(&[], 2, 3);
        assert_eq!(traces(&second), vec!["t-0"]);
        assert_eq!((second.page, second.page_size, second.total_pages, second.total), (2, 3, 2, 4));
        assert_eq!(page(&[], 9, 3).page, 2, "a page past the end is the last page");
    }

    #[test]
    fn a_bad_audit_filter_is_refused_with_what_was_wrong() {
        for (pairs, wanted) in [
            (vec![("stage", "paid")], "stage"),
            (vec![("since", "yesterday")], "since"),
            (vec![("until", "2026-13-01")], "until"),
        ] {
            let message = AuditFilter::parse(&audit_query(&pairs))
                .err()
                .unwrap();
            assert!(message.starts_with(wanted), "{message}");
        }
        assert!(
            AuditFilter::parse(&audit_query(&[("stage", "")]))
                .unwrap()
                .stage
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_audit_endpoint_refuses_a_bad_filter() {
        let (router, dir) = router_with(vec![]).await;
        let (status, body) = call(router.clone(), "/payments/audit?stage=paid", None, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("stage")
        );
        let (status, body) = call(router, "/payments/audit", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(keys(&body), vec!["events", "page", "page_size", "total", "total_pages"]);
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn the_summary_counts_recent_visible_rows_by_outcome() {
        let rows = vec![
            (row("s-1", LedgerOutcome::Paid, Duration::hours(1)), Some("tenant-a")),
            (row("s-1", LedgerOutcome::Paid, Duration::hours(2)), Some("tenant-a")),
            (row("s-1", LedgerOutcome::Rejected, Duration::hours(3)), Some("tenant-a")),
            (row("s-1", LedgerOutcome::Paid, Duration::hours(30)), Some("tenant-a")),
            (row("s-2", LedgerOutcome::Held, Duration::hours(1)), Some("tenant-b")),
        ];
        let (router, dir) = router_with(rows).await;

        let (status, body) = call(router.clone(), "/payments/summary?surface_id=s-1", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 3);
        assert_eq!(body["counts"], serde_json::json!({"paid": 2, "rejected": 1}));
        assert!(
            DateTime::parse_from_rfc3339(
                body["since"]
                    .as_str()
                    .unwrap()
            )
            .is_ok()
        );

        let (_, body) = call(router.clone(), "/payments/summary?hours=48", None, None).await;
        assert_eq!(body["total"], 5);

        let (_, body) = call(router, "/payments/summary", Some(tenant("tenant-b")), None).await;
        assert_eq!(body["counts"], serde_json::json!({"held": 1}), "a tenant counts only its own rows");
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_breaker_is_shown_to_an_operator_and_to_a_tenant_only_for_its_own_gateways() {
        let mut own = row("s-a", LedgerOutcome::Unavailable, Duration::zero());
        own.payment_gateway_id = "gw-tenant-a".to_string();
        let (router, dir) = router_with(vec![(own, Some("tenant-a"))]).await;

        let (status, body) = call(router.clone(), "/payments/breakers/gw-anything", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["payment_gateway_id"], "gw-anything");
        assert_eq!(body["state"], "closed");
        assert_eq!(body["consecutive_failures"], 0);

        let (status, body) =
            call(router.clone(), "/payments/breakers/gw-tenant-a", Some(tenant("tenant-a")), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["state"], "closed");

        for (gateway, caller) in [("gw-tenant-a", "tenant-b"), ("gw-anything", "tenant-a")] {
            let (status, body) =
                call(router.clone(), &format!("/payments/breakers/{gateway}"), Some(tenant(caller)), None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{gateway} for {caller}");
            assert_eq!(body["error"], "Payment gateway not found");
        }
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn an_unknown_id_is_not_found() {
        let (router, dir) = router_with(vec![]).await;
        let (status, body) = call(router, &format!("/payments/{}", uuid::Uuid::new_v4()), None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "Payment not found");
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn without_a_store_the_list_is_empty_and_ids_are_not_found() {
        let router = create_payments_ledger_router(PaymentsLedgerApiState { store: None, case_status: None });
        let (status, body) = call(router.clone(), "/payments", None, None).await;
        assert_eq!((status, body), (StatusCode::OK, serde_json::json!({"payments": [], "total": 0})));
        let (status, _) = call(router, &format!("/payments/{}", uuid::Uuid::new_v4()), None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    use crate::gateways::payment_case::{CaseStatusError, PaymentCaseState};
    use crate::payments_ledger::case_status::tests::Scripted;
    use std::sync::atomic::Ordering;

    async fn router_with_case_status(
        rows: Vec<(PaymentLedgerRow, Option<&str>)>,
        source: Arc<Scripted>,
    ) -> (Router, std::path::PathBuf) {
        let (store, dir) = store().await;
        for (row, tenant_id) in rows {
            store
                .record(row, tenant_id.map(str::to_string))
                .unwrap();
        }
        let router = create_payments_ledger_router(PaymentsLedgerApiState {
            store: Some(Arc::new(store)),
            case_status: Some(Arc::new(CaseStatusLookup::new(source))),
        });
        (router, dir)
    }

    fn held(case_id: Option<&str>) -> PaymentLedgerRow {
        let mut held = row("s-1", LedgerOutcome::Held, Duration::zero());
        held.case_id = case_id.map(str::to_string);
        held
    }

    #[tokio::test]
    async fn a_held_payments_detail_carries_where_its_case_stands() {
        let held = held(Some("case-7"));
        let source = Scripted::answering(Ok(Some(PaymentCaseState::CaptureFailed)));
        let (router, dir) = router_with_case_status(vec![(held.clone(), None)], source.clone()).await;

        let (status, body) = call(router.clone(), &format!("/payments/{}", held.id), None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], held.id);
        assert_eq!(body["case_id"], "case-7");
        assert_eq!(keys(&body["case_status"]), vec!["checked_at", "status"]);
        assert_eq!(body["case_status"]["status"], "capture_failed");
        assert!(
            chrono::DateTime::parse_from_rfc3339(
                body["case_status"]["checked_at"]
                    .as_str()
                    .unwrap()
            )
            .is_ok(),
            "{body}"
        );
        assert_eq!(
            source
                .asked
                .lock()
                .unwrap()
                .clone(),
            vec![("gw-pay".to_string(), "case-7".to_string())]
        );

        let (_, again) = call(router.clone(), &format!("/payments/{}", held.id), None, None).await;
        assert_eq!(again["case_status"], body["case_status"], "an answer is reused for a few seconds");
        assert_eq!(
            source
                .queries
                .load(Ordering::SeqCst),
            1
        );

        let (_, list) = call(router, "/payments", None, None).await;
        assert_eq!(
            list["payments"][0]["case_status"], body["case_status"],
            "the list carries an answer still cached, without asking agent-pay"
        );
        assert_eq!(
            source
                .queries
                .load(Ordering::SeqCst),
            1
        );
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn the_list_never_asks_agent_pay_and_leaves_an_uncached_case_status_out() {
        let held = held(Some("case-7"));
        let source = Scripted::answering(Ok(Some(PaymentCaseState::Approved)));
        let (router, dir) = router_with_case_status(vec![(held.clone(), None)], source.clone()).await;

        let (status, list) = call(router, "/payments", None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list["payments"][0]["id"], held.id);
        assert!(
            list["payments"][0]
                .get("case_status")
                .is_none()
        );
        assert_eq!(
            source
                .queries
                .load(Ordering::SeqCst),
            0
        );
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn only_a_held_payment_with_a_case_is_ever_asked_about() {
        let source = Scripted::answering(Ok(Some(PaymentCaseState::Held)));
        let others: Vec<PaymentLedgerRow> = [
            LedgerOutcome::Paid,
            LedgerOutcome::Challenge,
            LedgerOutcome::Rejected,
            LedgerOutcome::Unconfirmed,
            LedgerOutcome::Unavailable,
        ]
        .into_iter()
        .map(|outcome| {
            let mut other = row("s-1", outcome, Duration::zero());
            other.case_id = Some("case-9".to_string());
            other
        })
        .collect();
        let without_case = held(None);
        let mut rows: Vec<_> = others
            .iter()
            .cloned()
            .map(|row| (row, None))
            .collect();
        rows.push((without_case.clone(), None));
        let (router, dir) = router_with_case_status(rows, source.clone()).await;

        for id in others
            .iter()
            .map(|row| row.id.clone())
            .chain([without_case.id.clone()])
        {
            let (status, body) = call(router.clone(), &format!("/payments/{id}"), None, None).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                body.get("case_status")
                    .is_none(),
                "{body}"
            );
        }
        assert_eq!(
            source
                .queries
                .load(Ordering::SeqCst),
            0
        );
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_case_status_that_cannot_be_had_leaves_it_out_and_the_row_intact() {
        let held = held(Some("case-7"));
        for answer in
            [Err(CaseStatusError::Unavailable("down".into())), Err(CaseStatusError::Rejected("no".into())), Ok(None)]
        {
            let (router, dir) = router_with_case_status(vec![(held.clone(), None)], Scripted::answering(answer)).await;
            let (status, body) = call(router, &format!("/payments/{}", held.id), None, None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(serde_json::from_value::<PaymentLedgerRow>(body.clone()).unwrap(), held);
            assert!(
                body.get("case_status")
                    .is_none()
            );
            let _ = tokio::fs::remove_dir_all(dir).await;
        }
    }

    #[tokio::test]
    async fn a_case_status_is_never_asked_for_a_row_the_caller_cannot_see() {
        let foreign = held(Some("case-7"));
        let operator = held(Some("case-8"));
        let source = Scripted::answering(Ok(Some(PaymentCaseState::Held)));
        let (router, dir) = router_with_case_status(
            vec![(foreign.clone(), Some("tenant-b")), (operator.clone(), None)],
            source.clone(),
        )
        .await;

        for hidden in [&foreign, &operator] {
            let (status, _) =
                call(router.clone(), &format!("/payments/{}", hidden.id), Some(tenant("tenant-a")), None).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
        }
        assert_eq!(
            source
                .queries
                .load(Ordering::SeqCst),
            0
        );
        let _ = tokio::fs::remove_dir_all(dir).await;
    }
}
