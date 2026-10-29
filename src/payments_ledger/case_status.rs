//! The live review state of a held payment, asked of the agent-pay gateway that
//! holds it. It is best effort: the answer is cached briefly, and any failure
//! leaves the state out rather than failing or delaying the ledger response for
//! longer than the wait.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::gateways::payment_case::{CaseStatusError, PaymentCaseState};

/// How long one query waits for agent-pay.
const WAIT: Duration = Duration::from_secs(3);
/// How long an answer is reused.
const FRESH_FOR: Duration = Duration::from_secs(15);
/// How many answers are kept.
const CACHED_ANSWERS: u64 = 1024;
/// How many questions may be waiting on agent-pay at once; a question past it
/// is not asked, so the ledger API cannot flood the fabric.
const CONCURRENT_QUERIES: usize = 8;

/// Where a held payment stands, and when that was asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CaseStatus {
    pub status: PaymentCaseState,
    pub checked_at: DateTime<Utc>,
}

/// Where the review state of a case comes from.
#[async_trait::async_trait]
pub trait CaseStatusSource: Send + Sync {
    /// The state of `case_id` on the payment gateway `payment_gateway_id`;
    /// `Ok(None)` when the gateway does not know the case.
    async fn status(
        &self,
        payment_gateway_id: &str,
        case_id: &str,
    ) -> Result<Option<PaymentCaseState>, CaseStatusError>;
}

/// Asks the payment gateway over the fabric.
pub struct FabricCaseStatus {
    gateways: Arc<crate::gateways::FileSystemGatewayStore>,
}

impl FabricCaseStatus {
    pub fn new(gateways: Arc<crate::gateways::FileSystemGatewayStore>) -> Self {
        Self { gateways }
    }
}

#[async_trait::async_trait]
impl CaseStatusSource for FabricCaseStatus {
    async fn status(
        &self,
        payment_gateway_id: &str,
        case_id: &str,
    ) -> Result<Option<PaymentCaseState>, CaseStatusError> {
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
        crate::gateways::handlers::fetch_payment_case_status(listener_manager.as_deref(), &gateway, case_id, WAIT).await
    }
}

/// [`CaseStatusSource`] answers kept for [`FRESH_FOR`]. Concurrent queries for
/// one case share a single question, and a failed or unknown answer is not kept.
pub struct CaseStatusLookup {
    source: Arc<dyn CaseStatusSource>,
    answers: moka::future::Cache<(String, String), CaseStatus>,
    wait: Duration,
    asking: tokio::sync::Semaphore,
}

impl CaseStatusLookup {
    pub fn new(source: Arc<dyn CaseStatusSource>) -> Self {
        Self::with_timing(source, WAIT, FRESH_FOR)
    }

    fn with_timing(
        source: Arc<dyn CaseStatusSource>,
        wait: Duration,
        fresh_for: Duration,
    ) -> Self {
        Self {
            source,
            answers: moka::future::Cache::builder()
                .max_capacity(CACHED_ANSWERS)
                .time_to_live(fresh_for)
                .build(),
            wait,
            asking: tokio::sync::Semaphore::new(CONCURRENT_QUERIES),
        }
    }

    /// The last answer for `case_id` still fresh, without asking agent-pay.
    pub async fn cached(
        &self,
        payment_gateway_id: &str,
        case_id: &str,
    ) -> Option<CaseStatus> {
        self.answers
            .get(&(payment_gateway_id.to_string(), case_id.to_string()))
            .await
    }

    /// The state of the held payment `case_id` on `payment_gateway_id`, or
    /// `None` when it cannot be had within the wait.
    pub async fn check(
        &self,
        payment_gateway_id: &str,
        case_id: &str,
    ) -> Option<CaseStatus> {
        let source = self.source.clone();
        let (gateway_id, case) = (payment_gateway_id.to_string(), case_id.to_string());
        self.answers
            .try_get_with((payment_gateway_id.to_string(), case_id.to_string()), async move {
                let Ok(_asking) = self.asking.try_acquire() else {
                    return Err("too many questions are waiting on the payment gateway".to_string());
                };
                let asked = tokio::time::timeout(self.wait, source.status(&gateway_id, &case)).await;
                match asked {
                    Ok(Ok(Some(status))) => Ok(CaseStatus { status, checked_at: Utc::now() }),
                    Ok(Ok(None)) => Err("the payment gateway does not know the case".to_string()),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err("the payment gateway did not answer in time".to_string()),
                }
            })
            .await
            .map_err(|reason| tracing::debug!(case_id, "[payments-ledger] Case status not had: {reason}"))
            .ok()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A source that answers `answer` after `delay`, counting its queries.
    pub(crate) struct Scripted {
        pub answer: Result<Option<PaymentCaseState>, CaseStatusError>,
        pub delay: Duration,
        pub queries: AtomicUsize,
        pub asked: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl Scripted {
        pub(crate) fn answering(answer: Result<Option<PaymentCaseState>, CaseStatusError>) -> Arc<Self> {
            Arc::new(Self {
                answer,
                delay: Duration::ZERO,
                queries: AtomicUsize::new(0),
                asked: std::sync::Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl CaseStatusSource for Scripted {
        async fn status(
            &self,
            payment_gateway_id: &str,
            case_id: &str,
        ) -> Result<Option<PaymentCaseState>, CaseStatusError> {
            self.queries
                .fetch_add(1, Ordering::SeqCst);
            self.asked
                .lock()
                .unwrap()
                .push((payment_gateway_id.to_string(), case_id.to_string()));
            tokio::time::sleep(self.delay).await;
            self.answer.clone()
        }
    }

    #[tokio::test]
    async fn the_state_of_a_case_is_asked_of_its_payment_gateway_and_stamped() {
        let source = Scripted::answering(Ok(Some(PaymentCaseState::Approved)));
        let lookup = CaseStatusLookup::new(source.clone());
        let before = Utc::now();

        let checked = lookup
            .check("gw-pay", "case-1")
            .await
            .expect("a known case has a state");
        assert_eq!(checked.status, PaymentCaseState::Approved);
        assert!(checked.checked_at >= before && checked.checked_at <= Utc::now());
        assert_eq!(
            source
                .asked
                .lock()
                .unwrap()
                .clone(),
            vec![("gw-pay".to_string(), "case-1".to_string())]
        );
    }

    #[tokio::test]
    async fn an_answer_is_reused_and_concurrent_queries_share_one_question() {
        let source = Arc::new(Scripted {
            answer: Ok(Some(PaymentCaseState::Held)),
            delay: Duration::from_millis(50),
            queries: AtomicUsize::new(0),
            asked: std::sync::Mutex::new(Vec::new()),
        });
        let lookup = CaseStatusLookup::new(source.clone());
        let checked = futures::future::join_all((0..10).map(|_| lookup.check("gw-pay", "case-1"))).await;
        assert!(
            checked
                .iter()
                .all(|c| c.is_some_and(|c| c.status == PaymentCaseState::Held))
        );
        let first = checked[0].unwrap().checked_at;
        assert!(
            checked
                .iter()
                .all(|c| c.unwrap().checked_at == first)
        );
        assert_eq!(
            lookup
                .check("gw-pay", "case-1")
                .await
                .unwrap()
                .checked_at,
            first
        );
        assert_eq!(
            source
                .queries
                .load(Ordering::SeqCst),
            1
        );

        lookup
            .check("gw-pay", "case-2")
            .await;
        lookup
            .check("gw-other", "case-1")
            .await;
        assert_eq!(
            source
                .queries
                .load(Ordering::SeqCst),
            3,
            "another case or gateway is another question"
        );
    }

    #[tokio::test]
    async fn an_answer_expires() {
        let source = Scripted::answering(Ok(Some(PaymentCaseState::Held)));
        let lookup = CaseStatusLookup::with_timing(source.clone(), WAIT, Duration::from_millis(40));
        lookup
            .check("gw-pay", "case-1")
            .await;
        tokio::time::sleep(Duration::from_millis(120)).await;
        lookup
            .check("gw-pay", "case-1")
            .await;
        assert_eq!(
            source
                .queries
                .load(Ordering::SeqCst),
            2
        );
    }

    #[tokio::test]
    async fn a_failure_an_unknown_case_and_a_slow_answer_leave_the_state_out_and_are_not_kept() {
        for (answer, delay) in [
            (Err(CaseStatusError::Unavailable("down".into())), Duration::ZERO),
            (Err(CaseStatusError::Rejected("no".into())), Duration::ZERO),
            (Ok(None), Duration::ZERO),
            (Ok(Some(PaymentCaseState::Held)), Duration::from_secs(5)),
        ] {
            let source = Arc::new(Scripted {
                answer,
                delay,
                queries: AtomicUsize::new(0),
                asked: std::sync::Mutex::new(Vec::new()),
            });
            let lookup = CaseStatusLookup::with_timing(source.clone(), Duration::from_millis(30), FRESH_FOR);
            assert_eq!(
                lookup
                    .check("gw-pay", "case-1")
                    .await,
                None
            );
            assert_eq!(
                lookup
                    .check("gw-pay", "case-1")
                    .await,
                None
            );
            assert_eq!(
                source
                    .queries
                    .load(Ordering::SeqCst),
                2,
                "nothing was kept"
            );
        }
    }

    #[tokio::test]
    async fn only_so_many_questions_wait_on_the_payment_gateway_at_once() {
        let source = Arc::new(Scripted {
            answer: Ok(Some(PaymentCaseState::Held)),
            delay: Duration::from_millis(300),
            queries: AtomicUsize::new(0),
            asked: std::sync::Mutex::new(Vec::new()),
        });
        let lookup = CaseStatusLookup::new(source.clone());

        let answered = futures::future::join_all((0..CONCURRENT_QUERIES + 4).map(|i| {
            let lookup = &lookup;
            async move {
                lookup
                    .check("gw-pay", &format!("case-{i}"))
                    .await
            }
        }))
        .await;
        assert_eq!(
            answered
                .iter()
                .filter(|status| status.is_some())
                .count(),
            CONCURRENT_QUERIES
        );
        assert_eq!(
            source
                .queries
                .load(Ordering::SeqCst),
            CONCURRENT_QUERIES
        );

        assert!(
            lookup
                .check("gw-pay", &format!("case-{}", CONCURRENT_QUERIES + 1))
                .await
                .is_some(),
            "a question that was turned away is asked once the others have been answered"
        );
    }

    #[test]
    fn the_state_serialises_as_status_and_checked_at() {
        let checked = CaseStatus {
            status: PaymentCaseState::CaptureFailed,
            checked_at: DateTime::parse_from_rfc3339("2026-10-21T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        assert_eq!(
            serde_json::to_value(checked).unwrap(),
            serde_json::json!({"status": "capture_failed", "checked_at": "2026-10-21T10:00:00Z"})
        );
    }
}
