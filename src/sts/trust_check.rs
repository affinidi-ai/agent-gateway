//! Trust Check on STS issuance.
//!
//! An STS managed connection may carry a `trust_check_list` — the same
//! `TrustCheckElement` vocabulary an Agent Surface uses on its caller leg.
//! Before a token is minted, the list is evaluated against its trust registries
//! over TRQP and the results are merged into the OPA policy input at
//! `input.trust_check_results.caller[]`, so a gateway policy can allow or deny on
//! a recognition / authorization verdict. As in the proxy pipeline, the stage
//! itself never denies — OPA decides.
//!
//! The checker is a port so the handler flow stays unit-testable with a mock;
//! the production adapter delegates to `run_trust_check_stage` over a
//! `TrqpListenerClient`. When no trust-registry listener manager is wired the
//! list is skipped ([`DisabledTrustChecker`]).

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::trust_registries::TrustRegistryListenerManager;
use crate::trust_registry_verification::{TrqpListenerClient, TrustCheckElement, TrustCheckLeg, run_trust_check_stage};

/// Runs an STS client's `trust_check_list` and returns the results to merge into
/// the OPA input.
#[async_trait]
pub trait StsTrustChecker: Send + Sync {
    /// Evaluate `trust_check_list` against `input` (the bare issuance policy
    /// input, e.g. `{ "sts": {...} }`). Returns the serialized
    /// `trust_check_results` context to place at `input.trust_check_results`, or
    /// `None` when the list is empty (so the input carries no results block).
    /// `subject_id` labels the audit trail (the STS client id).
    async fn evaluate(
        &self,
        subject_id: &str,
        input: &Value,
        trust_check_list: &[TrustCheckElement],
    ) -> Option<Value>;
}

/// Production checker backed by the trust-registry listener manager. Runs the
/// caller-leg Trust Check stage — the STS client requesting a token is the
/// analogue of a caller — over a `TrqpListenerClient`.
pub struct ListenerTrustChecker {
    manager: Arc<TrustRegistryListenerManager>,
}

impl ListenerTrustChecker {
    pub fn new(manager: Arc<TrustRegistryListenerManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl StsTrustChecker for ListenerTrustChecker {
    async fn evaluate(
        &self,
        subject_id: &str,
        input: &Value,
        trust_check_list: &[TrustCheckElement],
    ) -> Option<Value> {
        if trust_check_list.is_empty() {
            return None;
        }
        let client = TrqpListenerClient::new(self.manager.clone());
        let ctx = run_trust_check_stage(subject_id, TrustCheckLeg::Caller, trust_check_list, input, &client).await?;
        serde_json::to_value(&ctx).ok()
    }
}

/// Fail-safe checker used when no trust-registry listener manager is available:
/// the list is skipped (no results). A configured list therefore contributes no
/// verdict — the gateway policy still governs issuance.
pub struct DisabledTrustChecker;

#[async_trait]
impl StsTrustChecker for DisabledTrustChecker {
    async fn evaluate(
        &self,
        _subject_id: &str,
        _input: &Value,
        _trust_check_list: &[TrustCheckElement],
    ) -> Option<Value> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust_registry_verification::trust_check_element::{TrqpQueryParams, TrqpQueryType};
    use serde_json::json;

    fn element() -> TrustCheckElement {
        TrustCheckElement {
            id: "e1".to_string(),
            trust_registry_id: "reg".to_string(),
            query_type: TrqpQueryType::Recognition,
            query: TrqpQueryParams::default(),
            timeout_secs: None,
            name: None,
        }
    }

    #[tokio::test]
    async fn disabled_checker_returns_none_even_with_elements() {
        let checker = DisabledTrustChecker;
        assert!(
            checker
                .evaluate("client", &json!({ "sts": {} }), &[element()])
                .await
                .is_none(),
            "the disabled checker must contribute no results"
        );
    }
}
