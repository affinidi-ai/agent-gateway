//! Integration events raised by the delegated payment gate. They go to every active
//! integration whose event set holds them, and never carry payer identity or credentials.

use std::collections::HashMap;

use crate::integrations::delivery::dispatch::dispatch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentGateEvent {
    ChallengeIssued,
    Paid,
    Held,
    Rejected,
    Unconfirmed,
    Unavailable,
    Authorized,
    Voided,
    CaptureFailed,
    ReconcileFailed,
}

impl PaymentGateEvent {
    #[cfg(test)]
    const ALL: [Self; 10] = [
        Self::ChallengeIssued,
        Self::Paid,
        Self::Held,
        Self::Rejected,
        Self::Unconfirmed,
        Self::Unavailable,
        Self::Authorized,
        Self::Voided,
        Self::CaptureFailed,
        Self::ReconcileFailed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChallengeIssued => "payment.challenge_issued",
            Self::Paid => "payment.paid",
            Self::Held => "payment.held",
            Self::Rejected => "payment.rejected",
            Self::Unconfirmed => "payment.unconfirmed",
            Self::Unavailable => "payment.unavailable",
            Self::Authorized => "payment.authorized",
            Self::Voided => "payment.voided",
            Self::CaptureFailed => "payment.capture_failed",
            Self::ReconcileFailed => "payment.reconcile_failed",
        }
    }

    fn severity(self) -> &'static str {
        match self {
            Self::ChallengeIssued | Self::Paid | Self::Held | Self::Authorized | Self::Voided => "info",
            Self::Rejected | Self::Unconfirmed => "warning",
            Self::Unavailable | Self::CaptureFailed | Self::ReconcileFailed => "error",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct PaymentGateEventFacts {
    pub surface_id: String,
    pub variant: Option<String>,
    pub payment_gateway_id: String,
    pub payment_surface_id: String,
    pub resource: Option<String>,
    pub rail: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub case_id: Option<String>,
    pub remote_status: Option<u16>,
    pub trace_id: String,
    pub authorization_id: Option<String>,
    pub receipt_reference: Option<String>,
    pub quoted_amount: Option<String>,
    pub quoted_currency: Option<String>,
    pub price_mismatch: bool,
    /// Already passed through `payments_ledger::ledger_reason`.
    pub reason: Option<String>,
}

fn runtime_values(
    event: PaymentGateEvent,
    facts: PaymentGateEventFacts,
) -> HashMap<String, String> {
    HashMap::from([
        ("EVENT_TYPE".to_string(), event.as_str().to_string()),
        ("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339()),
        ("SURFACE_ID".to_string(), facts.surface_id),
        (
            "VARIANT".to_string(),
            facts
                .variant
                .unwrap_or_default(),
        ),
        ("PAYMENT_GATEWAY_ID".to_string(), facts.payment_gateway_id),
        ("PAYMENT_SURFACE_ID".to_string(), facts.payment_surface_id),
        (
            "RESOURCE".to_string(),
            facts
                .resource
                .unwrap_or_default(),
        ),
        ("RAIL".to_string(), facts.rail.unwrap_or_default()),
        (
            "AMOUNT".to_string(),
            facts
                .amount
                .unwrap_or_default(),
        ),
        (
            "CURRENCY".to_string(),
            facts
                .currency
                .unwrap_or_default(),
        ),
        (
            "CASE_ID".to_string(),
            facts
                .case_id
                .unwrap_or_default(),
        ),
        (
            "REMOTE_STATUS".to_string(),
            facts
                .remote_status
                .map(|status| status.to_string())
                .unwrap_or_default(),
        ),
        ("TRACE_ID".to_string(), facts.trace_id),
        (
            "AUTHORIZATION_ID".to_string(),
            facts
                .authorization_id
                .unwrap_or_default(),
        ),
        (
            "RECEIPT_REFERENCE".to_string(),
            facts
                .receipt_reference
                .unwrap_or_default(),
        ),
        (
            "QUOTED_AMOUNT".to_string(),
            facts
                .quoted_amount
                .unwrap_or_default(),
        ),
        (
            "QUOTED_CURRENCY".to_string(),
            facts
                .quoted_currency
                .unwrap_or_default(),
        ),
        (
            "PRICE_MISMATCH".to_string(),
            facts
                .price_mismatch
                .to_string(),
        ),
        (
            "REASON".to_string(),
            facts
                .reason
                .unwrap_or_default(),
        ),
        ("SEVERITY".to_string(), event.severity().to_string()),
    ])
}

/// Raises a payment event without making the caller wait.
pub fn raise_payment_gate_event(
    event: PaymentGateEvent,
    facts: PaymentGateEventFacts,
) {
    dispatch(event.as_str(), runtime_values(event, facts));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_names_are_payment_prefixed() {
        let names: Vec<&str> = PaymentGateEvent::ALL
            .iter()
            .map(|e| e.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "payment.challenge_issued",
                "payment.paid",
                "payment.held",
                "payment.rejected",
                "payment.unconfirmed",
                "payment.unavailable",
                "payment.authorized",
                "payment.voided",
                "payment.capture_failed",
                "payment.reconcile_failed"
            ]
        );
    }

    #[test]
    fn runtime_values_carry_the_facts_and_severity() {
        let values = runtime_values(
            PaymentGateEvent::Held,
            PaymentGateEventFacts {
                surface_id: "s-1".to_string(),
                variant: Some("premium".to_string()),
                payment_gateway_id: "gw-pay".to_string(),
                payment_surface_id: "ps-1".to_string(),
                resource: Some("/tools/search".to_string()),
                rail: Some("mpp".to_string()),
                amount: Some("0.50".to_string()),
                currency: Some("USD".to_string()),
                case_id: Some("case-9".to_string()),
                remote_status: Some(202),
                trace_id: "trace-1".to_string(),
                authorization_id: Some("auth-1".to_string()),
                receipt_reference: Some("ref-1".to_string()),
                quoted_amount: Some("0.40".to_string()),
                quoted_currency: Some("USD".to_string()),
                price_mismatch: true,
                reason: Some("risk_review".to_string()),
            },
        );
        let mut keys: Vec<&str> = values
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "AMOUNT",
                "AUTHORIZATION_ID",
                "CASE_ID",
                "CURRENCY",
                "EVENT_TYPE",
                "PAYMENT_GATEWAY_ID",
                "PAYMENT_SURFACE_ID",
                "PRICE_MISMATCH",
                "QUOTED_AMOUNT",
                "QUOTED_CURRENCY",
                "RAIL",
                "REASON",
                "RECEIPT_REFERENCE",
                "REMOTE_STATUS",
                "RESOURCE",
                "SEVERITY",
                "SURFACE_ID",
                "TIMESTAMP",
                "TRACE_ID",
                "VARIANT"
            ]
        );
        assert_eq!(values["EVENT_TYPE"], "payment.held");
        assert_eq!(values["SEVERITY"], "info");
        assert_eq!(values["SURFACE_ID"], "s-1");
        assert_eq!(values["VARIANT"], "premium");
        assert_eq!(values["PAYMENT_GATEWAY_ID"], "gw-pay");
        assert_eq!(values["PAYMENT_SURFACE_ID"], "ps-1");
        assert_eq!(values["RESOURCE"], "/tools/search");
        assert_eq!(values["RAIL"], "mpp");
        assert_eq!(values["AMOUNT"], "0.50");
        assert_eq!(values["CURRENCY"], "USD");
        assert_eq!(values["CASE_ID"], "case-9");
        assert_eq!(values["REMOTE_STATUS"], "202");
        assert_eq!(values["TRACE_ID"], "trace-1");
        assert_eq!(values["AUTHORIZATION_ID"], "auth-1");
        assert_eq!(values["RECEIPT_REFERENCE"], "ref-1");
        assert_eq!(values["QUOTED_AMOUNT"], "0.40");
        assert_eq!(values["QUOTED_CURRENCY"], "USD");
        assert_eq!(values["PRICE_MISMATCH"], "true");
        assert_eq!(values["REASON"], "risk_review");
        assert!(chrono::DateTime::parse_from_rfc3339(&values["TIMESTAMP"]).is_ok());
    }

    #[test]
    fn absent_facts_are_empty_strings() {
        let values = runtime_values(PaymentGateEvent::Unavailable, PaymentGateEventFacts::default());
        for key in [
            "VARIANT",
            "RESOURCE",
            "RAIL",
            "AMOUNT",
            "CURRENCY",
            "CASE_ID",
            "REMOTE_STATUS",
            "TRACE_ID",
            "AUTHORIZATION_ID",
            "RECEIPT_REFERENCE",
            "QUOTED_AMOUNT",
            "QUOTED_CURRENCY",
            "REASON",
        ] {
            assert_eq!(values[key], "", "{key}");
        }
        assert_eq!(values["PRICE_MISMATCH"], "false");
        assert_eq!(values["SEVERITY"], "error");
    }

    #[test]
    fn severity_follows_the_event() {
        let severities: Vec<&str> = PaymentGateEvent::ALL
            .iter()
            .map(|e| e.severity())
            .collect();
        assert_eq!(
            severities,
            vec!["info", "info", "info", "warning", "warning", "error", "info", "info", "error", "error"]
        );
    }

    #[test]
    fn every_event_is_in_the_catalog_with_the_variables_it_fills() {
        for event in PaymentGateEvent::ALL {
            let listed = crate::integrations::events::find_event(event.as_str()).expect("payment event in the catalog");
            assert_eq!(listed.family, "payment");
            let values = runtime_values(event, PaymentGateEventFacts::default());
            for name in values
                .keys()
                .filter(|name| !["EVENT_TYPE", "TIMESTAMP"].contains(&name.as_str()))
            {
                assert!(
                    listed
                        .variables
                        .contains(&name.as_str()),
                    "{} lacks {name}",
                    listed.id
                );
            }
        }
    }
}
